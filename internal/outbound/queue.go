// Package outbound SMTP 出站投递（D3：直连 MX，可配 smarthost；DKIM 签名；指数退避）。
package outbound

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/store"
	"github.com/emersion/go-msgauth/dkim"
)

var retrySchedule = []int{0, 15, 60, 360, 1440} // 分钟：0=首次, 之后指数退避

type Worker struct {
	Store *store.Store
	Cfg   *config.Config
}

// Start 启动投递循环 + 队列清理。
func (w *Worker) Start() {
	go func() {
		for {
			w.drain()
			time.Sleep(20 * time.Second)
		}
	}()
	go func() {
		// 每天清一次已完成的队列行：status='sent' 的行原来永久保留，
		// 还带着整封 raw_blob，库只会越涨越大。
		for {
			w.cleanup()
			time.Sleep(24 * time.Hour)
		}
	}()
}

// cleanup 删除超过保留期的已送达/已失败队列行。
func (w *Worker) cleanup() {
	days := 7
	if v, err := w.Store.GetSetting("queue_retention_days"); err == nil && v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 365 {
			days = n
		}
	}
	res, err := w.Store.DB.Exec(`DELETE FROM mail_queue
		WHERE status IN ('sent','failed') AND created_at < datetime('now', ?)`,
		fmt.Sprintf("-%d days", days))
	if err != nil {
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("已清理 %d 条历史投递队列记录（保留 %d 天）", n, days)
	}
}

func (w *Worker) drain() {
	rows, err := w.Store.DB.Query(`SELECT id, from_addr, to_addr, raw_blob, attempts FROM mail_queue
		WHERE status='queued' AND next_try_at <= datetime('now') LIMIT 20`)
	if err != nil {
		return
	}
	type job struct {
		id       int64
		from, to string
		raw      []byte
		attempts int
	}
	var jobs []job
	for rows.Next() {
		var j job
		if rows.Scan(&j.id, &j.from, &j.to, &j.raw, &j.attempts) == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()
	for _, j := range jobs {
		w.deliver(j.id, j.from, j.to, j.raw, j.attempts)
	}
}

func (w *Worker) deliver(id int64, from, to string, raw []byte, attempts int) {
	// 转发规则指向本站邮箱时，收件人不在公网：直接入库，不再做 MX 查询。
	// 这里用 InsertIntoInbox（不重跑转发规则），避免 A→B、B→A 互相转发形成死循环。
	if mbID, active, found := w.Store.MailboxStateByAddress(to); found {
		if !active {
			w.Store.DB.Exec(`UPDATE mail_queue SET status='failed', attempts=?, last_error=? WHERE id=?`,
				attempts+1, "recipient mailbox is paused", id)
			log.Printf("出站放弃 %s -> %s: 收件邮箱已暂停收发", from, to)
			return
		}
		p := store.ParseFull(&store.MailFull{Raw: raw})
		if err := w.Store.InsertIntoInbox(mbID, from, to, p.Subject, raw, p.TextBody); err != nil {
			w.retry(id, attempts, err)
			return
		}
		w.Store.DB.Exec(`UPDATE mail_queue SET status='sent', last_error=NULL WHERE id=?`, id)
		log.Printf("出站本地投递成功 %s -> %s", from, to)
		return
	}

	signed := w.dkimSign(from, raw)
	var err error
	if w.Cfg.SMTPClient.Smarthost != "" {
		err = w.viaSmarthost(from, []string{to}, signed)
	} else {
		err = w.viaMX(from, to, signed)
	}
	if err == nil {
		w.Store.DB.Exec(`UPDATE mail_queue SET status='sent', last_error=NULL WHERE id=?`, id)
		log.Printf("出站投递成功 %s -> %s", from, to)
		return
	}
	w.retry(id, attempts, err)
}

// retry 记录失败并按退避表安排下一次尝试，用尽则标记 failed。
func (w *Worker) retry(id int64, attempts int, err error) {
	next := attempts + 1
	if next >= len(retrySchedule) {
		w.Store.DB.Exec(`UPDATE mail_queue SET status='failed', attempts=?, last_error=? WHERE id=?`,
			next, err.Error(), id)
		log.Printf("出站投递失败(放弃) queue=%d: %v", id, err)
		return
	}
	w.Store.DB.Exec(`UPDATE mail_queue SET attempts=?, next_try_at=datetime('now', ?), last_error=? WHERE id=?`,
		next, fmt.Sprintf("+%d minutes", retrySchedule[next]), err.Error(), id)
	log.Printf("出站投递重试 %d queue=%d: %v", next, id, err)
}

func (w *Worker) viaMX(from, to string, raw []byte) error {
	return w.sendDirect(from, []string{to}, raw)
}

// 单次投递的整体超时。smtp.SendMail 只做阻塞式读写，遇到吞包的 MX 会挂到
// 系统 TCP 超时（数分钟），期间整个出站循环都被卡住。
const deliveryTimeout = 60 * time.Second

// sendDirect 直连收件域的 MX（无 MX 时按 RFC 5321 回落 A 记录）。
//
// 有意不过滤私网/回环地址：本产品定位是自建与局域网邮箱，内网 MX 互联投递
// （mail.lan、192.168.x.x 等）是合法且常见用法，默认禁止会直接打断内网邮件。
// 公网部署请配 smarthost 并用防火墙限制出站 25，避免被当作内网探测跳板。
func (w *Worker) sendDirect(from string, tos []string, raw []byte) error {
	domain := tos[0][strings.Index(tos[0], "@")+1:]
	mxs, err := net.LookupMX(domain)
	if err != nil || len(mxs) == 0 {
		// 无 MX 记录时按 RFC 5321 回落 A 记录
		return sendMailTimeout(domain+":25", from, tos, raw)
	}
	var last error
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".") + ":25"
		if err := sendMailTimeout(host, from, tos, raw); err != nil {
			last = err
			continue
		}
		return nil
	}
	return last
}

// sendMailTimeout 等价于 smtp.SendMail，但整条连接带 deadline，并在对端支持时升级 STARTTLS。
func sendMailTimeout(addr, from string, tos []string, raw []byte) error {
	conn, err := net.DialTimeout("tcp", addr, deliveryTimeout)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(deliveryTimeout)); err != nil {
		conn.Close()
		return err
	}
	host, _, _ := net.SplitHostPort(addr)
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close() // NewClient 失败时它不接管连接
		return err
	}
	defer cl.Close()
	if ok, _ := cl.Extension("STARTTLS"); ok {
		if err := cl.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return err
		}
	}
	if err := cl.Mail(from); err != nil {
		return err
	}
	for _, to := range tos {
		if err := cl.Rcpt(to); err != nil {
			return err
		}
	}
	wc, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(raw); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

// dkimSign 查发件域 DKIM 私钥并签名；无密钥则原样返回。
func (w *Worker) dkimSign(from string, raw []byte) []byte {
	domain := from[strings.Index(from, "@")+1:]
	var pem, selector string
	if err := w.Store.DB.QueryRow(`SELECT k.private_key, k.selector FROM dkim_keys k
		JOIN domains d ON d.id=k.domain_id WHERE d.domain=? LIMIT 1`, domain).Scan(&pem, &selector); err != nil {
		// 域名还没生成密钥属正常状态；其它查询故障必须留痕，否则签名静默降级无人知晓。
		if err != sql.ErrNoRows {
			log.Printf("DKIM 查私钥失败 domain=%s: %v", domain, err)
		}
		return raw
	}
	priv, err := parseDKIMKey([]byte(pem))
	if err != nil {
		log.Printf("DKIM 私钥解析失败 domain=%s: %v", domain, err)
		return raw
	}
	if selector == "" {
		selector = "default"
	}
	opts := dkim.SignOptions{Domain: domain, Selector: selector, Signer: priv}
	var buf bytes.Buffer
	if err := dkim.Sign(&buf, bytes.NewReader(raw), &opts); err != nil {
		log.Printf("DKIM 签名失败 domain=%s，本封邮件将以未签名方式投递: %v", domain, err)
		return raw
	}
	return buf.Bytes()
}

// EnsureDKIMKeys 为所有域名生成 RSA2048 密钥（幂等）。
//
// 不再限定 status='verified'：DKIM 密钥跟 DNS 验证是两件独立的事，而管理员
// 配 DNS 时需要一次把 TXT 验证记录和 DKIM 记录都填好。原来只给已验证域名
// 生成，导致「域名待验证 → 没有 dkim_dns → 界面永远显示生成中」，用户既不
// 知道该填什么，也没法先把 DNS 配完再验证。
func EnsureDKIMKeys(st *store.Store) {
	rows, err := st.DB.Query(`SELECT id, domain FROM domains WHERE NOT EXISTS
		(SELECT 1 FROM dkim_keys k WHERE k.domain_id=domains.id)`)
	if err != nil {
		return
	}
	type kv struct {
		id     int64
		domain string
	}
	var need []kv
	for rows.Next() {
		var k kv
		rows.Scan(&k.id, &k.domain)
		need = append(need, k)
	}
	rows.Close()
	for _, k := range need {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			continue
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		st.DB.Exec(`INSERT INTO dkim_keys(domain_id, selector, private_key) VALUES(?,?,?)`,
			k.id, "default", string(pemBytes))
		log.Printf("已生成 DKIM 密钥 %s（selector=default，请发布 DNS TXT 记录）", k.domain)
	}
}

// parseDKIMKey 解析 PEM（PKCS1/PKCS8）。
func parseDKIMKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("bad PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch v := k8.(type) {
	case *rsa.PrivateKey:
		return v, nil
	}
	return nil, fmt.Errorf("unsupported key type")
}

// viaSmarthost 经 relay 投递：465 隐式 TLS，其余 STARTTLS；支持认证与跳过校验。
func (w *Worker) viaSmarthost(from string, tos []string, raw []byte) error {
	addr := w.Cfg.SMTPClient.Smarthost
	host, _, _ := net.SplitHostPort(addr)
	implicit := strings.HasSuffix(addr, ":465")
	conn, err := net.DialTimeout("tcp", addr, deliveryTimeout)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(deliveryTimeout)); err != nil {
		conn.Close()
		return err
	}
	tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: w.Cfg.SMTPClient.InsecureSkipVerify}
	if implicit {
		conn = tls.Client(conn, tlsCfg)
	}
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close() // NewClient 失败时它不会接管连接，需自行关闭避免 fd 泄漏
		return err
	}
	defer cl.Close()
	if !implicit {
		if ok, _ := cl.Extension("STARTTLS"); ok {
			if err := cl.StartTLS(tlsCfg); err != nil {
				return err
			}
		}
	}
	if w.Cfg.SMTPClient.Username != "" {
		auth := smtp.PlainAuth("", w.Cfg.SMTPClient.Username, w.Cfg.SMTPClient.Password, host)
		if err := cl.Auth(auth); err != nil {
			return err
		}
	}
	if err := cl.Mail(from); err != nil {
		return err
	}
	for _, to := range tos {
		if err := cl.Rcpt(to); err != nil {
			return err
		}
	}
	wc, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(raw); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return cl.Quit()
}
