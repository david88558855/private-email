// Package outbound SMTP 出站投递（D3：直连 MX，可配 smarthost；DKIM 签名；指数退避）。
package outbound

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/smtp"
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

// Start 启动投递循环。
func (w *Worker) Start() {
	go func() {
		for {
			w.drain()
			time.Sleep(20 * time.Second)
		}
	}()
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
		return raw
	}
	priv, err := parseDKIMKey([]byte(pem))
	if err != nil {
		return raw
	}
	if selector == "" {
		selector = "default"
	}
	opts := dkim.SignOptions{Domain: domain, Selector: selector, Signer: priv}
	var buf strings.Builder
	if err := dkim.Sign(&buf, strings.NewReader(string(raw)), &opts); err != nil {
		return raw
	}
	return []byte(buf.String())
}

// EnsureDKIMKeys 为已验证域名生成 RSA2048 密钥（幂等）。
func EnsureDKIMKeys(st *store.Store) {
	rows, err := st.DB.Query(`SELECT id, domain FROM domains WHERE status='verified' AND NOT EXISTS
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
	conn, err := net.Dial("tcp", addr)
	if err != nil {
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
