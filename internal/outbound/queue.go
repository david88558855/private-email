// Package outbound SMTP 出站投递（D3：直连 MX，可配 smarthost；DKIM 签名；指数退避）。
package outbound

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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
	signed := w.dkimSign(from, raw)
	var err error
	if w.Cfg.SMTPClient.Smarthost != "" {
		err = smtp.SendMail(w.Cfg.SMTPClient.Smarthost, nil, from, []string{to}, signed)
	} else {
		err = w.viaMX(from, to, signed)
	}
	if err == nil {
		w.Store.DB.Exec(`UPDATE mail_queue SET status='sent', last_error=NULL WHERE id=?`, id)
		log.Printf("出站投递成功 %s -> %s", from, to)
		return
	}
	next := attempts + 1
	if next >= len(retrySchedule) {
		w.Store.DB.Exec(`UPDATE mail_queue SET status='failed', attempts=?, last_error=? WHERE id=?`,
			next, err.Error(), id)
		log.Printf("出站投递失败(放弃) %s -> %s: %v", from, to, err)
		return
	}
	w.Store.DB.Exec(`UPDATE mail_queue SET attempts=?, next_try_at=datetime('now', ?), last_error=? WHERE id=?`,
		next, fmt.Sprintf("+%d minutes", retrySchedule[next]), err.Error(), id)
	log.Printf("出站投递重试 %d %s -> %s: %v", next, from, to, err)
}

func (w *Worker) viaMX(from, to string, raw []byte) error {
	domain := to[strings.Index(to, "@")+1:]
	mxs, err := net.LookupMX(domain)
	if err != nil || len(mxs) == 0 {
		// 无 MX 记录时按 RFC 5321 回落 A 记录
		return smtp.SendMail(domain+":25", nil, from, []string{to}, raw)
	}
	var last error
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".") + ":25"
		if err := smtp.SendMail(host, nil, from, []string{to}, raw); err != nil {
			last = err
			continue
		}
		return nil
	}
	return last
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
