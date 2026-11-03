// Package smtp SMTP 入站服务（决策 D5：SPF/DKIM 记分；D1=B：BLOB 入库）。
package smtp

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/mailutil"
	"github.com/david88558855/private-email/internal/store"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"
)

type Backend struct {
	Store  *store.Store
	Config *config.Config
}

type session struct {
	be    *Backend
	conn  *smtp.Conn
	from  string
	rcpts []string
	helo  string
}

func (b *Backend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	return &session{be: b, conn: conn}, nil
}

func (s *session) Reset() { s.from = ""; s.rcpts = nil }

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	s.helo = s.conn.Hostname()
	s.from = from
	return nil
}

func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	addr := strings.Trim(to, "<>")
	if !strings.Contains(addr, "@") {
		return &smtp.SMTPError{Code: 501, Message: "bad address"}
	}
	mb, err := s.be.Store.MailboxByAddress(addr)
	if err != nil {
		return &smtp.SMTPError{Code: 451, Message: "internal error"}
	}
	if mb == nil {
		return &smtp.SMTPError{Code: 550, Message: "user unknown"}
	}
	s.rcpts = append(s.rcpts, addr)
	return nil
}

func (s *session) Data(r io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(r, s.be.Config.SMTP.MaxSize*1024*1024+1024))
	if err != nil {
		return &smtp.SMTPError{Code: 552, Message: "read error"}
	}
	if int64(len(raw)) > s.be.Config.SMTP.MaxSize*1024*1024 {
		return &smtp.SMTPError{Code: 552, Message: "message too large"}
	}
	if len(s.rcpts) == 0 {
		return &smtp.SMTPError{Code: 554, Message: "no valid recipient"}
	}

	p := mailutil.Parse(raw)
	// 流水线：SPF → DKIM 验签 → 记分（D5=A）
	score := 0.0
	host, _, _ := net.SplitHostPort(s.conn.Conn().RemoteAddr().String())
	res, _ := spf.CheckHostWithSender(net.ParseIP(host), s.helo, s.from)
	if res != spf.Pass {
		score += 1.5
	}
	if !dkimPass(raw) {
		score += 1.5
	}
	// 验证码提取（全局规则 + 内置）
	code := extractCode(s.be.Store, p.TextBody+" "+mailutil.StripHTML(p.HTMLBody)+" "+p.Subject)

	for _, addr := range s.rcpts {
		mb, err := s.be.Store.MailboxByAddress(addr)
		if err != nil || mb == nil {
			continue
		}
		folderID, err := s.be.Store.FolderID(mb.ID, "INBOX")
		if err != nil {
			continue
		}
		if _, _, err := s.be.Store.InsertMail(folderID, s.from, addr, p.Subject, raw,
			"", code, score, p.TextBody); err != nil {
			log.Printf("deliver %s: %v", addr, err)
			return &smtp.SMTPError{Code: 451, Message: "delivery failed"}
		}
		// 转发规则（M4 投递）
		enqueueForwards(s.be.Store, mb.ID, s.from, raw)
		log.Printf("SMTP 收信 %s -> %s (%dB, spam=%.1f, code=%s)", s.from, addr, len(raw), score, code)
	}
	return nil
}

func (s *session) Logout() error { return nil }

func dkimPass(raw []byte) bool {
	vs, err := dkim.Verify(bytes.NewReader(raw))
	if err != nil || len(vs) == 0 {
		return false
	}
	for _, v := range vs {
		if v.Err == nil {
			return true
		}
	}
	return false
}

func extractCode(st *store.Store, text string) string {
	rows, err := st.DB.Query(`SELECT pattern FROM verification_rules WHERE is_active=1 AND mailbox_id IS NULL`)
	if err != nil {
		return mailutil.ExtractCode(text, nil)
	}
	return mailutil.ExtractCode(text, rows)
}

func enqueueForwards(st *store.Store, mailboxID int64, from string, raw []byte) {
	rows, err := st.DB.Query(`SELECT target FROM forward_rules WHERE mailbox_id=? AND is_active=1`, mailboxID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var target string
		if rows.Scan(&target) == nil && target != "" {
			st.EnqueueForward(mailboxID, from, target, raw)
		}
	}
}

// Serve 启动 SMTP 三个监听（25 STARTTLS / 587 submission / 465 隐式 TLS）。
// M2 阶段 465/587 若无证书可用则自动跳过。
func Serve(be *Backend) {
	s := smtp.NewServer(be)
	s.Domain = "private-email"
	s.MaxMessageBytes = be.Config.SMTP.MaxSize * 1024 * 1024
	s.AllowInsecureAuth = true
	s.ReadTimeout = 2 * time.Minute
	s.WriteTimeout = 2 * time.Minute

	go listen(s, be.Config.SMTP.Listen, "SMTP", nil)
	if be.Config.SMTP.Submission != "" {
		go listen(s, be.Config.SMTP.Submission, "Submission", nil)
	}
}

func listen(s *smtp.Server, addr, name string, cert *tls.Config) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("%s 监听 %s 失败: %v（跳过）", name, addr, err)
		return
	}
	log.Printf("%s 服务就绪 %s", name, addr)
	defer func() { recover() }()
	s.Serve(ln)
}

var _ = sql.ErrNoRows
