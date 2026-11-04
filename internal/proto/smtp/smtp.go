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
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type Backend struct {
	Store  *store.Store
	Config *config.Config
	Cert   *tls.Certificate
}

type session struct {
	be       *Backend
	conn     *smtp.Conn
	from     string
	rcpts    []string
	helo     string
	authUser string // 已认证的邮箱地址（587 提交）
}

func (b *Backend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	return &session{be: b, conn: conn}, nil
}

func (s *session) Reset() { s.from = ""; s.rcpts = nil }

// AuthMechanisms / Auth：587 提交端口认证（D2：Web 密码或 App 专用密码）。
func (s *session) AuthMechanisms() []string { return []string{sasl.Plain, sasl.Login} }

func (s *session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return s.authenticate(username, password)
		}), nil
	case sasl.Login:
		return &loginServer{cb: s.authenticate}, nil
	}
	return nil, smtp.ErrAuthUnsupported
}

func (s *session) authenticate(username, password string) error {
	mb, ok := s.be.Store.VerifyMailboxAuth(username, password)
	if !ok {
		return smtp.ErrAuthFailed
	}
	s.authUser = mb.Address
	return nil
}

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
	if be.Cert != nil {
		// 有证书：走 STARTTLS 后认证（明文认证禁用）
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*be.Cert}}
		s.AllowInsecureAuth = false
	} else {
		// 无证书环境（内网/首启）允许明文认证兜底
		s.AllowInsecureAuth = true
	}
	s.ReadTimeout = 2 * time.Minute
	s.WriteTimeout = 2 * time.Minute

	go listen(s, be.Config.SMTP.Listen, "SMTP", s.TLSConfig)
	if be.Config.SMTP.Submission != "" {
		go listen(s, be.Config.SMTP.Submission, "Submission", s.TLSConfig)
	}
	if be.Config.SMTP.TLS != "" && be.Cert != nil {
		go listenImplicit(s, be.Config.SMTP.TLS, "SMTPS", s.TLSConfig)
	}
}

func listenImplicit(s *smtp.Server, addr, name string, tlsCfg *tls.Config) {
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		log.Printf("%s 监听 %s 失败（跳过）: %v", name, addr, err)
		return
	}
	log.Printf("%s 服务就绪 %s", name, addr)
	defer func() { recover() }()
	s.Serve(ln)
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

// loginServer SASL LOGIN 机制（go-sasl 未内置服务端实现）。
type loginServer struct {
	cb    func(username, password string) error
	stage int
	user  string
}

func (l *loginServer) Start(_ []byte) ([]byte, error) {
	l.stage = 1
	return []byte("Username:"), nil
}

func (l *loginServer) Next(msg []byte) ([]byte, bool, error) {
	switch l.stage {
	case 1:
		l.user = string(msg)
		l.stage = 2
		return []byte("Password:"), false, nil
	case 2:
		if err := l.cb(l.user, string(msg)); err != nil {
			return nil, false, err
		}
		l.stage = 3
		return nil, true, nil
	}
	return nil, false, smtp.ErrAuthFailed
}
