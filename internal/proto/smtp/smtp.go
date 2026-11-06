// Package smtp SMTP 入站服务（决策 D5：SPF/DKIM 记分；D1=B：BLOB 入库）。
package smtp

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/david88558855/private-email/internal/authlimit"
	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/insecureauth"
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
	Policy *insecureauth.Policy // 明文认证来源约束，未注入时按「仅 TLS」处理
}

// RFC 4954 §4：538 用于「该认证机制必须先加密」，比笼统的 535 更能让客户端
// 自动改用 STARTTLS，而不是一直重试同一组凭据。
var errTLSRequired = &smtp.SMTPError{
	Code:         538,
	EnhancedCode: smtp.EnhancedCode{5, 7, 11},
	Message:      "Encryption required for requested authentication mechanism",
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
			// 与 POP3 parsePlain 保持同一口径：服务端不支持身份代理，
			// 非空 authzid 只允许与 authcid 相同，否则拒绝。
			if identity != "" && !strings.EqualFold(identity, username) {
				return smtp.ErrAuthFailed
			}
			return s.authenticate(username, password)
		}), nil
	case sasl.Login:
		return &loginServer{cb: s.authenticate}, nil
	}
	return nil, smtp.ErrAuthUnsupported
}

func (s *session) authenticate(username, password string) error {
	// 库的 AllowInsecureAuth 只是总开关，无法按来源区分；白名单在这里兜底，
	// 否则公网客户端照样能在 587 上看到 AUTH 并反复提交凭据。
	var isTLS bool
	var remote net.Addr
	if s.conn != nil {
		_, isTLS = s.conn.TLSConnectionState()
		if c := s.conn.Conn(); c != nil {
			remote = c.RemoteAddr()
		}
	}
	if !s.be.Policy.Allow(isTLS, remote) {
		return errTLSRequired
	}
	key := s.remoteKey()
	if !authlimit.Allow(key) || !authlimit.Allow("acct:"+strings.ToLower(username)) {
		return smtp.ErrAuthFailed
	}
	mb, ok := s.be.Store.VerifyMailboxAuth(username, password)
	if !ok {
		authlimit.Fail(key)
		authlimit.Fail("acct:" + strings.ToLower(username))
		return smtp.ErrAuthFailed
	}
	// 只清账号维度；IP 维度靠窗口自然过期，防止同 IP 用一次成功登录洗掉撞库计数。
	authlimit.Reset("acct:" + strings.ToLower(username))
	s.authUser = mb.Address
	return nil
}

// remoteKey 取来源 IP 作为限速键。
func (s *session) remoteKey() string {
	if s.conn == nil {
		return "unknown"
	}
	c := s.conn.Conn()
	if c == nil || c.RemoteAddr() == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	if s.conn != nil {
		s.helo = s.conn.Hostname()
	}
	s.from = strings.Trim(from, "<>")
	return nil
}

// Rcpt 收件人判定：
//   - 本机存在的邮箱：接受，稍后直投 INBOX。
//   - 外域地址：只有已认证会话才接受（提交端口），并写入投递队列。
//     未认证的 25 端口仍只收本站邮件，避免变成开放中继。
func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	addr := strings.Trim(to, "<>")
	if !strings.Contains(addr, "@") {
		return &smtp.SMTPError{Code: 501, Message: "bad address"}
	}
	mb, err := s.be.Store.MailboxByAddress(addr)
	if err != nil {
		return &smtp.SMTPError{Code: 451, Message: "internal error"}
	}
	if mb == nil && s.authUser == "" {
		return &smtp.SMTPError{Code: 550, Message: "relay access denied"}
	}
	if mb == nil && s.authUser != "" {
		// 外域发信配额：单账号每小时最多 300 封，防止一个账号打爆出站 IP 信誉
		if !s.be.allowSend(s.authUser) {
			return &smtp.SMTPError{Code: 452, Message: "too many messages, try later"}
		}
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
	// 已认证会话只能用自己的地址发信，防冒用同服务器其他人的发件人
	if s.authUser != "" && !strings.EqualFold(s.from, s.authUser) {
		return &smtp.SMTPError{Code: 553, Message: "sender must match authenticated user"}
	}
	// 空发件人 <> 用于退信（RFC 5321 §4.5.5）；已认证会话已在上面强制匹配，
	// 这里只有未认证的入站会话能走到。

	p := mailutil.Parse(raw)

	// 本机用户自己提交的邮件不做 SPF/DKIM 记分（他们本来就没有对端域的签名）
	score := 0.0
	if s.authUser == "" {
		var host string
		if s.conn != nil && s.conn.Conn() != nil && s.conn.Conn().RemoteAddr() != nil {
			host, _, _ = net.SplitHostPort(s.conn.Conn().RemoteAddr().String())
		}
		res, _ := spf.CheckHostWithSender(net.ParseIP(host), s.helo, s.from)
		if res != spf.Pass {
			score += 1.5
		}
		if !dkimPass(raw) {
			score += 1.5
		}
	}

	// 加 Received 头（RFC 5321 §4.4）：没有它就没有链路追踪，
	// 也无法用 Received 计数检测邮件环路，反垃圾评分会被扣。
	raw = prependReceived(raw, s.helo, s.remoteIP(), s.be.Config.TLS.Hostname)

	// 分组：本地直投 / 外域入队。全部放在一个事务里提交，
	// 避免「前几个收件人写库成功、后面失败返回 451」导致发信方重发整封、前面的人收到两封。
	var locals []store.LocalDelivery
	var externals []string
	for _, addr := range s.rcpts {
		mb, err := s.be.Store.MailboxByAddress(addr)
		if err != nil {
			return &smtp.SMTPError{Code: 451, Message: "internal error"}
		}
		if mb == nil {
			externals = append(externals, addr)
			continue
		}
		locals = append(locals, store.LocalDelivery{
			MailboxID: mb.ID,
			Address:   addr,
			Subject:   p.Subject,
			Code:      extractCode(s.be.Store, p.TextBody+" "+mailutil.StripHTML(p.HTMLBody)+" "+p.Subject, mb.ID),
			Score:     score,
			TextBody:  p.TextBody,
		})
	}

	queueMailboxID := int64(0)
	if s.authUser != "" {
		if mb, err := s.be.Store.MailboxByAddress(s.authUser); err == nil && mb != nil {
			queueMailboxID = mb.ID
		}
	}
	if err := s.be.Store.DeliverInbound(s.from, raw, locals, queueMailboxID, externals); err != nil {
		log.Printf("SMTP 投递失败 %s: %v", s.from, err)
		return &smtp.SMTPError{Code: 451, Message: "delivery failed"}
	}
	log.Printf("SMTP 收信 %s -> %v (%dB, spam=%.1f)", s.from, s.rcpts, len(raw), score)
	return nil
}

func (s *session) remoteIP() string {
	if s.conn == nil || s.conn.Conn() == nil || s.conn.Conn().RemoteAddr() == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(s.conn.Conn().RemoteAddr().String())
	if err != nil {
		return s.conn.Conn().RemoteAddr().String()
	}
	return host
}

func (s *session) Logout() error { return nil }

// prependReceived 在报文头部插入本站的 Received 行。
func prependReceived(raw []byte, helo, ip, hostname string) []byte {
	if hostname == "" {
		hostname = "private-email"
	}
	if helo == "" {
		helo = "unknown"
	}
	var idb [8]byte
	rand.Read(idb[:])
	line := fmt.Sprintf("Received: from %s (%s) by %s with ESMTP id %s; %s\r\n",
		helo, ip, hostname, hex.EncodeToString(idb[:]), time.Now().Format(time.RFC1123Z))
	out := make([]byte, 0, len(raw)+len(line))
	out = append(out, line...)
	out = append(out, raw...)
	return out
}

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

// extractCode 先按该邮箱的自定义规则，再按全局规则，最后走内置规则。
func extractCode(st *store.Store, text string, mailboxID int64) string {
	rows, err := st.DB.Query(`SELECT pattern FROM verification_rules
		WHERE is_active=1 AND (mailbox_id IS NULL OR mailbox_id=?)
		ORDER BY mailbox_id IS NULL, id`, mailboxID)
	if err != nil {
		return mailutil.ExtractCode(text, nil)
	}
	return mailutil.ExtractCode(text, rows)
}

// ---------- 外发配额 ----------

type quotaBucket struct {
	n     int
	reset time.Time
}

var (
	quotaMu  sync.Mutex
	quotaMap = map[string]*quotaBucket{}
)

const sendQuotaPerHour = 300

// allowSend 每个已认证账号每小时的外发上限（进程内计数）。
func (b *Backend) allowSend(address string) bool {
	now := time.Now()
	quotaMu.Lock()
	defer quotaMu.Unlock()
	if len(quotaMap) > 10000 {
		for k, v := range quotaMap {
			if now.After(v.reset) {
				delete(quotaMap, k)
			}
		}
	}
	q, ok := quotaMap[address]
	if !ok || now.After(q.reset) {
		quotaMap[address] = &quotaBucket{n: 1, reset: now.Add(time.Hour)}
		return true
	}
	if q.n >= sendQuotaPerHour {
		return false
	}
	q.n++
	return true
}

// Serve 启动 SMTP 三个监听（25 STARTTLS / 587 submission / 465 隐式 TLS）。
func Serve(be *Backend) {
	s := smtp.NewServer(be)
	s.Domain = hostnameOr(be.Config.TLS.Hostname, "private-email")
	s.MaxMessageBytes = be.Config.SMTP.MaxSize * 1024 * 1024
	// 总开关只决定 EHLO 是否公布 AUTH；具体来源是否放行由 Policy 在认证回调里判。
	s.AllowInsecureAuth = be.Config.Security.AllowInsecureAuth
	if be.Cert != nil {
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*be.Cert}}
	}
	s.ReadTimeout = 5 * time.Minute
	s.WriteTimeout = 5 * time.Minute
	s.MaxRecipients = 100
	// 单行上限（RFC 5321 §4.5.3.1.6 要求 ≥1000）。不设时库不限制，
	// 一个不带换行的超长行就能把内存吃满。
	s.MaxLineLength = 2000

	if be.Config.SMTP.Listen != "" {
		go listen(s, be.Config.SMTP.Listen, "SMTP", be.Config.Security.MaxConns)
	}
	if be.Config.SMTP.Submission != "" {
		go listen(s, be.Config.SMTP.Submission, "Submission", be.Config.Security.MaxConns)
	}
	if be.Config.SMTP.TLS != "" && be.Cert != nil {
		go listenImplicit(s, be.Config.SMTP.TLS, "SMTPS", s.TLSConfig, be.Config.Security.MaxConns)
	}
}

func hostnameOr(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

func listenImplicit(s *smtp.Server, addr, name string, tlsCfg *tls.Config, maxConns int) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("%s 监听 %s 失败（跳过）: %v", name, addr, err)
		return
	}
	log.Printf("%s 服务就绪 %s", name, addr)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SMTP 监听 panic: %v\n%s", r, debug.Stack())
		}
	}()
	// 隐式 TLS 同样要限连接数，但限流必须放在 TLS 里面：
	// go-smtp 用 `c.conn.(*tls.Conn)` 判断连接是否加密，外层包自定义
	// net.Conn 会让 AUTH 被当成明文而拒绝。
	s.Serve(newLimitTLSListener(ln, maxConns, tlsCfg))
}

// limitTLSListener 先限流 TCP，再自己 tls.Server()，返回的仍是 *tls.Conn。
type limitTLSListener struct {
	net.Listener
	sem chan struct{}
	cfg *tls.Config
}

func newLimitTLSListener(ln net.Listener, n int, cfg *tls.Config) net.Listener {
	if n <= 0 {
		return tls.NewListener(ln, cfg)
	}
	return &limitTLSListener{Listener: ln, sem: make(chan struct{}, n), cfg: cfg}
}

func (l *limitTLSListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return tls.Server(&limitConn{Conn: c, release: func() { <-l.sem }}, l.cfg), nil
}

func listen(s *smtp.Server, addr, name string, maxConns int) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("%s 监听 %s 失败: %v（跳过）", name, addr, err)
		return
	}
	log.Printf("%s 服务就绪 %s", name, addr)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SMTP 监听 panic: %v\n%s", r, debug.Stack())
		}
	}()
	s.Serve(limitListener(ln, maxConns))
}

// limitListener 限制并发连接数（SMTP 侧同样需要，避免连接洪泛）。
type limitListenerImpl struct {
	net.Listener
	sem chan struct{}
}

func limitListener(ln net.Listener, n int) net.Listener {
	if n <= 0 {
		return ln
	}
	return &limitListenerImpl{Listener: ln, sem: make(chan struct{}, n)}
}

func (l *limitListenerImpl) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

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
