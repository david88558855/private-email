// Package pop3 POP3 服务端（RFC 1939 最小集）。
package pop3

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/david88558855/private-email/internal/authlimit"
	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/insecureauth"
	"github.com/david88558855/private-email/internal/store"
)

// idleTimeout 单条命令之间的最长空闲时间。
// 原来 bufio.Scanner 直接阻塞在 conn 上，没有任何 deadline，
// 一个连接可以挂到天荒地老，扫描器能把 fd 和 goroutine 耗光。
const idleTimeout = 5 * time.Minute

// Serve 启动 POP3 明文（110）与隐式 TLS（995）。
func Serve(st *store.Store, cfg *config.Config, cert *tls.Certificate, policy *insecureauth.Policy) {
	if cfg.POP3.Listen != "" {
		ln, err := net.Listen("tcp", cfg.POP3.Listen)
		if err != nil {
			log.Printf("POP3 监听 %s 失败（跳过）: %v", cfg.POP3.Listen, err)
		} else {
			log.Printf("POP3 服务就绪 %s", cfg.POP3.Listen)
			go accept(limitListener(ln, cfg.Security.MaxConns), st, false, policy)
		}
	}
	if cfg.POP3.TLS != "" && cert != nil {
		go func() {
			tln, err := tls.Listen("tcp", cfg.POP3.TLS, &tls.Config{Certificates: []tls.Certificate{*cert}})
			if err != nil {
				log.Printf("POP3S 监听失败（跳过）: %v", err)
				return
			}
			log.Printf("POP3S 服务就绪 %s", cfg.POP3.TLS)
			// POP3 自己判断 isTLS，包一层连接限制不会影响（不像 IMAP/SMTP 依赖具体类型）
			accept(limitListener(tln, cfg.Security.MaxConns), st, true, policy)
		}()
	}
}

func accept(ln net.Listener, st *store.Store, isTLS bool, policy *insecureauth.Policy) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(conn, st, isTLS, policy)
	}
}

// limitListener 限制并发连接数。
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

// mailboxLock 保证同一邮箱同时只有一个 POP3 会话（RFC 1939 的 maildrop 独占）。
// 不加锁时两个客户端同时下载，同一封邮件会被取两次。
var (
	lockMu sync.Mutex
	inUse  = map[int64]bool{}
)

func acquire(mailboxID int64) bool {
	lockMu.Lock()
	defer lockMu.Unlock()
	if inUse[mailboxID] {
		return false
	}
	inUse[mailboxID] = true
	return true
}

func release(mailboxID int64) {
	lockMu.Lock()
	delete(inUse, mailboxID)
	lockMu.Unlock()
}

type sess struct {
	st       *store.Store
	user     string
	mb       *store.Mailbox
	loggedIn bool // 是否已完成认证并进入 TRANSACTION 状态
	mails    []mailDrop
	deleted  map[int]bool
	locked   bool
}

type mailDrop struct {
	id   int64
	uid  string
	size int
}

// parsePlain 解 RFC 4616 的 PLAIN 凭据：authzid\0authcid\0passwd。
// 服务端不支持身份代理，authzid 必须为空，否则拒绝——放行会让客户端以他人身份登录。
func parsePlain(b []byte) (string, string, error) {
	parts := bytes.SplitN(b, []byte{0}, 3)
	if len(parts) != 3 || len(parts[0]) != 0 || len(parts[1]) == 0 || len(parts[2]) == 0 {
		return "", "", fmt.Errorf("invalid PLAIN payload")
	}
	return string(parts[1]), string(parts[2]), nil
}

// verify 是 PASS 与 AUTH PLAIN 共用的认证入口：来源约束、失败限速、凭据校验。
// 返回 nil 时 msg 是可直接写给客户端的错误行，不回显任何凭据内容。
func (s *sess) verify(conn net.Conn, policy *insecureauth.Policy, isTLS bool,
	user, pass string) (*store.Mailbox, string) {
	if !policy.Allow(isTLS, conn.RemoteAddr()) {
		return nil, "-ERR TLS required"
	}
	key := remoteHost(conn)
	acct := "acct:" + strings.ToLower(user)
	if !authlimit.Allow(key) || !authlimit.Allow(acct) {
		return nil, "-ERR too many failed attempts, try later"
	}
	mb, ok := s.st.VerifyMailboxAuth(user, pass)
	if !ok {
		authlimit.Fail(key)
		authlimit.Fail(acct)
		return nil, "-ERR authentication failed"
	}
	// 只清账号维度，不清 IP 维度：否则知道任一账号口令就能反复「洗白」同一 IP 上的撞库计数。
	authlimit.Reset(acct)
	return mb, ""
}

// enterTransaction 认证成功后进入 TRANSACTION 状态，与 USER/PASS 路径完全一致。
// mb/locked 必须在 acquire 之后立刻置位（供 defer 释放 maildrop 锁），
// 但 loggedIn 只能等所有初始化成功后才置，否则会留下「假认证」会话。
func (s *sess) enterTransaction(mb *store.Mailbox, write func(string)) bool {
	if err := s.st.EnsureFolders(mb.ID); err != nil {
		write("-ERR mailbox unavailable")
		return false
	}
	folderID, err := s.st.FolderID(mb.ID, "INBOX")
	if err != nil {
		write("-ERR no INBOX")
		return false
	}
	// 只记索引不读正文：正文按 RETR/TOP 现取。按 UID 升序（老邮件在前）。
	items, err := s.st.ListMailsAsc(folderID)
	if err != nil {
		write("-ERR mailbox unavailable")
		return false
	}
	// 所有初始化都成功之后才抢 maildrop 锁。若先抢锁而初始化失败，
	// 客户端重试认证会撞上自己持有的锁，该邮箱会被锁死到断连。
	if !acquire(mb.ID) {
		write("-ERR mailbox is locked by another session")
		return false
	}
	s.mails = make([]mailDrop, 0, len(items))
	for _, it := range items {
		s.mails = append(s.mails, mailDrop{id: it.ID, uid: fmt.Sprintf("%d-%d", it.UID, it.Size), size: it.Size})
	}
	s.deleted = map[int]bool{}
	s.mb, s.locked = mb, true
	s.user, s.loggedIn = mb.Address, true
	write(fmt.Sprintf("+OK mailbox has %d messages", len(s.mails)))
	return true
}

func handle(conn net.Conn, st *store.Store, isTLS bool, policy *insecureauth.Policy) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("POP3 会话 panic: %v\n%s", r, debug.Stack())
		}
	}()
	s := &sess{st: st, deleted: map[int]bool{}}
	defer func() {
		if s.locked && s.mb != nil {
			release(s.mb.ID)
		}
	}()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)
	// 写失败（对端不读/超时）时立刻关连接：否则本 goroutine 会继续卡在读上，
	// 连接数信号量与 maildrop 锁迟迟不释放，累积后整个端口拒绝服务。
	write := func(s2 string) {
		if _, err := w.WriteString(s2 + "\r\n"); err != nil {
			conn.Close()
			return
		}
		if err := w.Flush(); err != nil {
			conn.Close()
		}
	}
	write("+OK Private Email POP3 ready")

	// 用 Scanner 而不是 ReadString：ReadString 遇到一个不带换行的超长行
	// 会一直往内存里堆，等于给了一个廉价的 DoS 面。
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 64*1024)
	for {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		if !sc.Scan() {
			return
		}
		// 写超时从「收到命令之后」开始计时。放在 sc.Scan 之前会让命令间空闲
		// 吞掉写窗口，空闲接近 5 分钟时 RETR 大邮件必然被截断。
		conn.SetWriteDeadline(time.Now().Add(idleTimeout))
		// 只去掉行尾换行，不要 TrimSpace：PASS 的口令要按原始剩余串取，
		// 否则 strings.Fields 会把连续空格/制表符压成一个，口令被悄悄改写。
		line := strings.TrimRight(sc.Text(), "\r\n")
		parts := strings.Fields(line)
		if len(parts) == 0 {
			write("-ERR empty")
			continue
		}
		cmd := strings.ToUpper(parts[0])
		switch cmd {
		case "USER":
			if s.authed() {
				write("-ERR already authenticated")
				break
			}
			if len(parts) < 2 {
				write("-ERR username required")
				break
			}
			s.user = parts[1]
			write("+OK")
		case "PASS":
			if s.authed() {
				write("-ERR already authenticated")
				break
			}
			if s.user == "" {
				write("-ERR USER first")
				break
			}
			// RFC 1939 的 PASS 参数与命令之间只隔一个空白，取原始剩余串。
			var pass string
			if i := strings.IndexAny(line, " \t"); i >= 0 {
				pass = strings.TrimLeft(line[i:], " \t")
			}
			mb, msg := s.verify(conn, policy, isTLS, s.user, pass)
			if mb == nil {
				write(msg)
				break
			}
			s.enterTransaction(mb, write)
		case "AUTH":
			// RFC 5034：AUTH PLAIN [base64(initial-response)]，成功即进入 TRANSACTION。
			// 先判来源再收凭据，避免不可信来源借 AUTH 反复触发 bcrypt。
			if s.authed() {
				write("-ERR already authenticated")
				break
			}
			if len(parts) < 2 || !strings.EqualFold(parts[1], "PLAIN") {
				write("-ERR unsupported SASL mechanism (PLAIN only)")
				break
			}
			if !policy.Allow(isTLS, conn.RemoteAddr()) {
				write("-ERR TLS required")
				break
			}
			var payload []byte
			var err error
			if len(parts) > 2 {
				payload, err = base64.StdEncoding.DecodeString(parts[2])
			} else {
				// PLAIN 无 challenge：发空 challenge，再读客户端的一行 base64 响应。
				write("+ ")
				conn.SetReadDeadline(time.Now().Add(idleTimeout))
				if !sc.Scan() {
					return
				}
				conn.SetWriteDeadline(time.Now().Add(idleTimeout))
				respLine := strings.TrimSpace(sc.Text())
				if respLine == "*" {
					write("-ERR authentication cancelled")
					break
				}
				payload, err = base64.StdEncoding.DecodeString(respLine)
			}
			if err != nil {
				write("-ERR invalid base64 response")
				break
			}
			user, pass, err := parsePlain(payload)
			if err != nil {
				write("-ERR invalid PLAIN credentials")
				break
			}
			mb, msg := s.verify(conn, policy, isTLS, user, pass)
			if mb == nil {
				write(msg)
				break
			}
			s.enterTransaction(mb, write)
		case "STAT":
			if !s.authed() {
				write("-ERR not authenticated")
				break
			}
			n, size := s.stats()
			write(fmt.Sprintf("+OK %d %d", n, size))
		case "LIST":
			if !s.authed() {
				write("-ERR not authenticated")
				break
			}
			if len(parts) > 1 {
				i, _ := strconv.Atoi(parts[1])
				if s.valid(i) {
					write(fmt.Sprintf("+OK %d %d", i, s.mails[i-1].size))
				} else {
					write("-ERR no such message")
				}
				break
			}
			n, size := s.stats()
			write(fmt.Sprintf("+OK %d messages (%d octets)", n, size))
			for i, m := range s.mails {
				if !s.deleted[i+1] {
					if _, err := fmt.Fprintf(w, "%d %d\r\n", i+1, m.size); err != nil {
						return
					}
				}
			}
			write(".")
		case "UIDL":
			if !s.authed() {
				write("-ERR not authenticated")
				break
			}
			if len(parts) > 1 {
				i, _ := strconv.Atoi(parts[1])
				if s.valid(i) {
					write(fmt.Sprintf("+OK %d %s", i, s.mails[i-1].uid))
				} else {
					write("-ERR no such message")
				}
				break
			}
			write("+OK")
			for i, m := range s.mails {
				if !s.deleted[i+1] {
					if _, err := fmt.Fprintf(w, "%d %s\r\n", i+1, m.uid); err != nil {
						return
					}
				}
			}
			write(".")
		case "RETR":
			if !s.authed() {
				write("-ERR not authenticated")
				break
			}
			if len(parts) < 2 {
				write("-ERR message number required")
				break
			}
			i, _ := strconv.Atoi(parts[1])
			if !s.valid(i) {
				write("-ERR no such message")
				break
			}
			full, err := s.st.GetMail(s.mails[i-1].id)
			if err != nil {
				write("-ERR message gone")
				break
			}
			write("+OK")
			if _, err := w.Write(dotStuff(full.Raw)); err != nil {
				return
			}
			write(".")
			s.st.MarkSeen(s.mails[i-1].id)
		case "TOP":
			if !s.authed() {
				write("-ERR not authenticated")
				break
			}
			if len(parts) < 3 {
				write("-ERR usage: TOP msg n")
				break
			}
			i, _ := strconv.Atoi(parts[1])
			nLines, _ := strconv.Atoi(parts[2])
			if !s.valid(i) {
				write("-ERR no such message")
				break
			}
			full, err := s.st.GetMail(s.mails[i-1].id)
			if err != nil {
				write("-ERR message gone")
				break
			}
			write("+OK")
			if _, err := w.Write(dotStuff(topBody(full.Raw, nLines))); err != nil {
				return
			}
			write(".")
		case "DELE":
			if !s.authed() {
				write("-ERR not authenticated")
				break
			}
			if len(parts) < 2 {
				write("-ERR message number required")
				break
			}
			i, _ := strconv.Atoi(parts[1])
			if !s.valid(i) {
				write("-ERR no such message")
				break
			}
			s.deleted[i] = true
			write(fmt.Sprintf("+OK message %d deleted", i))
		case "RSET":
			s.deleted = map[int]bool{}
			write("+OK")
		case "NOOP":
			write("+OK")
		case "QUIT":
			if s.authed() {
				// 更新阶段：真正删除被 DELE 的邮件（RFC：QUIT 才提交删除）。
				// 全部删除放进一个事务，中途失败时不留下「删了一半」的邮箱。
				var ids []int64
				for i := range s.mails {
					if s.deleted[i+1] {
						ids = append(ids, s.mails[i].id)
					}
				}
				if len(ids) > 0 {
					tx, err := s.st.DB.Begin()
					if err != nil {
						write("-ERR mailbox unavailable")
						return
					}
					for _, id := range ids {
						if _, err := tx.Exec(`DELETE FROM mails WHERE id=?`, id); err != nil {
							tx.Rollback()
							write("-ERR some deleted messages not removed")
							return
						}
					}
					if err := tx.Commit(); err != nil {
						write("-ERR some deleted messages not removed")
						return
					}
				}
			}
			write("+OK bye")
			return
		case "CAPA":
			write("+OK")
			// RFC 5034：只在允许明文认证的连接上公布 SASL，与 IMAP/SMTP 的能力发布保持一致
			if policy.Allow(isTLS, conn.RemoteAddr()) {
				write("SASL PLAIN")
			}
			write("UIDL")
			write("TOP")
			write("USER")
			write(".")
		default:
			write("-ERR unknown command")
		}
	}
}

func (s *sess) authed() bool { return s.loggedIn }

// valid 检查邮件序号是否可用（1-based，且未被标记删除）。
func (s *sess) valid(i int) bool {
	return i >= 1 && i <= len(s.mails) && !s.deleted[i]
}

// topBody 返回邮件头 + 正文前 n 行。
// 原实现直接忽略 n，永远只回头部，客户端预览行为与配置不符。
func topBody(raw []byte, n int) []byte {
	sep := -1
	for i := 0; i+3 < len(raw); i++ {
		if raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n' {
			sep = i + 4
			break
		}
		if raw[i] == '\n' && raw[i+1] == '\n' {
			sep = i + 2
			break
		}
	}
	if sep < 0 {
		return raw
	}
	head := raw[:sep]
	if n <= 0 {
		return head
	}
	body := raw[sep:]
	out := make([]byte, 0, len(head)+256)
	out = append(out, head...)
	start := 0
	lines := 0
	for i := 0; i < len(body) && lines < n; i++ {
		if body[i] == '\n' {
			out = append(out, body[start:i+1]...)
			start = i + 1
			lines++
		}
	}
	if start < len(body) && lines < n {
		out = append(out, body[start:]...)
	}
	return out
}

// remoteHost 取来源 IP 作为限速键。
func remoteHost(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

func (s *sess) stats() (int, int) {
	n, size := 0, 0
	for i, m := range s.mails {
		if !s.deleted[i+1] {
			n++
			size += m.size
		}
	}
	return n, size
}

// dotStuff RFC 1939 字节填充：行首 '.' 翻倍（含首行）。
func dotStuff(raw []byte) []byte {
	out := make([]byte, 0, len(raw)+16)
	// 首字节就是 '.' 时补一个点（循环里还会写入原始那个点，合计两个）
	if len(raw) > 0 && raw[0] == '.' {
		out = append(out, '.')
	}
	for i := 0; i < len(raw); i++ {
		out = append(out, raw[i])
		if raw[i] == '\n' && i+1 < len(raw) && raw[i+1] == '.' {
			out = append(out, '.')
			i++
			out = append(out, '.')
		}
	}
	// 报文本身以 CRLF 结尾时不再补空行，避免多出一个空白行
	switch {
	case bytes.HasSuffix(out, []byte("\r\n")):
	case bytes.HasSuffix(out, []byte("\n")):
		out = append(out[:len(out)-1], '\r', '\n') // 纯 LF 结尾补成 CRLF
	default:
		out = append(out, '\r', '\n')
	}
	return out
}
