// Package pop3 POP3 服务端（RFC 1939 最小集）。
package pop3

import (
	"bufio"
	"crypto/tls"

	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/david88558855/private-email/internal/authlimit"
	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/store"
)

// Serve 启动 POP3 明文（110）；TLS 995 于 M6 挂证书后启用。
func Serve(st *store.Store, cfg *config.Config, cert *tls.Certificate) {
	// 端口为空表示关闭该监听（net.Listen("tcp","") 会绑随机端口）
	if cfg.POP3.Listen != "" {
		ln, err := net.Listen("tcp", cfg.POP3.Listen)
		if err != nil {
			log.Printf("POP3 监听 %s 失败（跳过）: %v", cfg.POP3.Listen, err)
		} else {
			log.Printf("POP3 服务就绪 %s", cfg.POP3.Listen)
			go accept(ln, st)
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
			accept(tln, st)
		}()
	}
}

func accept(ln net.Listener, st *store.Store) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(conn, st)
	}
}

type sess struct {
	st      *store.Store
	user    string
	mb      *store.Mailbox
	mails   []mailDrop
	deleted map[int64]bool
}

type mailDrop struct {
	id   int64
	uid  string
	size int
}

func handle(conn net.Conn, st *store.Store) {
	defer conn.Close()
	defer func() { recover() }()
	s := &sess{st: st, deleted: map[int64]bool{}}
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)
	write := func(s2 string) { w.WriteString(s2 + "\r\n"); w.Flush() }
	write("+OK Private Email POP3 ready")
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 32*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		parts := strings.Fields(line)
		if len(parts) == 0 {
			write("-ERR empty")
			continue
		}
		cmd := strings.ToUpper(parts[0])
		switch cmd {
		case "USER":
			if len(parts) < 2 {
				write("-ERR username required")
				break
			}
			s.user = parts[1]
			write("+OK")
		case "PASS":
			if s.user == "" {
				write("-ERR USER first")
				break
			}
			key := remoteHost(conn)
			if !authlimit.Allow(key) {
				write("-ERR too many failed attempts, try later")
				break
			}
			mb, ok := s.st.VerifyMailboxAuth(s.user, strings.Join(parts[1:], " "))
			if !ok {
				authlimit.Fail(key)
				write("-ERR authentication failed")
				break
			}
			authlimit.Reset(key)
			s.mb = mb
			s.st.EnsureFolders(mb.ID)
			folderID, err := s.st.FolderID(mb.ID, "INBOX")
			if err != nil {
				write("-ERR no INBOX")
				break
			}
			// 只记索引不读正文：正文按 RETR/TOP 现取，避免大邮箱登录时把全部邮件读进内存
			items, _, _ := s.st.ListMails(folderID, "", 500, 0)
			s.mails = nil
			for _, it := range items {
				s.mails = append(s.mails, mailDrop{id: it.ID, uid: fmt.Sprintf("%d-%d", it.UID, it.Size), size: it.Size})
			}
			s.deleted = map[int64]bool{}
			write(fmt.Sprintf("+OK mailbox has %d messages", len(s.mails)))
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
				if i >= 1 && i <= len(s.mails) && !s.deleted[int64(i)] {
					write(fmt.Sprintf("+OK %d %d", i, s.mails[i-1].size))
				} else {
					write("-ERR no such message")
				}
				break
			}
			n, size := s.stats()
			write(fmt.Sprintf("+OK %d messages (%d octets)", n, size))
			for i, m := range s.mails {
				if !s.deleted[int64(i+1)] {
					fmt.Fprintf(w, "%d %d\r\n", i+1, m.size)
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
				if i >= 1 && i <= len(s.mails) && !s.deleted[int64(i)] {
					write(fmt.Sprintf("+OK %d %s", i, s.mails[i-1].uid))
				} else {
					write("-ERR no such message")
				}
				break
			}
			write("+OK")
			for i, m := range s.mails {
				if !s.deleted[int64(i+1)] {
					fmt.Fprintf(w, "%d %s\r\n", i+1, m.uid)
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
			if i < 1 || i > len(s.mails) || s.deleted[int64(i)] {
				write("-ERR no such message")
				break
			}
			full, err := s.st.GetMail(s.mails[i-1].id)
			if err != nil {
				write("-ERR message gone")
				break
			}
			write("+OK")
			w.Write(dotStuff(full.Raw))
			write(".")
			s.st.MarkSeen(s.mails[i-1].id)
		case "TOP":
			if !s.authed() {
				write("-ERR not authenticated")
				break
			}
			if len(parts) < 2 {
				write("-ERR message number required")
				break
			}
			i, _ := strconv.Atoi(parts[1])
			if i < 1 || i > len(s.mails) || s.deleted[int64(i)] {
				write("-ERR no such message")
				break
			}
			full, err := s.st.GetMail(s.mails[i-1].id)
			if err != nil {
				write("-ERR message gone")
				break
			}
			head := headerOnly(full.Raw)
			write("+OK")
			w.Write(head)
			write("")
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
			if i < 1 || i > len(s.mails) || s.deleted[int64(i)] {
				write("-ERR no such message")
				break
			}
			s.deleted[int64(i)] = true
			write(fmt.Sprintf("+OK message %d deleted", i))
		case "RSET":
			s.deleted = map[int64]bool{}
			write("+OK")
		case "NOOP":
			write("+OK")
		case "QUIT":
			if s.authed() {
				// 更新阶段：真正删除被 DELE 的邮件（MoveToTrash 语义按 RFC 永久删除）
				for i := range s.mails {
					if s.deleted[int64(i+1)] {
						s.st.DB.Exec(`DELETE FROM mails WHERE id=?`, s.mails[i].id)
					}
				}
			}
			write("+OK bye")
			return
		case "CAPA":
			write("+OK")
			write("UIDL")
			write("TOP")
			write("USER")
			write(".")
		default:
			write("-ERR unknown command")
		}
	}
}

func headerOnly(raw []byte) []byte {
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] == '\n' && (i+1 >= len(raw) || raw[i+1] == '\r' || raw[i+1] == '\n') {
			return raw[:i+1]
		}
	}
	return raw
}

func (s *sess) authed() bool { return s.mb != nil }

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
		if !s.deleted[int64(i+1)] {
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
	out = append(out, '\r', '\n')
	return out
}
