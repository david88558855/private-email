// Package pop3 POP3 服务端（RFC 1939 最小集）。
package pop3

import (
	"bufio"
	"crypto/tls"

	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/store"
)

// Serve 启动 POP3 明文（110）；TLS 995 于 M6 挂证书后启用。
func Serve(st *store.Store, cfg *config.Config, cert *tls.Certificate) {
	ln, err := net.Listen("tcp", cfg.POP3.Listen)
	if err != nil {
		log.Printf("POP3 监听 %s 失败（跳过）: %v", cfg.POP3.Listen, err)
		return
	}
	log.Printf("POP3 服务就绪 %s", cfg.POP3.Listen)
	go accept(ln, st)
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
	id  int64
	uid string
	raw []byte
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
			s.user = parts[1] // nolint
			write("+OK")
		case "PASS":
			if s.user == "" {
				write("-ERR USER first")
				break
			}
			mb, ok := s.st.VerifyMailboxAuth(s.user, strings.Join(parts[1:], " "))
			if !ok {
				write("-ERR authentication failed")
				break
			}
			s.mb = mb
			s.st.EnsureFolders(mb.ID)
			folderID, err := s.st.FolderID(mb.ID, "INBOX")
			if err != nil {
				write("-ERR no INBOX")
				break
			}
			items, _, _ := s.st.ListMails(folderID, "", 500, 0)
			s.mails = nil
			for _, it := range items {
				full, err := s.st.GetMail(it.ID)
				if err != nil {
					continue
				}
				s.mails = append(s.mails, mailDrop{id: it.ID, uid: fmt.Sprintf("%d-%d", it.UID, it.Size), raw: full.Raw})
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
					write(fmt.Sprintf("+OK %d %d", i, len(s.mails[i-1].raw)))
				} else {
					write("-ERR no such message")
				}
				break
			}
			n, size := s.stats()
			write(fmt.Sprintf("+OK %d messages (%d octets)", n, size))
			for i, m := range s.mails {
				if !s.deleted[int64(i+1)] {
					fmt.Fprintf(w, "%d %d\r\n", i+1, len(m.raw))
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
			i, _ := strconv.Atoi(parts[1])
			if i < 1 || i > len(s.mails) || s.deleted[int64(i)] {
				write("-ERR no such message")
				break
			}
			write("+OK")
			raw := s.mails[i-1].raw
			w.Write([]byte(strings.ReplaceAll(string(raw), "\r\n.", "\r\n..") + "\r\n"))
			write(".")
			s.st.MarkSeen(s.mails[i-1].id)
		case "TOP":
			if !s.authed() {
				write("-ERR not authenticated")
				break
			}
			i, _ := strconv.Atoi(parts[1])
			_, _ = strconv.Atoi(parts[2])
			if i < 1 || i > len(s.mails) || s.deleted[int64(i)] {
				write("-ERR no such message")
				break
			}
			head := headerOnly(s.mails[i-1].raw)
			write("+OK")
			w.Write(head)
			write("")
			write(".")
		case "DELE":
			if !s.authed() {
				write("-ERR not authenticated")
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

func (s *sess) stats() (int, int) {
	n, size := 0, 0
	for i, m := range s.mails {
		if !s.deleted[int64(i+1)] {
			n++
			size += len(m.raw)
		}
	}
	return n, size
}

var _ = binary.BigEndian.Uint32
