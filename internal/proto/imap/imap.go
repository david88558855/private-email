// Package imap IMAP4rev1 服务端（go-imap v1）。
package imap

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/store"
	imapbackend "github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap/backend/backendutil"
	imapserver "github.com/emersion/go-imap/server"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
)

type Backend struct {
	Store  *store.Store
	Config *config.Config
	Cert   *tls.Certificate
}

func (b *Backend) Login(_ *imapbackend.ConnInfo, username, password string) (backend.User, error) {
	mb, ok := b.Store.VerifyMailboxAuth(username, password)
	if !ok {
		return nil, backend.ErrInvalidCredentials
	}
	if err := b.Store.EnsureFolders(mb.ID); err != nil {
		return nil, err
	}
	return &User{be: b, mb: mb}, nil
}

// ---------- User ----------

type User struct {
	be *Backend
	mb *store.Mailbox
}

func (u *User) Username() string { return u.mb.Address }

func (u *User) ListMailboxes(bool) ([]backend.Mailbox, error) {
	fs, err := u.be.Store.FoldersOf(u.mb.ID)
	if err != nil {
		return nil, err
	}
	out := make([]backend.Mailbox, 0, len(fs))
	for _, f := range fs {
		out = append(out, u.mailbox(f["name"].(string)))
	}
	return out, nil
}

func (u *User) mailbox(name string) *Mailbox {
	var id int64
	u.be.Store.DB.QueryRow(`SELECT id FROM folders WHERE mailbox_id=? AND name=?`, u.mb.ID, name).Scan(&id)
	return &Mailbox{u: u, id: id, name: name}
}

func (u *User) GetMailbox(name string) (backend.Mailbox, error) {
	fs, _ := u.be.Store.FoldersOf(u.mb.ID)
	for _, f := range fs {
		if f["name"].(string) == name {
			return u.mailbox(name), nil
		}
	}
	return nil, backend.ErrNoSuchMailbox
}

func (u *User) CreateMailbox(name string) error {
	_, err := u.be.Store.DB.Exec(`INSERT INTO folders(mailbox_id, name, uid_validity) VALUES(?,?,?)`,
		u.mb.ID, name, randUint32())
	return err
}

func (u *User) DeleteMailbox(name string) error {
	if name == "INBOX" {
		return fmt.Errorf("cannot delete INBOX")
	}
	_, err := u.be.Store.DB.Exec(`DELETE FROM folders WHERE mailbox_id=? AND name=?`, u.mb.ID, name)
	return err
}

func (u *User) RenameMailbox(old, new string) error {
	_, err := u.be.Store.DB.Exec(`UPDATE folders SET name=? WHERE mailbox_id=? AND name=?`, new, u.mb.ID, old)
	return err
}

func (u *User) Poll() error   { return nil }
func (u *User) Close() error  { return nil }
func (u *User) Logout() error { return nil }

func randUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:]) | 1
}

// ---------- Mailbox ----------

type Mailbox struct {
	u    *User
	id   int64
	name string
}

func (m *Mailbox) Name() string { return m.name }

func (m *Mailbox) Info() (*imapbackend.MailboxInfo, error) {
	return &imapbackend.MailboxInfo{
		Attributes: []string{imapbackend.NoInferiorsAttr},
		Delimiter:  "/",
		Name:       m.name,
	}, nil
}

func (m *Mailbox) Status(items []imapbackend.StatusItem) (*imapbackend.MailboxStatus, error) {
	st := &imapbackend.MailboxStatus{Name: m.name}
	var total, unread, uidNext, uidValidity int64
	m.u.be.Store.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM mails WHERE folder_id=?),
		(SELECT COUNT(*) FROM mails WHERE folder_id=? AND flags NOT LIKE '%\Seen%'),
		uid_next, uid_validity FROM folders WHERE id=?`,
		m.id, m.id, m.id, m.id).Scan(&total, &unread, &uidNext, &uidValidity)
	for _, it := range items {
		switch it {
		case imapbackend.StatusMessages:
			st.Messages = uint32(total)
		case imapbackend.StatusUnseen:
			st.UnseenSeqNum = uint32(unread)
		case imapbackend.StatusUidNext:
			st.UidNext = uint32(uidNext)
		case imapbackend.StatusUidValidity:
			st.UidValidity = uint32(uidValidity)
		case imapbackend.StatusRecent:
			st.Recent = 0
		case "FLAGS":
			st.Flags = []string{imapbackend.SeenFlag, imapbackend.FlaggedFlag, imapbackend.DeletedFlag, imapbackend.AnsweredFlag, imapbackend.DraftFlag}
		}
	}
	return st, nil
}

func (m *Mailbox) SetSubscribed(bool) error { return nil }
func (m *Mailbox) Check() error             { return nil }

// mailsByUID 返回按 uid 升序的全部邮件 (seq, uid, id, flags)。
type mailRow struct {
	seq, uid, id int64
	flags        string
}

func (m *Mailbox) rows() []mailRow {
	rs, err := m.u.be.Store.DB.Query(`SELECT id, msg_uid, flags FROM mails WHERE folder_id=? ORDER BY msg_uid`, m.id)
	if err != nil {
		return nil
	}
	defer rs.Close()
	var out []mailRow
	for rs.Next() {
		var r mailRow
		rs.Scan(&r.id, &r.uid, &r.flags)
		r.seq = int64(len(out) + 1)
		out = append(out, r)
	}
	return out
}

func matchSeq(rows []mailRow, uid bool, set *imapbackend.SeqSet, fn func(mailRow)) {
	for _, r := range rows {
		var n uint32 = uint32(r.seq)
		if uid {
			n = uint32(r.uid)
		}
		if set.Contains(n) {
			fn(r)
		}
	}
}

func (m *Mailbox) ListMessages(uid bool, seqset *imapbackend.SeqSet, items []imapbackend.FetchItem, ch chan<- *imapbackend.Message) error {
	defer close(ch)
	rows := m.rows()
	matchSeq(rows, uid, seqset, func(r mailRow) {
		full, err := m.u.be.Store.GetMail(r.id)
		if err != nil {
			return
		}
		msg, err := fetchMessage(uint32(r.seq), uint32(r.uid), timeOf(full.CreatedAt),
			splitFlags(r.flags), len(full.Raw), full.Raw, items)
		if err != nil {
			return
		}
		ch <- msg
	})
	return nil
}

func timeOf(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		return time.Now()
	}
	return t
}

func splitFlags(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func fetchMessage(seq, uid uint32, date time.Time, flags []string, size int, raw []byte,
	items []imapbackend.FetchItem) (*imapbackend.Message, error) {
	body := bufio.NewReader(bytes.NewReader(raw))
	hdr, err := textproto.ReadHeader(body)
	if err != nil {
		return nil, err
	}
	fetched := imapbackend.NewMessage(seq, items)
	for _, item := range items {
		switch item {
		case imapbackend.FetchEnvelope:
			fetched.Envelope, _ = backendutil.FetchEnvelope(hdr)
		case imapbackend.FetchBody, imapbackend.FetchBodyStructure:
			fetched.BodyStructure, _ = backendutil.FetchBodyStructure(hdr, body, item == imapbackend.FetchBodyStructure)
		case imapbackend.FetchFlags:
			fetched.Flags = flags
		case imapbackend.FetchInternalDate:
			fetched.InternalDate = date
		case imapbackend.FetchRFC822Size:
			fetched.Size = uint32(size)
		case imapbackend.FetchUid:
			fetched.Uid = uid
		default:
			section, err := imapbackend.ParseBodySectionName(item)
			if err != nil {
				return nil, err
			}
			body2 := bufio.NewReader(bytes.NewReader(raw))
			hdr2, err := textproto.ReadHeader(body2)
			if err != nil {
				return nil, err
			}
			l, _ := backendutil.FetchBodySection(hdr2, body2, section)
			fetched.Body[section] = l
		}
	}
	return fetched, nil
}

func (m *Mailbox) SearchMessages(uid bool, criteria *imapbackend.SearchCriteria) ([]uint32, error) {
	var out []uint32
	for _, r := range m.rows() {
		full, err := m.u.be.Store.GetMail(r.id)
		if err != nil {
			continue
		}
		entity, err := message.Read(bytes.NewReader(full.Raw))
		if err != nil {
			continue
		}
		ok, err := backendutil.Match(entity, uint32(r.seq), uint32(r.uid), timeOf(full.CreatedAt), splitFlags(r.flags), criteria)
		if err == nil && ok {
			n := uint32(r.seq)
			if uid {
				n = uint32(r.uid)
			}
			out = append(out, n)
		}
	}
	return out, nil
}

func (m *Mailbox) CreateMessage(flags []string, _ time.Time, body imapbackend.Literal) error {
	raw, err := readLiteral(body)
	if err != nil {
		return err
	}
	if int64(len(raw)) > m.u.be.Config.SMTP.MaxSize*1024*1024 {
		return fmt.Errorf("message too large")
	}
	p := store.ParseFull(&store.MailFull{Raw: raw})
	folderID := m.id
	_, _, err = m.u.be.Store.InsertMail(folderID, p.From, "", p.Subject, raw,
		strings.Join(flags, " "), "", 0, p.TextBody)
	return err
}

func readLiteral(l imapbackend.Literal) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(l); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *Mailbox) UpdateMessagesFlags(uid bool, seqset *imapbackend.SeqSet, op imapbackend.FlagsOp, flags []string) error {
	rows := m.rows()
	matchSeq(rows, uid, seqset, func(r mailRow) {
		newFlags := applyFlags(r.flags, op, flags)
		m.u.be.Store.DB.Exec(`UPDATE mails SET flags=? WHERE id=?`, newFlags, r.id)
	})
	return nil
}

func applyFlags(cur string, op imapbackend.FlagsOp, flags []string) string {
	set := map[string]bool{}
	for _, f := range strings.Fields(cur) {
		set[f] = true
	}
	switch op {
	case imapbackend.SetFlags:
		set = map[string]bool{}
		for _, f := range flags {
			set[f] = true
		}
	case imapbackend.AddFlags:
		for _, f := range flags {
			set[f] = true
		}
	case imapbackend.RemoveFlags:
		for _, f := range flags {
			delete(set, f)
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	return strings.Join(out, " ")
}

func (m *Mailbox) CopyMessages(uid bool, seqset *imapbackend.SeqSet, dest string) error {
	dst, err := m.u.GetMailbox(dest)
	if err != nil {
		return backend.ErrNoSuchMailbox
	}
	dm := dst.(*Mailbox)
	rows := m.rows()
	matchSeq(rows, uid, seqset, func(r mailRow) {
		full, err := m.u.be.Store.GetMail(r.id)
		if err != nil {
			return
		}
		p := store.ParseFull(full)
		m.u.be.Store.InsertMail(dm.id, p.From, "", p.Subject, full.Raw, full.Flags, full.Code, full.SpamScore, p.TextBody)
	})
	return nil
}

func (m *Mailbox) Expunge() error {
	_, err := m.u.be.Store.DB.Exec(`DELETE FROM mails WHERE folder_id=? AND flags LIKE '%\Deleted%'`, m.id)
	return err
}

// Serve 启动 IMAP 明文/STARTTLS（143）与隐式 TLS（993，M6 配证书后启用）。
func Serve(b *Backend, cfg *config.Config) {
	s := imapserver.New(b)
	// 同 SMTP：明文认证保留（内网兼容），993/STARTTLS 可用时客户端应升级
	s.AllowInsecureAuth = true
	if b.Cert != nil {
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*b.Cert}}
	}
	// 端口为空表示关闭该监听（net.Listen("tcp","") 会绑随机端口）
	if cfg.IMAP.Listen != "" {
		go func() {
			ln, err := net.Listen("tcp", cfg.IMAP.Listen)
			if err != nil {
				log.Printf("IMAP 监听失败（跳过）: %v", err)
				return
			}
			log.Printf("IMAP 服务就绪 %s", cfg.IMAP.Listen)
			if err := s.Serve(ln); err != nil {
				log.Printf("IMAP 退出: %v", err)
			}
		}()
	}
	if cfg.IMAP.TLS != "" && b.Cert != nil {
		go func() {
			ln, err := tls.Listen("tcp", cfg.IMAP.TLS, s.TLSConfig)
			if err != nil {
				log.Printf("IMAPS 监听失败（跳过）: %v", err)
				return
			}
			log.Printf("IMAPS 服务就绪 %s", cfg.IMAP.TLS)
			s.Serve(ln)
		}()
	}
}
