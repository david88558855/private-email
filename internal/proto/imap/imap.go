// Package imap IMAP4rev1 服务端（go-imap v1）。
package imap

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/david88558855/private-email/internal/authlimit"
	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/insecureauth"
	"github.com/david88558855/private-email/internal/store"
	imapbackend "github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap/backend/backendutil"
	imapserver "github.com/emersion/go-imap/server"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
)

// defaultFlags 服务端支持的全部系统 flag。
var defaultFlags = []string{
	imapbackend.SeenFlag, imapbackend.FlaggedFlag, imapbackend.DeletedFlag,
	imapbackend.AnsweredFlag, imapbackend.DraftFlag,
}

type Backend struct {
	Store  *store.Store
	Config *config.Config
	Cert   *tls.Certificate
	Policy *insecureauth.Policy // 明文认证来源约束，未注入时按「仅 TLS」处理

	updates chan backend.Update

	mu         sync.Mutex
	lastExists map[int64]int
}

// NewBackend 构造后端并接上「新邮件 → IMAP 推送」的钩子。
func NewBackend(st *store.Store, cfg *config.Config, cert *tls.Certificate,
	policy *insecureauth.Policy) *Backend {
	b := &Backend{
		Store:      st,
		Config:     cfg,
		Cert:       cert,
		Policy:     policy,
		updates:    make(chan backend.Update, 64),
		lastExists: make(map[int64]int),
	}
	// 任何路径写入邮件（SMTP 收信 / HTTP 写信 / IMAP APPEND）都会触发，
	// 这样 IDLE 和 NOOP 才能真正把「有新邮件」推给客户端。
	st.OnInsert = b.NotifyNewMail
	return b
}

// Updates 实现 backend.BackendUpdater：go-imap 会把这里的更新广播给
// 匹配用户名与邮箱名的连接（包括处于 IDLE 的连接）。
func (b *Backend) Updates() <-chan backend.Update { return b.updates }

// NotifyNewMail 邮件落库后推送 EXISTS。
func (b *Backend) NotifyNewMail(folderID int64) {
	addr, name, ok := b.Store.FolderOwner(folderID)
	if !ok {
		return
	}
	total, _ := b.Store.FolderStats(folderID)
	// RECENT 必须是「本次进程内新到」的封数，不是未读数。
	// 之前这里错用了 FolderStats 的第二个返回值（unseen），
	// 结果别的会话读过信之后，推送里的 RECENT 会偏大。
	recent := b.Store.RecentCount(folderID)
	b.mu.Lock()
	if b.lastExists[folderID] == total {
		b.mu.Unlock()
		return
	}
	b.lastExists[folderID] = total
	b.mu.Unlock()
	b.pushExists(addr, name, folderID, total, recent, false)
}

// poll 供 NOOP 使用：数量没变就什么都不发，避免每个 NOOP 都重复 EXISTS。
func (b *Backend) poll(folderID int64) {
	addr, name, ok := b.Store.FolderOwner(folderID)
	if !ok {
		return
	}
	total, _ := b.Store.FolderStats(folderID)
	recent := b.Store.RecentCount(folderID)
	b.mu.Lock()
	same := b.lastExists[folderID] == total
	b.lastExists[folderID] = total
	b.mu.Unlock()
	if same {
		return
	}
	// sync=true：NOOP/CHECK 是命令处理路径，EXISTS 必须排在 tagged OK 前面。
	// 走异步通道时响应有概率落到 tagged OK 之后，客户端会先看到 OK 再收到
	// 一条迟到的 "* n EXISTS"，序号状态就错位了。
	b.pushExists(addr, name, folderID, total, recent, true)
}

func (b *Backend) pushExists(addr, name string, folderID int64, total, recent int, sync bool) {
	var uidNext, uidValidity int64
	b.Store.DB.QueryRow(`SELECT uid_next, uid_validity FROM folders WHERE id=?`, folderID).Scan(&uidNext, &uidValidity)
	st := &imapbackend.MailboxStatus{
		Name:  name,
		Items: map[imapbackend.StatusItem]interface{}{},
		// 只置这几个 key：responses.Select 会输出 EXISTS/RECENT/UIDNEXT/UIDVALIDITY，
		// 不会附带 FLAGS 等可能干扰客户端的行。
		Messages:    uint32(total),
		Recent:      uint32(recent),
		UidNext:     uint32(uidNext),
		UidValidity: uint32(uidValidity),
	}
	st.Items[imapbackend.StatusMessages] = nil
	st.Items[imapbackend.StatusRecent] = nil
	st.Items[imapbackend.StatusUidNext] = nil
	st.Items[imapbackend.StatusUidValidity] = nil
	u := &backend.MailboxUpdate{Update: backend.NewUpdate(addr, name), MailboxStatus: st}
	if sync {
		b.sendSync(u)
	} else {
		b.send(u)
	}
}

// pushFlags 通知其它连接某封邮件的 flags 变了。
func (b *Backend) pushFlags(addr, name string, seq, uid uint32, flags []string) {
	b.pushFlagsSync(addr, name, seq, uid, flags, false)
}

func (b *Backend) pushFlagsSync(addr, name string, seq, uid uint32, flags []string, sync bool) {
	msg := imapbackend.NewMessage(seq, []imapbackend.FetchItem{imapbackend.FetchFlags, imapbackend.FetchUid})
	msg.Flags = flags
	msg.Uid = uid
	u := &backend.MessageUpdate{Update: backend.NewUpdate(addr, name), Message: msg}
	if sync {
		b.sendSync(u)
	} else {
		b.send(u)
	}
}

// pushExpunge 通知其它连接某序号已被删除。
func (b *Backend) pushExpunge(addr, name string, seq uint32) {
	b.sendSync(&backend.ExpungeUpdate{Update: backend.NewUpdate(addr, name), SeqNum: seq})
}

// send 非阻塞投递：更新通道满时丢弃，绝不因为推送把收信主流程卡住。
func (b *Backend) send(u backend.Update) {
	select {
	case b.updates <- u:
	default:
	}
}

// sendSync 投递并等待广播完成，最多等 2 秒。
//
// EXPUNGE / STORE 这类命令必须先让客户端收到 untagged 响应，再回 tagged OK；
// 否则客户端会拿着过期的序号继续操作（Thunderbird 会直接报"邮件不存在"）。
// 客户端卡住时不能无限等，所以有超时兜底。
func (b *Backend) sendSync(u backend.Update) {
	// 必须在投递前把 Done() 的通道建出来。
	// go-imap 的 update.Done() 是懒加载的（`if u.done == nil { u.done = make(...) }`），
	// 不做同步：广播方 listenUpdates 也会调它。两个 goroutine 同时首次调用时
	// 会各建一个 channel，广播方 close 的是它自己那个，我们等的那个永远不会关闭，
	// 于是每条 EXPUNGE/STORE 都要白等满 2 秒（race detector 实测命中）。
	done := u.Done()
	select {
	case b.updates <- u:
	default:
		return
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func (b *Backend) Login(conn *imapbackend.ConnInfo, username, password string) (backend.User, error) {
	// go-imap 的 AllowInsecureAuth 是全局开关，按来源的白名单只能在认证回调里判。
	// LOGIN 与 AUTHENTICATE PLAIN 都走这里，两种命令因此共用同一份约束。
	var isTLS bool
	var remote net.Addr
	if conn != nil {
		isTLS = conn.TLS != nil
		remote = conn.RemoteAddr
	}
	if !b.Policy.Allow(isTLS, remote) {
		return nil, backend.ErrInvalidCredentials
	}
	key := remoteKey(conn)
	// 失败太多次先挡住，别再让它消耗 bcrypt
	if !authlimit.Allow(key) || !authlimit.Allow("acct:"+strings.ToLower(username)) {
		return nil, backend.ErrInvalidCredentials
	}
	mb, ok := b.Store.VerifyMailboxAuth(username, password)
	if !ok {
		authlimit.Fail(key)
		authlimit.Fail("acct:" + strings.ToLower(username))
		return nil, backend.ErrInvalidCredentials
	}
	// 只清账号维度；IP 维度靠窗口自然过期，防止同 IP 用一次成功登录洗掉撞库计数。
	authlimit.Reset("acct:" + strings.ToLower(username))
	if err := b.Store.EnsureFolders(mb.ID); err != nil {
		return nil, err
	}
	return &User{be: b, mb: mb}, nil
}

// remoteKey 取来源 IP 作为限速键。
func remoteKey(ci *imapbackend.ConnInfo) string {
	if ci == nil || ci.RemoteAddr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(ci.RemoteAddr.String())
	if err != nil {
		return ci.RemoteAddr.String()
	}
	return host
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

// systemFolders 内置文件夹：改名/删除会打断 SMTP 投递 / 已发送副本 / 删除进垃圾箱等依赖。
var systemFolders = map[string]bool{"INBOX": true, "Sent": true, "Drafts": true, "Trash": true}

// isSystemFolder 判定内置文件夹。INBOX 在 IMAP 里大小写不敏感，
// 否则 CreateMailbox("inbox") 会另建一个与 INBOX 并存的同名文件夹。
func isSystemFolder(name string) bool {
	if strings.EqualFold(name, "INBOX") {
		return true
	}
	return systemFolders[name]
}

func validFolderName(name string) bool {
	return name != "" && len(name) <= 64 && !strings.ContainsAny(name, "\r\n")
}

func (u *User) CreateMailbox(name string) error {
	if !validFolderName(name) {
		return fmt.Errorf("invalid folder name")
	}
	if isSystemFolder(name) {
		return fmt.Errorf("folder already exists")
	}
	_, err := u.be.Store.DB.Exec(`INSERT INTO folders(mailbox_id, name, uid_validity) VALUES(?,?,?)`,
		u.mb.ID, name, randUint32())
	return err
}

func (u *User) DeleteMailbox(name string) error {
	// 删掉 Sent 会让发信副本静默丢失，删掉 Trash 会让「删除邮件」整体 500
	if isSystemFolder(name) {
		return fmt.Errorf("cannot delete system folder")
	}
	_, err := u.be.Store.DB.Exec(`DELETE FROM folders WHERE mailbox_id=? AND name=?`, u.mb.ID, name)
	return err
}

func (u *User) RenameMailbox(old, new string) error {
	// 重命名 INBOX 会让收信投递找不到目标文件夹，等于整箱失联；Sent/Trash 同理会打断业务路径
	if isSystemFolder(old) || isSystemFolder(new) {
		return fmt.Errorf("cannot rename system folder")
	}
	if !validFolderName(new) {
		return fmt.Errorf("invalid folder name")
	}
	_, err := u.be.Store.DB.Exec(`UPDATE folders SET name=? WHERE mailbox_id=? AND name=?`, new, u.mb.ID, old)
	return err
}

// Poll go-imap 在 NOOP 时调用：有新邮件就推 EXISTS。
func (u *User) Poll() error {
	for _, f := range u.folders() {
		u.be.poll(f)
	}
	return nil
}

func (u *User) folders() []int64 {
	rows, err := u.be.Store.DB.Query(`SELECT id FROM folders WHERE mailbox_id=?`, u.mb.ID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// Close 连接结束时清掉 \Recent，避免下次登录仍把所有邮件标成"新邮件"。
func (u *User) Close() error {
	for _, f := range u.folders() {
		u.be.Store.ClearRecent(f)
	}
	return nil
}

// Logout 连接结束时清 recent（User.Close 在 go-imap 里不一定被调用）。
func (u *User) Logout() error {
	for _, f := range u.folders() {
		u.be.Store.ClearRecent(f)
	}
	return nil
}

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

// Status 返回 SELECT/STATUS 需要的状态。
//
// 两个必须踩准的语义：
//   - Items 必须初始化并填好请求的 key，否则 SELECT 一行 EXISTS 都不会输出，
//     客户端看到的是空邮箱（这就是原来最致命的 bug）。
//   - STATUS UNSEEN 是「未读数量」（Unseen），[UNSEEN n] 是「第一封未读的序号」
//     （UnseenSeqNum），原来把数量塞进序号字段，值是错的。
func (m *Mailbox) Status(items []imapbackend.StatusItem) (*imapbackend.MailboxStatus, error) {
	st := &imapbackend.MailboxStatus{
		Name:           m.name,
		Items:          make(map[imapbackend.StatusItem]interface{}),
		Flags:          defaultFlags,
		PermanentFlags: defaultFlags,
	}
	var total, unread, uidNext, uidValidity int64
	if err := m.u.be.Store.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM mails WHERE folder_id=?),
		(SELECT COUNT(*) FROM mails WHERE folder_id=? AND flags NOT LIKE '%\Seen%'),
		uid_next, uid_validity FROM folders WHERE id=?`,
		m.id, m.id, m.id).Scan(&total, &unread, &uidNext, &uidValidity); err != nil {
		return nil, err
	}
	// 第一封未读的序号（按 msg_uid 排序后的行号）
	var firstUnseen int64
	m.u.be.Store.DB.QueryRow(`SELECT COALESCE(MIN(rn),0) FROM
		(SELECT ROW_NUMBER() OVER (ORDER BY msg_uid) AS rn, flags FROM mails WHERE folder_id=?)
		WHERE flags NOT LIKE '%\Seen%'`, m.id).Scan(&firstUnseen)

	for _, it := range items {
		st.Items[it] = nil
		switch it {
		case imapbackend.StatusMessages:
			st.Messages = uint32(total)
		case imapbackend.StatusUnseen:
			st.Unseen = uint32(unread)
			st.UnseenSeqNum = uint32(firstUnseen)
		case imapbackend.StatusUidNext:
			st.UidNext = uint32(uidNext)
		case imapbackend.StatusUidValidity:
			st.UidValidity = uint32(uidValidity)
		case imapbackend.StatusRecent:
			st.Recent = uint32(m.u.be.Store.RecentCount(m.id))
		}
	}
	return st, nil
}

func (m *Mailbox) SetSubscribed(bool) error { return nil }

// Poll 实现 backend.MailboxPoller：NOOP 时把变化推给客户端。
func (m *Mailbox) Poll() error {
	m.u.be.poll(m.id)
	return nil
}

// Check 对应 CHECK 命令：把「服务端数量变了」告诉客户端。
func (m *Mailbox) Check() error {
	m.u.be.poll(m.id)
	return nil
}

// mailsByUID 返回按 uid 升序的全部邮件 (seq, uid, id, flags)。
type mailRow struct {
	seq, uid, id int64
	size         int
	createdAt    string
	flags        string
}

func (m *Mailbox) rows() ([]mailRow, error) {
	rs, err := m.u.be.Store.DB.Query(`SELECT id, msg_uid, size, created_at, COALESCE(flags,'')
		FROM mails WHERE folder_id=? ORDER BY msg_uid`, m.id)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []mailRow
	for rs.Next() {
		var r mailRow
		if err := rs.Scan(&r.id, &r.uid, &r.size, &r.createdAt, &r.flags); err != nil {
			return nil, err
		}
		r.seq = int64(len(out) + 1)
		out = append(out, r)
	}
	return out, rs.Err()
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

// needsRaw 判断本次 FETCH 是否必须读整封原文。
// 只取 FLAGS/UID/INTERNALDATE/SIZE 时不该把 25MB 的 BLOB 拖进内存——
// 一个带大附件的邮箱，FETCH 1:* (FLAGS) 能吃掉几个 GB。
func needsRaw(items []imapbackend.FetchItem) bool {
	for _, it := range items {
		switch it {
		case imapbackend.FetchFlags, imapbackend.FetchUid,
			imapbackend.FetchInternalDate, imapbackend.FetchRFC822Size:
		default:
			return true
		}
	}
	return false
}

// needsSeen 判断本次 FETCH 是否属于「取回即已读」的 BODY[...]（非 PEEK）。
// RFC 3501 §6.4.5：BODY[] 不带 PEEK 时必须隐式置 \Seen。
func needsSeen(items []imapbackend.FetchItem) bool {
	for _, it := range items {
		if it == imapbackend.FetchRFC822 {
			return true
		}
		sec, err := imapbackend.ParseBodySectionName(it)
		if err == nil && !sec.Peek {
			return true
		}
	}
	return false
}

func (m *Mailbox) ListMessages(uid bool, seqset *imapbackend.SeqSet, items []imapbackend.FetchItem, ch chan<- *imapbackend.Message) error {
	defer close(ch)
	rows, err := m.rows()
	if err != nil {
		return err
	}
	rawNeeded := needsRaw(items)
	markSeen := needsSeen(items)
	var firstErr error
	matchSeq(rows, uid, seqset, func(r mailRow) {
		var raw []byte
		var size int
		var createdAt string
		if rawNeeded {
			full, err := m.u.be.Store.GetMail(r.id)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			raw, size, createdAt = full.Raw, full.Size, full.CreatedAt
		} else {
			meta, err := m.u.be.Store.GetMailMeta(r.id)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			size, createdAt = meta.Size, meta.CreatedAt
		}
		flags := splitFlags(r.flags)
		if markSeen && !hasFlag(flags, imapbackend.SeenFlag) {
			flags = append(flags, imapbackend.SeenFlag)
			if err := m.u.be.Store.SetFlags(r.id, strings.Join(flags, " ")); err != nil {
				log.Printf("IMAP 置已读失败 mail=%d: %v", r.id, err)
			} else if addr, name, ok := m.u.be.Store.FolderOwner(m.id); ok {
				// 多端一致性：把这个变化推给同一邮箱的其它连接
				m.u.be.pushFlags(addr, name, uint32(r.seq), uint32(r.uid), flags)
			}
		}
		if m.u.be.Store.IsRecent(r.id) {
			flags = append(flags, imapbackend.RecentFlag)
		}
		msg, err := fetchMessage(uint32(r.seq), uint32(r.uid), timeOf(createdAt), flags, size, raw, items)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		ch <- msg
	})
	return firstErr
}

// timeOf 解析数据库时间。
//
// 坑：mails.created_at 声明为 DATETIME，modernc 驱动会把它还原成 time.Time，
// database/sql 再转成字符串时用的是 RFC3339（2026-11-04T10:42:08Z），
// 不是 SQLite 里存的 "2026-11-04 10:42:08"。只按后者解析会永远失败，
// 结果 INTERNALDATE 一直返回"现在"。
func timeOf(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999-07:00",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Local()
		}
	}
	return time.Now()
}

func splitFlags(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if strings.EqualFold(f, want) {
			return true
		}
	}
	return false
}

func fetchMessage(seq, uid uint32, date time.Time, flags []string, size int, raw []byte,
	items []imapbackend.FetchItem) (*imapbackend.Message, error) {
	fetched := imapbackend.NewMessage(seq, items)
	// 没有原文时只可能是元数据类请求，不需要解析头部
	if raw != nil {
		body := bufio.NewReader(bytes.NewReader(raw))
		hdr, err := textproto.ReadHeader(body)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			switch item {
			case imapbackend.FetchEnvelope:
				fetched.Envelope, _ = backendutil.FetchEnvelope(hdr)
			case imapbackend.FetchBody, imapbackend.FetchBodyStructure:
				fetched.BodyStructure, _ = backendutil.FetchBodyStructure(hdr, body, item == imapbackend.FetchBodyStructure)
			case imapbackend.FetchFlags, imapbackend.FetchInternalDate, imapbackend.FetchRFC822Size, imapbackend.FetchUid:
				// 下面统一填
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
				l, err := backendutil.FetchBodySection(hdr2, body2, section)
				if err != nil {
					return nil, err
				}
				fetched.Body[section] = l
			}
		}
	} else {
		for _, item := range items {
			switch item {
			case imapbackend.FetchEnvelope, imapbackend.FetchBody, imapbackend.FetchBodyStructure:
				return nil, errors.New("fetch: message body requested without raw data")
			}
		}
	}
	for _, item := range items {
		switch item {
		case imapbackend.FetchFlags:
			fetched.Flags = flags
		case imapbackend.FetchInternalDate:
			fetched.InternalDate = date
		case imapbackend.FetchRFC822Size:
			fetched.Size = uint32(size)
		case imapbackend.FetchUid:
			fetched.Uid = uid
		}
	}
	return fetched, nil
}

// simpleCriteria 判断能否不解析原文、只用元数据完成匹配。
func simpleCriteria(c *imapbackend.SearchCriteria) bool {
	return len(c.Header) == 0 && len(c.Body) == 0 && len(c.Text) == 0 &&
		len(c.Not) == 0 && len(c.Or) == 0 &&
		c.SentSince.IsZero() && c.SentBefore.IsZero()
}

// matchSimple 按序号/UID/flag/日期/大小匹配（不碰正文）。
func matchSimple(c *imapbackend.SearchCriteria, seq, uid uint32, date time.Time, size int, flags []string) bool {
	if c.SeqNum != nil && !c.SeqNum.Contains(seq) {
		return false
	}
	if c.Uid != nil && !c.Uid.Contains(uid) {
		return false
	}
	for _, f := range c.WithFlags {
		if !hasFlag(flags, f) {
			return false
		}
	}
	for _, f := range c.WithoutFlags {
		if hasFlag(flags, f) {
			return false
		}
	}
	if c.Larger > 0 && uint32(size) <= c.Larger {
		return false
	}
	if c.Smaller > 0 && uint32(size) >= c.Smaller {
		return false
	}
	if !c.Since.IsZero() && date.Before(c.Since) {
		return false
	}
	if !c.Before.IsZero() && !date.Before(c.Before) {
		return false
	}
	return true
}

func (m *Mailbox) SearchMessages(uid bool, criteria *imapbackend.SearchCriteria) ([]uint32, error) {
	rows, err := m.rows()
	if err != nil {
		return nil, err
	}
	simple := simpleCriteria(criteria)
	var out []uint32
	for _, r := range rows {
		seq, uidNum := uint32(r.seq), uint32(r.uid)
		flags := splitFlags(r.flags)
		date := timeOf(r.createdAt)
		if simple {
			if matchSimple(criteria, seq, uidNum, date, r.size, flags) {
				if uid {
					out = append(out, uidNum)
				} else {
					out = append(out, seq)
				}
			}
			continue
		}
		// 复杂条件（正文/头部/OR）才需要解析原文
		full, err := m.u.be.Store.GetMail(r.id)
		if err != nil {
			continue
		}
		entity, err := message.Read(bytes.NewReader(full.Raw))
		if err != nil {
			continue
		}
		ok, err := backendutil.Match(entity, seq, uidNum, date, flags, criteria)
		if err == nil && ok {
			if uid {
				out = append(out, uidNum)
			} else {
				out = append(out, seq)
			}
		}
	}
	return out, nil
}

// CreateMessage 处理 APPEND：保留收件人与 INTERNALDATE。
func (m *Mailbox) CreateMessage(flags []string, date time.Time, body imapbackend.Literal) error {
	raw, err := readLiteral(body)
	if err != nil {
		return err
	}
	if int64(len(raw)) > m.u.be.Config.SMTP.MaxSize*1024*1024 {
		return backend.ErrTooBig
	}
	p := store.ParseFull(&store.MailFull{Raw: raw})
	_, _, err = m.u.be.Store.InsertMailAt(m.id, p.From, p.To, p.Subject, raw,
		strings.Join(flags, " "), "", 0, p.TextBody, date)
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
	rows, err := m.rows()
	if err != nil {
		return err
	}
	addr, name, _ := m.u.be.Store.FolderOwner(m.id)
	var firstErr error
	matchSeq(rows, uid, seqset, func(r mailRow) {
		newFlags := applyFlags(r.flags, op, flags)
		if newFlags == r.flags {
			return
		}
		if err := m.u.be.Store.SetFlags(r.id, newFlags); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		m.u.be.pushFlagsSync(addr, name, uint32(r.seq), uint32(r.uid), splitFlags(newFlags), true)
	})
	return firstErr
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
	sort.Strings(out)
	return strings.Join(out, " ")
}

// CopyMessages 复制邮件：收件人、flags 一并保留（原来 recipient 传空，Web 端详情页是空白）。
func (m *Mailbox) CopyMessages(uid bool, seqset *imapbackend.SeqSet, dest string) error {
	dst, err := m.u.GetMailbox(dest)
	if err != nil {
		return backend.ErrNoSuchMailbox
	}
	dm := dst.(*Mailbox)
	rows, err := m.rows()
	if err != nil {
		return err
	}
	var firstErr error
	matchSeq(rows, uid, seqset, func(r mailRow) {
		full, err := m.u.be.Store.GetMail(r.id)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		p := store.ParseFull(full)
		if _, _, err := m.u.be.Store.InsertMail(dm.id, p.From, p.To, p.Subject, full.Raw,
			full.Flags, full.Code, full.SpamScore, p.TextBody); err != nil && firstErr == nil {
			firstErr = err
		}
	})
	return firstErr
}

// Expunge 物理删除 \Deleted 邮件，并把 EXPUNGE 通知其它连接（从大到小发，否则序号会错位）。
func (m *Mailbox) Expunge() error {
	rows, err := m.rows()
	if err != nil {
		return err
	}
	addr, name, _ := m.u.be.Store.FolderOwner(m.id)
	var seqs []uint32
	for _, r := range rows {
		if hasFlag(splitFlags(r.flags), imapbackend.DeletedFlag) {
			seqs = append(seqs, uint32(r.seq))
		}
	}
	if _, err := m.u.be.Store.Expunge(m.id); err != nil {
		return err
	}
	m.u.be.mu.Lock()
	m.u.be.lastExists[m.id] = len(rows) - len(seqs)
	m.u.be.mu.Unlock()
	for i := len(seqs) - 1; i >= 0; i-- {
		m.u.be.pushExpunge(addr, name, seqs[i])
	}
	return nil
}

// ---------- 监听 ----------

// limitListener 限制并发连接数，防止一个扫描器把 fd 和 goroutine 耗光。
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(ln net.Listener, n int) net.Listener {
	if n <= 0 {
		return ln
	}
	return &limitListener{Listener: ln, sem: make(chan struct{}, n)}
}

func (l *limitListener) Accept() (net.Conn, error) {
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

// tlsLimitListener 在 TLS 之下加连接上限。
//
// 直接包在 tls.Listener 外面会破坏 `c.(*tls.Conn)` 判断，所以反过来：
// 先限流 TCP，再自己 tls.Server()，返回的仍然是 *tls.Conn；而 Close 会
// 从 *tls.Conn 一路调到 limitConn，信号量正常释放。
type tlsLimitListener struct {
	net.Listener
	sem chan struct{}
	cfg *tls.Config
}

func newTLSLimitListener(ln net.Listener, n int, cfg *tls.Config) net.Listener {
	if n <= 0 {
		return tls.NewListener(ln, cfg)
	}
	return &tlsLimitListener{Listener: ln, sem: make(chan struct{}, n), cfg: cfg}
}

func (l *tlsLimitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return tls.Server(&limitConn{Conn: c, release: func() { <-l.sem }}, l.cfg), nil
}

// mergedListener 把明文和 TLS 两个监听合成一个，保证 s.Serve 只调用一次。
// 调用两次会让 go-imap 启动两个 listenUpdates 消费者，同一条更新被广播两遍。
type mergedListener struct {
	lns    []net.Listener
	conns  chan net.Conn
	errs   chan error
	addr   net.Addr
	once   sync.Once
	closed chan struct{}
}

func mergeListeners(lns ...net.Listener) net.Listener {
	m := &mergedListener{
		lns:    lns,
		conns:  make(chan net.Conn),
		errs:   make(chan error, len(lns)),
		addr:   lns[0].Addr(),
		closed: make(chan struct{}),
	}
	for _, ln := range lns {
		go func(ln net.Listener) {
			for {
				c, err := ln.Accept()
				if err != nil {
					select {
					case m.errs <- err:
					case <-m.closed:
					}
					return
				}
				select {
				case m.conns <- c:
				case <-m.closed:
					c.Close()
					return
				}
			}
		}(ln)
	}
	return m
}

// Accept 只在全部监听都失效后才返回错误。
// 以前任一端（比如 143）出一次 Accept 错误就把 Serve 顶掉，993 会跟着一起死。
func (m *mergedListener) Accept() (net.Conn, error) {
	failed := 0
	for {
		select {
		case c := <-m.conns:
			return c, nil
		case err := <-m.errs:
			failed++
			if failed >= len(m.lns) {
				return nil, err
			}
			log.Printf("IMAP 某个监听已停止（其余继续服务）: %v", err)
		case <-m.closed:
			return nil, net.ErrClosed
		}
	}
}

func (m *mergedListener) Close() error {
	m.once.Do(func() {
		close(m.closed)
		for _, ln := range m.lns {
			ln.Close()
		}
	})
	return nil
}

func (m *mergedListener) Addr() net.Addr { return m.addr }

// Serve 启动 IMAP 明文/STARTTLS（143）与隐式 TLS（993）。
func Serve(b *Backend, cfg *config.Config) {
	s := imapserver.New(b)
	// 总开关决定 CAPABILITY 是否公布 AUTH=PLAIN；白名单由 Backend.Login 兜底。
	// go-imap 已内置 sasl.Plain 服务端（AUTHENTICATE PLAIN），无需重复实现。
	s.AllowInsecureAuth = cfg.Security.AllowInsecureAuth
	s.AutoLogout = time.Duration(cfg.Security.IdleTimeoutMin) * time.Minute
	s.MaxLiteralSize = uint32(cfg.SMTP.MaxSize * 1024 * 1024)
	if b.Cert != nil {
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*b.Cert}}
	}

	var lns []net.Listener
	if cfg.IMAP.Listen != "" {
		ln, err := net.Listen("tcp", cfg.IMAP.Listen)
		if err != nil {
			log.Printf("IMAP 监听失败（跳过）: %v", err)
		} else {
			log.Printf("IMAP 服务就绪 %s", cfg.IMAP.Listen)
			lns = append(lns, newLimitListener(ln, cfg.Security.MaxConns))
		}
	}
	if cfg.IMAP.TLS != "" && b.Cert != nil {
		ln, err := net.Listen("tcp", cfg.IMAP.TLS)
		if err != nil {
			log.Printf("IMAPS 监听失败（跳过）: %v", err)
		} else {
			log.Printf("IMAPS 服务就绪 %s", cfg.IMAP.TLS)
			// 注意：不能在外层包 limitListener。go-imap 用 `c.(*tls.Conn)`
			// 判断连接是否已加密，包一层自定义 net.Conn 会让它认不出来，
			// 993 上的 LOGIN 会被当成明文认证直接拒绝。
			// newTLSLimitListener 把限流放在 TLS 里面，外层仍是 *tls.Conn。
			lns = append(lns, newTLSLimitListener(ln, cfg.Security.MaxConns, s.TLSConfig))
		}
	}
	if len(lns) == 0 {
		return
	}
	ln := lns[0]
	if len(lns) > 1 {
		ln = mergeListeners(lns...)
	}
	go func() {
		if err := s.Serve(ln); err != nil {
			log.Printf("IMAP 退出: %v", err)
		}
	}()
}
