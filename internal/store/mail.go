// Package store SQLite 单库读写层（D1=B：元数据 + 邮件 BLOB 同库）。
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Store 封装全部持久化操作。
type Store struct {
	DB *sql.DB
	// OnInsert 在邮件成功落库后回调（用于 IMAP 的 IDLE/NOOP 推送）。
	// 回调在事务提交之后、无锁状态下执行，允许为空。
	OnInsert func(folderID int64)

	recentMu sync.Mutex
	recent   map[int64]int64 // mailID -> folderID
}

// NewFolders 默认文件夹。
var NewFolders = []string{"INBOX", "Sent", "Drafts", "Trash"}

func randUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:]) | 1
}

// EnsureFolders 建默认文件夹（幂等）。
func (s *Store) EnsureFolders(mailboxID int64) error {
	for _, name := range NewFolders {
		if _, err := s.DB.Exec(`INSERT OR IGNORE INTO folders(mailbox_id, name, uid_validity) VALUES(?,?,?)`,
			mailboxID, name, randUint32()); err != nil {
			return err
		}
	}
	return nil
}

// FolderID 按名取文件夹。
func (s *Store) FolderID(mailboxID int64, name string) (int64, error) {
	var id int64
	err := s.DB.QueryRow(`SELECT id FROM folders WHERE mailbox_id=? AND name=?`, mailboxID, name).Scan(&id)
	return id, err
}

// InsertMail 事务写入邮件（uid 分配 + FTS 同步原子完成）。
func (s *Store) InsertMail(folderID int64, sender, recipient, subject string,
	raw []byte, flags, code string, spamScore float64, textBody string) (int64, int64, error) {
	return s.insertMail(folderID, sender, recipient, subject, raw, flags, code, spamScore, textBody, time.Time{})
}

// InsertMailAt 同 InsertMail，但把 INTERNALDATE 设为指定时间（IMAP APPEND 用）。
//
// 时间必须和插入在同一个事务里写：以前是先插再 UPDATE，中间会有一小段时间
// 这封邮件的 INTERNALDATE 是"现在"，并且插入通知已经发出去了，客户端可能
// 已经拿到错误的日期。
func (s *Store) InsertMailAt(folderID int64, sender, recipient, subject string,
	raw []byte, flags, code string, spamScore float64, textBody string, at time.Time) (int64, int64, error) {
	return s.insertMail(folderID, sender, recipient, subject, raw, flags, code, spamScore, textBody, at)
}

func (s *Store) insertMail(folderID int64, sender, recipient, subject string,
	raw []byte, flags, code string, spamScore float64, textBody string, at time.Time) (int64, int64, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	var uidNext int64
	if err := tx.QueryRow(`SELECT uid_next FROM folders WHERE id=?`, folderID).Scan(&uidNext); err != nil {
		return 0, 0, err
	}
	res, err := tx.Exec(`INSERT INTO mails(folder_id, msg_uid, sender, recipient, subject, flags, size, raw_blob, code, spam_score, body_text)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		folderID, uidNext, sender, recipient, subject, flags, len(raw), raw, code, spamScore, textBody)
	if err != nil {
		return 0, 0, err
	}
	mailID, _ := res.LastInsertId()
	if _, err := tx.Exec(`UPDATE folders SET uid_next=uid_next+1 WHERE id=?`, folderID); err != nil {
		return 0, 0, err
	}
	if !at.IsZero() {
		if _, err := tx.Exec(`UPDATE mails SET created_at=? WHERE id=?`,
			at.UTC().Format("2006-01-02 15:04:05"), mailID); err != nil {
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	s.markRecent(mailID, folderID)
	if s.OnInsert != nil {
		s.OnInsert(folderID)
	}
	return mailID, uidNext, nil
}

// ---------- 近新邮件（IMAP \Recent） ----------

func (s *Store) markRecent(mailID, folderID int64) {
	s.recentMu.Lock()
	if s.recent == nil {
		s.recent = make(map[int64]int64)
	}
	// 上限保护：极端情况下（长期不 select）不让 map 无限增长
	if len(s.recent) > 10000 {
		s.recent = make(map[int64]int64)
	}
	s.recent[mailID] = folderID
	s.recentMu.Unlock()
}

// RecentCount 返回该文件夹中「本次进程内新到」的邮件数。
func (s *Store) RecentCount(folderID int64) int {
	s.recentMu.Lock()
	defer s.recentMu.Unlock()
	n := 0
	for _, f := range s.recent {
		if f == folderID {
			n++
		}
	}
	return n
}

// IsRecent 判断某封邮件是否带 \Recent。
func (s *Store) IsRecent(mailID int64) bool {
	s.recentMu.Lock()
	defer s.recentMu.Unlock()
	_, ok := s.recent[mailID]
	return ok
}

// ClearRecent 在邮箱被选中后清除该文件夹的 recent 标记（RFC：一个会话消费一次）。
func (s *Store) ClearRecent(folderID int64) {
	s.recentMu.Lock()
	defer s.recentMu.Unlock()
	for id, f := range s.recent {
		if f == folderID {
			delete(s.recent, id)
		}
	}
}

// MailSummary 列表项。
type MailSummary struct {
	ID        int64   `json:"id"`
	UID       int64   `json:"uid"`
	Sender    string  `json:"sender"`
	Subject   string  `json:"subject"`
	Flags     string  `json:"flags"`
	Size      int     `json:"size"`
	Code      string  `json:"code"`
	SpamScore float64 `json:"spam_score"`
	CreatedAt string  `json:"created_at"`
}

// ListMails 列表（q 走 FTS5 全文检索）。
func (s *Store) ListMails(folderID int64, q string, limit, offset int) ([]MailSummary, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	base := `SELECT m.id, m.msg_uid, m.sender, m.subject, m.flags, m.size, COALESCE(m.code,''), m.spam_score, m.created_at FROM mails m `
	q = strings.TrimSpace(q)
	terms := searchTerms(q)
	// 只搜到特殊符号时视为无匹配，避免拼出非法 FTS5 表达式导致 500
	if q != "" && len(terms) == 0 {
		return []MailSummary{}, 0, nil
	}

	var rows *sql.Rows
	var err error
	var total int
	if len(terms) == 0 {
		base += `WHERE m.folder_id=? `
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM mails WHERE folder_id=?`, folderID).Scan(&total); err != nil {
			return nil, 0, err
		}
		rows, err = s.DB.Query(base+`ORDER BY m.id DESC LIMIT ? OFFSET ?`, folderID, limit, offset)
	} else if needLike(terms) {
		// trigram 至少要 3 个字符；中文两字词（"验证"、"邮箱"）走 LIKE 回退
		conds := make([]string, 0, len(terms))
		args := []any{folderID}
		for _, t := range terms {
			conds = append(conds, `(m.subject LIKE ? ESCAPE '\' OR m.sender LIKE ? ESCAPE '\' OR m.body_text LIKE ? ESCAPE '\')`)
			p := "%" + escapeLike(t) + "%"
			args = append(args, p, p, p)
		}
		where := "WHERE m.folder_id=? AND " + strings.Join(conds, " AND ")
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM mails m `+where, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		rows, err = s.DB.Query(base+where+` ORDER BY m.id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	} else {
		fq := ftsExpr(terms)
		base += `JOIN mails_fts f ON f.rowid = m.id AND mails_fts MATCH ? WHERE m.folder_id=? `
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM mails m JOIN mails_fts f ON f.rowid=m.id AND mails_fts MATCH ? WHERE m.folder_id=?`, fq, folderID).Scan(&total); err != nil {
			return nil, 0, err
		}
		rows, err = s.DB.Query(base+`ORDER BY m.id DESC LIMIT ? OFFSET ?`, fq, folderID, limit, offset)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []MailSummary{}
	for rows.Next() {
		var m MailSummary
		if err := rows.Scan(&m.ID, &m.UID, &m.Sender, &m.Subject, &m.Flags, &m.Size, &m.Code, &m.SpamScore, &m.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	return out, total, rows.Err()
}

// ListMailsAsc POP3 用：按 UID 升序返回全部邮件（老邮件在前）。
// 不设 500 封上限——超过 500 封的邮箱，老邮件在客户端会整批消失。
func (s *Store) ListMailsAsc(folderID int64) ([]MailSummary, error) {
	rows, err := s.DB.Query(`SELECT id, msg_uid, sender, subject, flags, size, COALESCE(code,''), spam_score, created_at
		FROM mails WHERE folder_id=? ORDER BY msg_uid ASC`, folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MailSummary{}
	for rows.Next() {
		var m MailSummary
		if err := rows.Scan(&m.ID, &m.UID, &m.Sender, &m.Subject, &m.Flags, &m.Size, &m.Code, &m.SpamScore, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// searchTerms 拆分并清洗用户输入。FTS5 的语法符号（引号、星号、括号、冒号、尖号）
// 在引号内也可能被解释，一律剔除；全部被剔除则返回空，由调用方当作「无匹配」。
func searchTerms(q string) []string {
	words := strings.Fields(q)
	out := make([]string, 0, len(words))
	for _, w := range words {
		w = strings.Map(func(r rune) rune {
			switch r {
			case '"', '*', '(', ')', ':', '^', '+', '-':
				return -1
			}
			return r
		}, w)
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}

// needLike 任一 token 少于 3 个字符时，trigram 索引无法命中，整条查询改用 LIKE。
func needLike(terms []string) bool {
	for _, t := range terms {
		if utf8.RuneCountInString(t) < 3 {
			return true
		}
	}
	return false
}

// ftsExpr 生成 trigram 可用的 MATCH 表达式：逐词加引号，AND 连接。
// trigram 不支持前缀 `*` 语法（那是 unicode61 的玩法）。
func ftsExpr(terms []string) string {
	parts := make([]string, 0, len(terms))
	for _, t := range terms {
		parts = append(parts, `"`+strings.ReplaceAll(t, `"`, `""`)+`"`)
	}
	return strings.Join(parts, " AND ")
}

// escapeLike 转义 LIKE 通配符，避免用户输入的 % _ 变成通配。
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

// MailFull 详情（含 BLOB）。
type MailFull struct {
	MailSummary
	To     string          `json:"to"`
	Text   string          `json:"text_body"`
	HTML   string          `json:"html_body"`
	Raw    []byte          `json:"-"`
	Attach []AttachmentRow `json:"attachments"`
}

// AttachmentRow 附件行。
type AttachmentRow struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
}

// MailMeta 不含 BLOB 的邮件元数据（IMAP FETCH FLAGS/UID 用）。
type MailMeta struct {
	ID        int64
	UID       int64
	Flags     string
	Size      int
	CreatedAt string
}

// GetMailMeta 只读元数据，避免为了拿 flags 把 25MB 的 raw_blob 拖进内存。
func (s *Store) GetMailMeta(id int64) (*MailMeta, error) {
	m := &MailMeta{}
	err := s.DB.QueryRow(`SELECT id, msg_uid, flags, size, created_at FROM mails WHERE id=?`, id).
		Scan(&m.ID, &m.UID, &m.Flags, &m.Size, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// GetMail 读取详情。
func (s *Store) GetMail(id int64) (*MailFull, error) {
	m := &MailFull{}
	err := s.DB.QueryRow(`SELECT id, msg_uid, sender, recipient, subject, flags, size, COALESCE(code,''),
		spam_score, created_at, raw_blob FROM mails WHERE id=?`, id).
		Scan(&m.ID, &m.UID, &m.Sender, &m.To, &m.Subject, &m.Flags, &m.Size, &m.Code, &m.SpamScore, &m.CreatedAt, &m.Raw)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// GetMailRaw 只取原始报文（IMAP BODY[] 用）。
func (s *Store) GetMailRaw(id int64) ([]byte, error) {
	var raw []byte
	err := s.DB.QueryRow(`SELECT raw_blob FROM mails WHERE id=?`, id).Scan(&raw)
	return raw, err
}

// MarkSeen 置已读。
func (s *Store) MarkSeen(id int64) error {
	_, err := s.DB.Exec(`UPDATE mails SET flags = CASE WHEN flags LIKE '%\Seen%' THEN flags ELSE flags || ' \Seen' END WHERE id=?`, id)
	return err
}

// SetFlags 直接写入 flags 串（IMAP STORE 用）。
func (s *Store) SetFlags(id int64, flags string) error {
	_, err := s.DB.Exec(`UPDATE mails SET flags=? WHERE id=?`, flags, id)
	return err
}

// DeleteMail 移入垃圾箱（已在垃圾箱则真删）。
func (s *Store) DeleteMail(id int64) error {
	var folderID int64
	if err := s.DB.QueryRow(`SELECT folder_id FROM mails WHERE id=?`, id).Scan(&folderID); err != nil {
		return err
	}
	var mailboxID int64
	var name string
	if err := s.DB.QueryRow(`SELECT mailbox_id, name FROM folders WHERE id=?`, folderID).Scan(&mailboxID, &name); err != nil {
		return err
	}
	if name == "Trash" {
		_, err := s.DB.Exec(`DELETE FROM mails WHERE id=?`, id)
		return err
	}
	trashID, err := s.FolderID(mailboxID, "Trash")
	if err != nil {
		// 早期版本允许 IMAP 删掉 Trash，老库里可能已缺失：补建后重试，避免删除功能整体不可用
		if e := s.EnsureFolders(mailboxID); e != nil {
			return fmt.Errorf("trash folder missing: %w", err)
		}
		if trashID, err = s.FolderID(mailboxID, "Trash"); err != nil {
			return fmt.Errorf("trash folder missing: %w", err)
		}
	}
	return s.moveMail(id, trashID)
}

// moveMail 把邮件移到目标文件夹，并在目标文件夹内重新分配 UID。
// msg_uid 只保证「同一文件夹内唯一」：各文件夹的 uid_next 都从 1 开始，
// 直接沿用原 UID 会撞上 UNIQUE(folder_id,msg_uid)，表现为删除失败、返回 500。
//
// 顺带清掉 \Deleted：IMAP 里标了删除又用 Web 删除，进 Trash 后仍带 \Deleted，
// 下一次 EXPUNGE 会把它直接物理删掉，用户根本没机会恢复。
func (s *Store) moveMail(id, dstFolderID int64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var uidNext int64
	if err := tx.QueryRow(`SELECT uid_next FROM folders WHERE id=?`, dstFolderID).Scan(&uidNext); err != nil {
		return err
	}
	var flags string
	if err := tx.QueryRow(`SELECT COALESCE(flags,'') FROM mails WHERE id=?`, id).Scan(&flags); err != nil {
		return err
	}
	flags = removeFlag(flags, `\Deleted`)
	if _, err := tx.Exec(`UPDATE mails SET folder_id=?, msg_uid=?, flags=? WHERE id=?`, dstFolderID, uidNext, flags, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE folders SET uid_next=uid_next+1 WHERE id=?`, dstFolderID); err != nil {
		return err
	}
	return tx.Commit()
}

// removeFlag 从空格分隔的 flags 串里去掉指定 flag。
func removeFlag(flags, drop string) string {
	out := make([]string, 0, 6)
	for _, f := range strings.Fields(flags) {
		if !strings.EqualFold(f, drop) {
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

// Expunge 物理删除文件夹内标记了 \Deleted 的邮件，返回删除条数。
func (s *Store) Expunge(folderID int64) (int64, error) {
	res, err := s.DB.Exec(`DELETE FROM mails WHERE folder_id=? AND flags LIKE '%\Deleted%'`, folderID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// OwnsMail 校验邮件归属（folder → mailbox → user）。
func (s *Store) OwnsMail(mailID, userID int64) bool {
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM mails m JOIN folders f ON f.id=m.folder_id
		JOIN mailboxes mb ON mb.id=f.mailbox_id WHERE m.id=? AND mb.user_id=?`, mailID, userID).Scan(&n)
	return n > 0
}

// MailQueue 入站转发队列行（M4 worker 消费）。
func (s *Store) EnqueueForward(mailboxID int64, from, to string, raw []byte) {
	if _, err := s.DB.Exec(`INSERT INTO mail_queue(mailbox_id, from_addr, to_addr, raw_blob, next_try_at) VALUES(?,?,?,?,datetime('now'))`,
		mailboxID, from, to, raw); err != nil {
		// 主邮件已落库，转发副本入队失败若不留痕，用户会以为转发成功。
		log.Printf("转发入队失败 target=%s: %v", to, err)
	}
}

// EnqueueForwards 按转发规则把邮件投递入队（无规则则什么都不做）。
func (s *Store) EnqueueForwards(mailboxID int64, from string, raw []byte) {
	rows, err := s.DB.Query(`SELECT target FROM forward_rules WHERE mailbox_id=? AND is_active=1`, mailboxID)
	if err != nil {
		log.Printf("转发规则查询失败 mailbox=%d: %v", mailboxID, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			log.Printf("转发规则扫描失败 mailbox=%d: %v", mailboxID, err)
			continue
		}
		if target != "" {
			s.EnqueueForward(mailboxID, from, target, raw)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("转发规则迭代失败 mailbox=%d: %v", mailboxID, err)
	}
}

// InsertIntoInbox 把邮件写入该邮箱的 INBOX，不触发转发规则。
// INBOX 缺失（新用户未初始化 / 老库）时自动补建，避免收信被静默丢弃。
func (s *Store) InsertIntoInbox(mailboxID int64, sender, recipient, subject string,
	raw []byte, textBody string) error {
	folderID, err := s.FolderID(mailboxID, "INBOX")
	if err != nil {
		if e := s.EnsureFolders(mailboxID); e != nil {
			return err
		}
		if folderID, err = s.FolderID(mailboxID, "INBOX"); err != nil {
			return err
		}
	}
	_, _, err = s.InsertMail(folderID, sender, recipient, subject, raw, "", "", 0, textBody)
	return err
}

// DeliverLocal 直投本机邮箱的 INBOX（同域收发不走出站，避免依赖公网 DNS/MX），并执行其转发规则。
func (s *Store) DeliverLocal(mailboxID int64, sender, recipient, subject string,
	raw []byte, textBody string) error {
	if err := s.InsertIntoInbox(mailboxID, sender, recipient, subject, raw, textBody); err != nil {
		return err
	}
	s.EnqueueForwards(mailboxID, sender, raw)
	return nil
}

// MailboxStateByAddress 按地址查邮箱（不区分是否启用），用于区分「不存在」与「已暂停收发」。
func (s *Store) MailboxStateByAddress(addr string) (id int64, active bool, found bool) {
	var a int
	if err := s.DB.QueryRow(`SELECT id, is_active FROM mailboxes WHERE lower(address)=lower(?)`, addr).
		Scan(&id, &a); err != nil {
		return 0, false, false
	}
	return id, a == 1, true
}

// FolderOwner 返回文件夹所属邮箱地址与文件夹名（IMAP 推送定位用）。
func (s *Store) FolderOwner(folderID int64) (address, name string, ok bool) {
	err := s.DB.QueryRow(`SELECT mb.address, f.name FROM folders f JOIN mailboxes mb ON mb.id=f.mailbox_id WHERE f.id=?`, folderID).
		Scan(&address, &name)
	return address, name, err == nil
}

// FolderStats 返回文件夹的邮件数与未读数。
func (s *Store) FolderStats(folderID int64) (total, unseen int) {
	s.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM mails WHERE folder_id=?),
		(SELECT COUNT(*) FROM mails WHERE folder_id=? AND flags NOT LIKE '%\Seen%')`,
		folderID, folderID).Scan(&total, &unseen)
	return
}

// LocalDelivery 一封待投递到本机邮箱的邮件。
type LocalDelivery struct {
	MailboxID int64
	Address   string
	Subject   string
	Code      string
	Score     float64
	TextBody  string
}

// DeliverInbound 单事务完成「所有本地收件人入库 + 所有外域收件人入队」。
//
// 原来的做法是在收件人循环里逐个写库，任一失败就返回 451：前面写成功的
// 收件人不会回滚，发信方按 451 重发整封，于是前面的人收到两封。
// 现在要么全部成功，要么一封都不落库。
func (s *Store) DeliverInbound(from string, raw []byte, locals []LocalDelivery,
	queueMailboxID int64, externals []string) error {
	// INBOX 缺失的老库先补齐（在事务外做，避免 DDL 与写事务交叉）
	for _, l := range locals {
		if _, err := s.FolderID(l.MailboxID, "INBOX"); err != nil {
			if err := s.EnsureFolders(l.MailboxID); err != nil {
				return err
			}
		}
	}

	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	type queued struct {
		mailID   int64
		folderID int64
	}
	var inserted []queued

	for _, l := range locals {
		var folderID, uidNext int64
		if err := tx.QueryRow(`SELECT id, uid_next FROM folders WHERE mailbox_id=? AND name='INBOX'`, l.MailboxID).
			Scan(&folderID, &uidNext); err != nil {
			return fmt.Errorf("inbox of mailbox %d: %w", l.MailboxID, err)
		}
		res, err := tx.Exec(`INSERT INTO mails(folder_id, msg_uid, sender, recipient, subject, flags, size, raw_blob, code, spam_score, body_text)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			folderID, uidNext, from, l.Address, l.Subject, "", len(raw), raw, l.Code, l.Score, l.TextBody)
		if err != nil {
			return err
		}
		mailID, _ := res.LastInsertId()
		if _, err := tx.Exec(`UPDATE folders SET uid_next=uid_next+1 WHERE id=?`, folderID); err != nil {
			return err
		}
		inserted = append(inserted, queued{mailID: mailID, folderID: folderID})
	}

	for _, to := range externals {
		var mbID any
		if queueMailboxID > 0 {
			mbID = queueMailboxID
		}
		if _, err := tx.Exec(`INSERT INTO mail_queue(mailbox_id, from_addr, to_addr, raw_blob, next_try_at)
			VALUES(?,?,?,?,datetime('now'))`, mbID, from, to, raw); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// 提交后再做通知与转发，避免在事务里做额外 IO。
	// 先标 \Recent 再通知：顺序反了，通知里读到的 RECENT 会少一封。
	seen := map[int64]bool{}
	for _, q := range inserted {
		s.markRecent(q.mailID, q.folderID)
		if s.OnInsert != nil && !seen[q.folderID] {
			seen[q.folderID] = true
			s.OnInsert(q.folderID)
		}
	}
	for _, l := range locals {
		s.EnqueueForwards(l.MailboxID, from, raw)
	}
	return nil
}

// RecentMail 工作台最近邮件。
type RecentMail struct {
	ID        int64  `json:"id"`
	Sender    string `json:"sender"`
	Subject   string `json:"subject"`
	Code      string `json:"code"`
	CreatedAt string `json:"created_at"`
	Unread    bool   `json:"unread"`
}

// RecentMails 用户跨邮箱最近 N 封。
func (s *Store) RecentMails(userID int64, n int) ([]RecentMail, int, error) {
	rows, err := s.DB.Query(`SELECT m.id, m.sender, m.subject, COALESCE(m.code,''), m.created_at,
		CASE WHEN m.flags LIKE '%\Seen%' THEN 0 ELSE 1 END
		FROM mails m JOIN folders f ON f.id=m.folder_id JOIN mailboxes mb ON mb.id=f.mailbox_id
		WHERE mb.user_id=? ORDER BY m.id DESC LIMIT ?`, userID, n)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []RecentMail{}
	for rows.Next() {
		var m RecentMail
		var unread int
		if err := rows.Scan(&m.ID, &m.Sender, &m.Subject, &m.Code, &m.CreatedAt, &unread); err != nil {
			return nil, 0, err
		}
		m.Unread = unread == 1
		out = append(out, m)
	}
	return out, len(out), rows.Err()
}
