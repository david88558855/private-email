// Package store SQLite 单库读写层（D1=B：元数据 + 邮件 BLOB 同库）。
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"fmt"
	"strings"
)

// Store 封装全部持久化操作。
type Store struct {
	DB *sql.DB
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
	return mailID, uidNext, tx.Commit()
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
	var rows *sql.Rows
	var err error
	var total int
	q = strings.TrimSpace(q)
	fq := ftsQuery(q)
	// 只搜到特殊符号时视为无匹配，避免拼出非法 FTS5 表达式导致 500
	if q != "" && fq == "" {
		return []MailSummary{}, 0, nil
	}
	// 先 COUNT 后取 rows：单写连接下 rows 未关闭时再查询会自锁
	if fq != "" {
		base += `JOIN mails_fts f ON f.rowid = m.id AND mails_fts MATCH ? WHERE m.folder_id=? `
		s.DB.QueryRow(`SELECT COUNT(*) FROM mails m JOIN mails_fts f ON f.rowid=m.id AND mails_fts MATCH ? WHERE m.folder_id=?`, fq, folderID).Scan(&total)
		rows, err = s.DB.Query(base+`ORDER BY m.id DESC LIMIT ? OFFSET ?`, fq, folderID, limit, offset)
	} else {
		base += `WHERE m.folder_id=? `
		s.DB.QueryRow(`SELECT COUNT(*) FROM mails WHERE folder_id=?`, folderID).Scan(&total)
		rows, err = s.DB.Query(base+`ORDER BY m.id DESC LIMIT ? OFFSET ?`, folderID, limit, offset)
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

// ftsQuery 把用户输入转成 FTS5 查询串：逐词加引号并做前缀匹配。
// FTS5 的语法符号（引号、星号、括号、冒号、尖号）在引号内也不安全，一律剔除；
// 全部被剔除则返回空串，由调用方当作“无匹配”处理。
func ftsQuery(q string) string {
	words := strings.Fields(q)
	out := make([]string, 0, len(words))
	for _, w := range words {
		w = strings.Map(func(r rune) rune {
			switch r {
			case '"', '*', '(', ')', ':', '^':
				return -1
			}
			return r
		}, w)
		if w != "" {
			out = append(out, `"`+w+`"*`)
		}
	}
	return strings.Join(out, " ")
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

// MarkSeen 置已读。
func (s *Store) MarkSeen(id int64) error {
	_, err := s.DB.Exec(`UPDATE mails SET flags = CASE WHEN flags LIKE '%\Seen%' THEN flags ELSE flags || ' \Seen' END WHERE id=?`, id)
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
	if _, err := tx.Exec(`UPDATE mails SET folder_id=?, msg_uid=? WHERE id=?`, dstFolderID, uidNext, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE folders SET uid_next=uid_next+1 WHERE id=?`, dstFolderID); err != nil {
		return err
	}
	return tx.Commit()
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
	s.DB.Exec(`INSERT INTO mail_queue(mailbox_id, from_addr, to_addr, raw_blob, next_try_at) VALUES(?,?,?,?,datetime('now'))`,
		mailboxID, from, to, raw)
}

// EnqueueForwards 按转发规则把邮件投递入队（无规则则什么都不做）。
func (s *Store) EnqueueForwards(mailboxID int64, from string, raw []byte) {
	rows, err := s.DB.Query(`SELECT target FROM forward_rules WHERE mailbox_id=? AND is_active=1`, mailboxID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var target string
		if rows.Scan(&target) == nil && target != "" {
			s.EnqueueForward(mailboxID, from, target, raw)
		}
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
