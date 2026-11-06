package store

import "database/sql"

// Mailbox 邮箱账户。
type Mailbox struct {
	ID       int64  `json:"id"`
	UserID   int64  `json:"user_id"`
	Address  string `json:"address"`
	DomainID int64  `json:"domain_id"`
	IsActive bool   `json:"is_active"`
}

// MailboxByAddress SMTP RCPT 校验用。
//
// 显式 ORDER BY id LIMIT 1：历史库里可能存在仅大小写不同的重复地址
// （早期版本没做小写归一），不带排序时命中哪一行由 SQLite 决定。
// 主密码是共用哈希所以看不出差别，但 App 专用密码按邮箱归属校验，
// 命错行就会表现成「令牌怎么都不对」。
func (s *Store) MailboxByAddress(addr string) (*Mailbox, error) {
	m := &Mailbox{}
	err := s.DB.QueryRow(`SELECT id, user_id, address, domain_id, is_active FROM mailboxes
		WHERE lower(address)=lower(?) AND is_active=1 ORDER BY id LIMIT 1`, addr).
		Scan(&m.ID, &m.UserID, &m.Address, &m.DomainID, &m.IsActive)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return m, err
}

// MailboxesOf 用户的邮箱列表。
func (s *Store) MailboxesOf(userID int64) ([]Mailbox, error) {
	rows, err := s.DB.Query(`SELECT id, user_id, address, domain_id, is_active FROM mailboxes WHERE user_id=?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Mailbox{}
	for rows.Next() {
		var m Mailbox
		if err := rows.Scan(&m.ID, &m.UserID, &m.Address, &m.DomainID, &m.IsActive); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// OwnsMailbox 校验归属。
func (s *Store) OwnsMailbox(mailboxID, userID int64) bool {
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM mailboxes WHERE id=? AND user_id=?`, mailboxID, userID).Scan(&n)
	return n > 0
}

// FoldersOf 邮箱文件夹。
func (s *Store) FoldersOf(mailboxID int64) ([]map[string]any, error) {
	rows, err := s.DB.Query(`SELECT f.id, f.name, f.uid_validity,
		(SELECT COUNT(*) FROM mails m WHERE m.folder_id=f.id) AS total,
		(SELECT COUNT(*) FROM mails m WHERE m.folder_id=f.id AND m.flags NOT LIKE '%\Seen%') AS unread
		FROM folders f WHERE f.mailbox_id=? ORDER BY f.id`, mailboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, total, unread int64
		var name string
		var uv int64
		if err := rows.Scan(&id, &name, &uv, &total, &unread); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "name": name, "uid_validity": uv, "total": total, "unread": unread})
	}
	return out, rows.Err()
}
