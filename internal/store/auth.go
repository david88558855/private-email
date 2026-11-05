package store

import "golang.org/x/crypto/bcrypt"

// VerifyMailboxAuth 协议层认证（D2：Web 密码或 App 专用密码）。
func (s *Store) VerifyMailboxAuth(address, password string) (*Mailbox, bool) {
	mb, err := s.MailboxByAddress(address)
	if err != nil || mb == nil {
		return nil, false
	}
	// 账号被管理员停用时，Web 侧会立刻 401，但协议侧（IMAP/POP3/SMTP）原本不受影响，
	// 等于停用只挡住了网页。这里统一按 users.status 判定，App 专用密码一并失效。
	var status string
	if err := s.DB.QueryRow(`SELECT status FROM users WHERE id=?`, mb.UserID).Scan(&status); err != nil || status != "active" {
		return nil, false
	}
	var hash string
	if err := s.DB.QueryRow(`SELECT password FROM mailboxes WHERE id=?`, mb.ID).Scan(&hash); err != nil {
		return nil, false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
		return mb, true
	}
	rows, err := s.DB.Query(`SELECT password_hash FROM app_passwords WHERE mailbox_id=?`, mb.ID)
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		if rows.Scan(&h) == nil && bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) == nil {
			s.DB.Exec(`UPDATE app_passwords SET last_used=datetime('now') WHERE password_hash=?`, h)
			return mb, true
		}
	}
	return nil, false
}
