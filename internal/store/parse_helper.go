package store

import "github.com/david88558855/private-email/internal/mailutil"

// ParseFull 解析已取出的邮件 BLOB。
func ParseFull(m *MailFull) *mailutil.Parsed { return mailutil.Parse(m.Raw) }
