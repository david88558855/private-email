package database

import (
	"database/sql"
	"fmt"
)

var migrations = []string{
	// 001 初始 schema（方案 4.2 节）
	`
CREATE TABLE users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL,            -- bcrypt
	role TEXT NOT NULL DEFAULT 'user', -- user | admin
	status TEXT NOT NULL DEFAULT 'active', -- active | disabled
	contribution INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE sessions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	token_hash TEXT UNIQUE NOT NULL,
	ip TEXT,
	expiry DATETIME NOT NULL
);
CREATE TABLE domains (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT UNIQUE NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending', -- pending | verified
	dns_verified_at DATETIME,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE mailboxes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	address TEXT UNIQUE NOT NULL,
	domain_id INTEGER NOT NULL REFERENCES domains(id),
	password TEXT NOT NULL,            -- bcrypt，SMTP/IMAP/POP3 认证（D2：复用+App专用密码）
	is_active INTEGER NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE app_passwords (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
	label TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	last_used DATETIME,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE folders (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	uid_validity INTEGER NOT NULL,
	uid_next INTEGER NOT NULL DEFAULT 1,
	UNIQUE(mailbox_id, name)
);
CREATE TABLE mails (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
	msg_uid INTEGER NOT NULL,
	sender TEXT NOT NULL,
	recipient TEXT NOT NULL,
	subject TEXT DEFAULT '',
	flags TEXT DEFAULT '',             -- IMAP flags: \Seen \Answered ...
	size INTEGER NOT NULL DEFAULT 0,
	raw_blob BLOB,                     -- 原始 MIME 报文（D1=B 全库存储）
	code TEXT,                         -- 验证码提取结果
	spam_score REAL NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(folder_id, msg_uid)
);
CREATE TABLE mail_attachments (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mail_id INTEGER NOT NULL REFERENCES mails(id) ON DELETE CASCADE,
	filename TEXT NOT NULL,
	content_type TEXT,
	size INTEGER NOT NULL
);
CREATE VIRTUAL TABLE mails_fts USING fts5(subject, sender, body_text);
CREATE TABLE forward_rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
	target TEXT NOT NULL,
	condition_json TEXT DEFAULT '{}',
	is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE verification_rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mailbox_id INTEGER REFERENCES mailboxes(id) ON DELETE CASCADE, -- NULL=全局
	name TEXT NOT NULL,
	pattern TEXT NOT NULL,             -- 正则
	is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE dkim_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
	selector TEXT NOT NULL,
	private_key TEXT NOT NULL,         -- PEM（D1=B 同库存储）
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE mail_queue (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mailbox_id INTEGER REFERENCES mailboxes(id) ON DELETE SET NULL,
	from_addr TEXT NOT NULL,
	to_addr TEXT NOT NULL,
	raw_blob BLOB NOT NULL,
	status TEXT NOT NULL DEFAULT 'queued', -- queued|sent|failed
	attempts INTEGER NOT NULL DEFAULT 0,
	next_try_at DATETIME,
	last_error TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE invites (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	code TEXT UNIQUE NOT NULL,
	created_by INTEGER REFERENCES users(id),
	used_by INTEGER REFERENCES users(id),
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE audit_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER,
	action TEXT NOT NULL,
	detail TEXT,
	ip TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_mails_folder ON mails(folder_id, created_at DESC);
CREATE INDEX idx_queue_status ON mail_queue(status, next_try_at);
`,
}

// Migrate 顺序执行未应用的迁移，schema_migrations 记录版本。
func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return err
	}
	var current int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	for i, m := range migrations {
		v := i + 1
		if v <= current {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %03d: %w", v, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version) VALUES(?)`, v); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
