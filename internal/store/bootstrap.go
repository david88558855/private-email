package store

import (
	"log"

	"github.com/david88558855/private-email/internal/mailutil"
)

// Bootstrap 首启种子：默认域名 + 管理员邮箱（密码复用 Web 密码，D2）。
func (s *Store) Bootstrap() {
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM domains`).Scan(&n)
	if n == 0 {
		if _, err := s.DB.Exec(`INSERT INTO domains(domain, status, dns_verified_at) VALUES('local.test','verified',datetime('now'))`); err != nil {
			log.Println("seed domain:", err)
		}
	}
	// 为每个有权限用户确保至少一个邮箱（按 用户名@第一个域名）
	var domainID int64
	s.DB.QueryRow(`SELECT id FROM domains ORDER BY id LIMIT 1`).Scan(&domainID)
	rows, err := s.DB.Query(`SELECT u.id, u.username FROM users u WHERE NOT EXISTS
		(SELECT 1 FROM mailboxes mb WHERE mb.user_id=u.id)`)
	if err != nil {
		return
	}
	type pair struct {
		id   int64
		name string
	}
	var need []pair
	for rows.Next() {
		var p pair
		rows.Scan(&p.id, &p.name)
		need = append(need, p)
	}
	rows.Close()
	for _, p := range need {
		var hash string
		if err := s.DB.QueryRow(`SELECT password FROM users WHERE id=?`, p.id).Scan(&hash); err != nil {
			continue
		}
		addr := p.name + "@local.test"
		if _, err := s.DB.Exec(`INSERT INTO mailboxes(user_id, address, domain_id, password) VALUES(?,?,?,?)`,
			p.id, addr, domainID, hash); err != nil {
			log.Println("seed mailbox:", err)
			continue
		}
		var mbID int64
		s.DB.QueryRow(`SELECT id FROM mailboxes WHERE address=?`, addr).Scan(&mbID)
		s.EnsureFolders(mbID)
		log.Printf("已创建邮箱 %s（客户端密码与 Web 登录一致）", addr)
	}
}

// RebuildFTSBody 迁移 002 后为旧邮件补 body_text（触发器自动同步 FTS）。
func (s *Store) RebuildFTSBody() {
	rows, err := s.DB.Query(`SELECT id, raw_blob FROM mails WHERE body_text='' AND length(raw_blob) > 0`)
	if err != nil {
		return
	}
	type item struct {
		id  int64
		raw []byte
	}
	var need []item
	for rows.Next() {
		var it item
		if rows.Scan(&it.id, &it.raw) == nil {
			need = append(need, it)
		}
	}
	rows.Close()
	for _, it := range need {
		p := mailutil.Parse(it.raw)
		s.DB.Exec(`UPDATE mails SET body_text=? WHERE id=?`, p.TextBody, it.id)
	}
	if len(need) > 0 {
		log.Printf("已重建 %d 封旧邮件的全文索引", len(need))
	}
}
