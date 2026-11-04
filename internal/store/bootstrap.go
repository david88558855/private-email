package store

import (
	"log"

	"github.com/david88558855/private-email/internal/mailutil"
)

// Bootstrap 首启种子：仅保证 admin 有可用邮箱（若无任何域名则提示）。
// 域名完全由管理员在后台添加，不再内置 local.test。
func (s *Store) Bootstrap() {}

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
