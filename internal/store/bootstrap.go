package store

import (
	"log"
	"time"

	"github.com/david88558855/private-email/internal/mailutil"
)

// Bootstrap 首启种子：仅保证 admin 有可用邮箱（若无任何域名则提示）。
// 域名完全由管理员在后台添加，不再内置 local.test。
func (s *Store) Bootstrap() {}

// RebuildFTSBody 迁移后为旧邮件补 body_text（触发器自动同步 FTS）。
//
// 分页处理：老库第一次升级时几 GB 邮件如果一次性读进内存会 OOM。
// 这里先取 id 列表（不碰 BLOB），再逐封读原文、解析、写回，内存里同时
// 最多只有一封邮件。
func (s *Store) RebuildFTSBody() {
	if v, err := s.GetSetting("fts_backfill_done"); err != nil || v == "1" {
		return
	}
	rows, err := s.DB.Query(`SELECT id FROM mails WHERE body_text='' AND length(raw_blob) > 0 ORDER BY id`)
	if err != nil {
		log.Printf("全文索引重建：查询待回填邮件失败: %v", err)
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			log.Printf("全文索引重建：扫描 id 失败: %v", err)
			rows.Close()
			return
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		log.Printf("全文索引重建：遍历 id 失败: %v", err)
		rows.Close()
		return
	}
	rows.Close()

	done, failed := 0, 0
	deadline := time.Now().Add(10 * time.Minute)
	for _, id := range ids {
		if time.Now().After(deadline) {
			log.Printf("全文索引重建已达单次时间上限，剩余 %d 封下次启动继续", len(ids)-done)
			return // 不写 done 标记，下次启动继续
		}
		var raw []byte
		if err := s.DB.QueryRow(`SELECT raw_blob FROM mails WHERE id=?`, id).Scan(&raw); err != nil {
			failed++
			log.Printf("全文索引重建：读取 mail=%d 失败: %v", id, err)
			continue
		}
		p := mailutil.Parse(raw)
		if _, err := s.DB.Exec(`UPDATE mails SET body_text=? WHERE id=?`, p.TextBody, id); err != nil {
			failed++
			log.Printf("全文索引重建：写回 mail=%d 失败: %v", id, err)
			continue
		}
		done++
	}
	if done > 0 {
		log.Printf("已重建 %d 封旧邮件的全文索引", done)
	}
	// 只有全部成功才落完成标记；否则剩余邮件的 body_text 永远为空、检索永久残缺。
	if failed > 0 {
		log.Printf("全文索引重建有 %d 封失败，下次启动继续", failed)
		return
	}
	if err := s.SetSetting("fts_backfill_done", "1"); err != nil {
		log.Printf("全文索引重建：写入完成标记失败: %v", err)
	}
}
