package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/david88558855/private-email/internal/store"
	"github.com/gin-gonic/gin"
)

// Dashboard GET /api/v1/dashboard —— 用户工作台数据。
func (h *MailHandler) Dashboard(c *gin.Context) {
	uid := c.GetInt64("user_id")
	out := map[string]any{}
	var mailboxes, today, unread int64
	var storage int64
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mailboxes WHERE user_id=?`, uid).Scan(&mailboxes)
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mails m JOIN folders f ON f.id=m.folder_id
		JOIN mailboxes mb ON mb.id=f.mailbox_id WHERE mb.user_id=? AND date(m.created_at)=date('now','localtime')`, uid).Scan(&today)
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mails m JOIN folders f ON f.id=m.folder_id
		JOIN mailboxes mb ON mb.id=f.mailbox_id WHERE mb.user_id=? AND m.flags NOT LIKE '%\Seen%'`, uid).Scan(&unread)
	h.Store.DB.QueryRow(`SELECT COALESCE(SUM(m.size),0) FROM mails m JOIN folders f ON f.id=m.folder_id
		JOIN mailboxes mb ON mb.id=f.mailbox_id WHERE mb.user_id=?`, uid).Scan(&storage)
	out["mailboxes"] = mailboxes
	out["today"] = today
	out["unread"] = unread
	out["storage_bytes"] = storage

	// 近 7 日趋势
	type trend struct {
		Day   string `json:"day"`
		Count int64  `json:"count"`
	}
	trends := []trend{}
	rows, err := h.Store.DB.Query(`SELECT date(m.created_at, 'localtime') d, COUNT(*) FROM mails m
		JOIN folders f ON f.id=m.folder_id JOIN mailboxes mb ON mb.id=f.mailbox_id
		WHERE mb.user_id=? AND m.created_at >= datetime('now','-6 days','localtime','start of day')
		GROUP BY d ORDER BY d`, uid)
	if err == nil {
		defer rows.Close()
		byDay := map[string]int64{}
		for rows.Next() {
			var d string
			var n int64
			rows.Scan(&d, &n)
			byDay[d] = n
		}
		for i := 6; i >= 0; i-- {
			day := timeShift(i)
			trends = append(trends, trend{Day: day, Count: byDay[day]})
		}
	}
	out["trend"] = trends

	// 最近邮件
	recent, _, err := h.Store.RecentMails(uid, 5)
	if err != nil {
		recent = []store.RecentMail{}
	}
	out["recent"] = recent
	c.JSON(http.StatusOK, out)
}

func timeShift(back int) string {
	return time.Now().AddDate(0, 0, -back).Format("2006-01-02")
}

// Rules GET/POST/DELETE /api/v1/mailboxes/:id/rules?kind=forward|verif
func (h *MailHandler) Rules(c *gin.Context) {
	uid := c.GetInt64("user_id")
	mbID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if !h.Store.OwnsMailbox(mbID, uid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问"})
		return
	}
	kind := c.DefaultQuery("kind", "forward")
	switch c.Request.Method {
	case http.MethodGet:
		if kind == "verif" {
			rows, err := h.Store.DB.Query(`SELECT id, name, pattern FROM verification_rules WHERE mailbox_id=? AND is_active=1`, mbID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
				return
			}
			defer rows.Close()
			items := []map[string]any{}
			for rows.Next() {
				var id int64
				var name, pattern string
				rows.Scan(&id, &name, &pattern)
				items = append(items, map[string]any{"id": id, "name": name, "pattern": pattern})
			}
			c.JSON(http.StatusOK, gin.H{"items": items})
			return
		}
		rows, err := h.Store.DB.Query(`SELECT id, target FROM forward_rules WHERE mailbox_id=? AND is_active=1`, mbID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var id int64
			var target string
			rows.Scan(&id, &target)
			items = append(items, map[string]any{"id": id, "target": target})
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	case http.MethodPost:
		if kind == "verif" {
			var req struct{ Name, Pattern string }
			if c.ShouldBindJSON(&req) != nil || req.Pattern == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
				return
			}
			if req.Name == "" {
				req.Name = "自定义规则"
			}
			if _, err := h.Store.DB.Exec(`INSERT INTO verification_rules(mailbox_id, name, pattern) VALUES(?,?,?)`,
				mbID, req.Name, req.Pattern); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "正则无效"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"ok": true})
			return
		}
		var req struct {
			Target string `json:"target" binding:"required,email"`
		}
		if c.ShouldBindJSON(&req) != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误（需合法邮箱）"})
			return
		}
		h.Store.DB.Exec(`INSERT INTO forward_rules(mailbox_id, target) VALUES(?,?)`, mbID, req.Target)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	case http.MethodDelete:
		id, _ := strconv.ParseInt(c.Query("id"), 10, 64)
		if kind == "verif" {
			h.Store.DB.Exec(`DELETE FROM verification_rules WHERE id=? AND mailbox_id=?`, id, mbID)
		} else {
			h.Store.DB.Exec(`DELETE FROM forward_rules WHERE id=? AND mailbox_id=?`, id, mbID)
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

// Domains GET /api/v1/domains —— 登录用户可读域名列表（创建邮箱用）。
func (h *MailHandler) DomainsList(c *gin.Context) {
	rows, err := h.Store.DB.Query(`SELECT id, domain FROM domains WHERE status='verified' ORDER BY id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var domain string
		rows.Scan(&id, &domain)
		items = append(items, map[string]any{"id": id, "domain": domain})
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// MailboxCreate POST /api/v1/mailboxes {prefix, domain_id} —— 用户自助创建邮箱。
func (h *MailHandler) MailboxCreate(c *gin.Context) {
	uid := c.GetInt64("user_id")
	var req struct {
		Prefix   string `json:"prefix" binding:"required,min=2,max=32"`
		DomainID int64  `json:"domain_id"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误（前缀 2-32 位）"})
		return
	}
	if !validUsername(req.Prefix) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "前缀仅限小写字母/数字/-/_，2-32 位"})
		return
	}
	// 数量上限
	var count int64
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mailboxes WHERE user_id=?`, uid).Scan(&count)
	if count >= 10 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "每个用户最多 10 个邮箱"})
		return
	}
	// 域名：指定则校验，否则取第一个
	domainID := req.DomainID
	var domain string
	if domainID > 0 {
		if err := h.Store.DB.QueryRow(`SELECT domain FROM domains WHERE id=? AND status='verified'`, domainID).
			Scan(&domain); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "域名不存在或未验证"})
			return
		}
	} else {
		if err := h.Store.DB.QueryRow(`SELECT id, domain FROM domains WHERE status='verified' ORDER BY id LIMIT 1`).
			Scan(&domainID, &domain); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "暂无可用域名，请联系管理员"})
			return
		}
	}
	address := req.Prefix + "@" + domain
	// 密码与 Web 一致（D2）：取用户当前哈希
	var hash string
	if err := h.Store.DB.QueryRow(`SELECT password FROM users WHERE id=?`, uid).Scan(&hash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	res, err := h.Store.DB.Exec(`INSERT INTO mailboxes(user_id, address, domain_id, password) VALUES(?,?,?,?)`,
		uid, address, domainID, hash)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "该地址已被占用"})
		return
	}
	mbID, _ := res.LastInsertId()
	h.Store.EnsureFolders(mbID)
	h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, detail) VALUES(?, 'mailbox_create', ?)`, uid, address)
	c.JSON(http.StatusOK, gin.H{"ok": true, "address": address, "id": mbID})
}

// MailboxPatch PATCH /api/v1/mailboxes/:id {active:bool} —— 停用/启用自己的邮箱。
func (h *MailHandler) MailboxPatch(c *gin.Context) {
	uid := c.GetInt64("user_id")
	mbID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if !h.Store.OwnsMailbox(mbID, uid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问"})
		return
	}
	var req struct {
		Active *bool `json:"active" binding:"required"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	v := 0
	if *req.Active {
		v = 1
	}
	h.Store.DB.Exec(`UPDATE mailboxes SET is_active=? WHERE id=?`, v, mbID)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
