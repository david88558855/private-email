package handlers

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
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
	// created_at 存的是 UTC；直接 date(created_at) 与本地日期比，在 UTC+8 的
	// 00:00–08:00 之间会把刚收到的邮件算成"昨天"。两边都转本地再比。
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mails m JOIN folders f ON f.id=m.folder_id
		JOIN mailboxes mb ON mb.id=f.mailbox_id
		WHERE mb.user_id=? AND date(m.created_at,'localtime')=date('now','localtime')`, uid).Scan(&today)
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
	rows, err := h.Store.DB.Query(`SELECT date(m.created_at,'localtime') d, COUNT(*) FROM mails m
		JOIN folders f ON f.id=m.folder_id JOIN mailboxes mb ON mb.id=f.mailbox_id
		WHERE mb.user_id=? AND date(m.created_at,'localtime') >= date('now','-6 days','localtime')
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
			// 存之前先编译：无效或过长的正则会在提取阶段被跳过，等于静默失效
			if len(req.Pattern) > 128 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "正则过长（上限 128 字符）"})
				return
			}
			re, err := regexp.Compile(req.Pattern)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "正则无效：" + err.Error()})
				return
			}
			if !hasCaptureGroup(re) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "正则需包含捕获组，如 ([0-9]{6})"})
				return
			}
			var n int
			if err := h.Store.DB.QueryRow(`SELECT COUNT(*) FROM verification_rules WHERE mailbox_id=?`, mbID).Scan(&n); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
				return
			}
			if n >= maxRulesPerMailbox {
				c.JSON(http.StatusBadRequest, gin.H{"error": "自定义规则最多 50 条，请先删除不用的"})
				return
			}
			if _, err := h.Store.DB.Exec(`INSERT INTO verification_rules(mailbox_id, name, pattern) VALUES(?,?,?)`,
				mbID, req.Name, req.Pattern); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "保存失败"})
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
		var n int
		if err := h.Store.DB.QueryRow(`SELECT COUNT(*) FROM forward_rules WHERE mailbox_id=?`, mbID).Scan(&n); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
			return
		}
		if n >= maxRulesPerMailbox {
			c.JSON(http.StatusBadRequest, gin.H{"error": "转发规则最多 50 条，请先删除不用的"})
			return
		}
		if _, err := h.Store.DB.Exec(`INSERT INTO forward_rules(mailbox_id, target) VALUES(?,?)`, mbID, req.Target); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	case http.MethodDelete:
		id, _ := strconv.ParseInt(c.Query("id"), 10, 64)
		table := "forward_rules"
		if kind == "verif" {
			table = "verification_rules"
		}
		if _, err := h.Store.DB.Exec(`DELETE FROM `+table+` WHERE id=? AND mailbox_id=?`, id, mbID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
			return
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
	// pending_count 让前端能区分「一个域名都没加」和「加了但没验证」。
	// 原来两种情况都返回空数组，前端只能笼统提示"请先在后台添加域名"，
	// 管理员明明加了域名，用户却被告知没加，排查方向直接被带偏。
	var pending int
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM domains WHERE status<>'verified'`).Scan(&pending)
	c.JSON(http.StatusOK, gin.H{"items": items, "pending_count": pending})
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
			var pending int
			h.Store.DB.QueryRow(`SELECT COUNT(*) FROM domains WHERE status<>'verified'`).Scan(&pending)
			if pending > 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "域名尚未完成验证，请管理员在后台验证后再创建"})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": "暂无可用域名，请联系管理员"})
			}
			return
		}
	}
	prefix := strings.ToLower(req.Prefix)
	if reservedAddresses[prefix] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该地址为系统保留地址"})
		return
	}
	address := prefix + "@" + strings.ToLower(domain)
	// SQLite 的 UNIQUE 是大小写敏感的，`Alice@x` 和 `alice@x` 能同时存在，
	// 而登录查询用的是 lower(address)，会随机命中一个。这里统一小写并显式查重。
	var dup int
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mailboxes WHERE lower(address)=?`, address).Scan(&dup)
	if dup > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "该地址已被占用"})
		return
	}
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

// DomainDelete DELETE /api/v1/admin/domains/:id —— 删除域名（有邮箱时拒绝）。
func (h *MailHandler) DomainDelete(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var n int64
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mailboxes WHERE domain_id=?`, id).Scan(&n)
	if n > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("该域名下仍有 %d 个邮箱，请先删除", n)})
		return
	}
	res, err := h.Store.DB.Exec(`DELETE FROM domains WHERE id=?`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	if k, _ := res.RowsAffected(); k == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "域名不存在"})
		return
	}
	h.Store.DB.Exec(`DELETE FROM dkim_keys WHERE domain_id=?`, id)
	h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, detail) VALUES(?,?,?)`,
		c.GetInt64("user_id"), "domain_delete", c.Param("id"))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// hasCaptureGroup 验证码规则必须能取出捕获组，否则匹配成功也拿不到码。
func hasCaptureGroup(re *regexp.Regexp) bool { return re.NumSubexp() > 0 }

// reservedAddresses 系统/管理类地址，禁止普通用户抢注。
// 多人共用一个实例时，抢到 postmaster@ 就等于拿到对外身份，可用来钓鱼。
var reservedAddresses = map[string]bool{
	"postmaster": true, "hostmaster": true, "webmaster": true, "abuse": true,
	"admin": true, "administrator": true, "root": true, "security": true,
	"noreply": true, "no-reply": true, "mailer-daemon": true, "daemon": true,
	"support": true, "billing": true, "hr": true, "sales": true, "info": true,
	"contact": true, "legal": true, "privacy": true, "dns": true, "ftp": true,
	"www": true, "mail": true,
}
