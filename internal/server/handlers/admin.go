package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/david88558855/private-email/internal/outbound"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type AdminHandler struct {
	Store *storeAlias
}

// adminOnly 中间件片段
func adminOK(c *gin.Context) bool {
	if c.GetString("role") != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "需要管理员权限"})
		return false
	}
	return true
}

// Users GET /api/v1/admin/users
func (h *MailHandler) Users(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	rows, err := h.Store.DB.Query(`SELECT u.id, u.username, u.role, u.status, u.created_at,
		(SELECT COUNT(*) FROM mailboxes mb WHERE mb.user_id=u.id) FROM users u ORDER BY u.id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, mbs int64
		var username, role, status, created string
		rows.Scan(&id, &username, &role, &status, &created, &mbs)
		items = append(items, map[string]any{"id": id, "username": username, "role": role,
			"status": status, "created_at": created, "mailboxes": mbs})
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// UserPatch PATCH /api/v1/admin/users/:id {op: disable|enable|reset, password?}
func (h *MailHandler) UserPatch(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Op       string `json:"op"`
		Password string `json:"password"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	switch req.Op {
	case "disable", "enable":
		st := "disabled"
		if req.Op == "enable" {
			st = "active"
		}
		h.Store.DB.Exec(`UPDATE users SET status=? WHERE id=?`, st, id)
	case "reset":
		if len(req.Password) < 6 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "密码至少 6 位"})
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		h.Store.DB.Exec(`UPDATE users SET password=? WHERE id=?`, string(hash), id)
		// 同步该用户全部邮箱的客户端密码（D2 默认复用）
		h.Store.DB.Exec(`UPDATE mailboxes SET password=? WHERE user_id=?`, string(hash), id)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "未知操作"})
		return
	}
	h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, detail) VALUES(?,?,?)`,
		c.GetInt64("user_id"), "admin_"+req.Op, "user:"+c.Param("id"))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// UserAdd POST /api/v1/admin/users {username, password, role}
func (h *MailHandler) UserAdd(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	var req struct {
		Username string `json:"username" binding:"required,min=2,max=32"`
		Password string `json:"password" binding:"required,min=6"`
		Role     string `json:"role"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误（用户名 2-32 位，密码至少 6 位）"})
		return
	}
	if req.Role != "admin" {
		req.Role = "user"
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	res, err := h.Store.DB.Exec(`INSERT INTO users(username, password, role) VALUES(?,?,?)`,
		req.Username, string(hash), req.Role)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}
	uid, _ := res.LastInsertId()
	// 自动建邮箱 username@第一个域名
	var domainID int64
	var domain string
	h.Store.DB.QueryRow(`SELECT id, domain FROM domains ORDER BY id LIMIT 1`).Scan(&domainID, &domain)
	if domainID > 0 {
		h.Store.DB.Exec(`INSERT INTO mailboxes(user_id, address, domain_id, password) VALUES(?,?,?,?)`,
			uid, req.Username+"@"+domain, domainID, string(hash))
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "address": req.Username + "@" + domain})
}

// Domains GET /api/v1/admin/domains —— 含 DKIM DNS 记录展示
func (h *MailHandler) Domains(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	rows, err := h.Store.DB.Query(`SELECT d.id, d.domain, d.status, d.created_at,
		COALESCE(k.selector,''), COALESCE(k.private_key,'') FROM domains d
		LEFT JOIN dkim_keys k ON k.domain_id=d.id ORDER BY d.id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var domain, status, created, selector, key string
		rows.Scan(&id, &domain, &status, &created, &selector, &key)
		item := map[string]any{"id": id, "domain": domain, "status": status, "created_at": created}
		if key != "" {
			pub := dnsTXTFor(key)
			item["dkim_dns"] = map[string]any{
				"host":   selector + "._domainkey." + domain,
				"record": "v=DKIM1; k=rsa; p=" + pub,
			}
		}
		items = append(items, item)
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// DomainAdd POST /api/v1/admin/domains {domain}
func (h *MailHandler) DomainAdd(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	var req struct {
		Domain string `json:"domain" binding:"required"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	req.Domain = strings.ToLower(strings.Trim(req.Domain, ". "))
	if !strings.Contains(req.Domain, ".") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名格式错误"})
		return
	}
	if _, err := h.Store.DB.Exec(`INSERT INTO domains(domain, status, dns_verified_at) VALUES(?,?,datetime('now'))`,
		req.Domain, "verified"); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "域名已存在"})
		return
	}
	outbound.EnsureDKIMKeys(h.Store)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Invites GET/POST /api/v1/admin/invites
func (h *MailHandler) Invites(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	if c.Request.Method == http.MethodPost {
		code := randCode(8)
		h.Store.DB.Exec(`INSERT INTO invites(code, created_by) VALUES(?,?)`, code, c.GetInt64("user_id"))
		c.JSON(http.StatusOK, gin.H{"code": code})
		return
	}
	rows, err := h.Store.DB.Query(`SELECT i.code, i.created_at, i.used_by,
		(SELECT username FROM users WHERE id=i.used_by) FROM invites i ORDER BY i.id DESC LIMIT 50`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var code, created string
		var usedBy any
		rows.Scan(&code, &created, &usedBy, &usedBy)
		used := usedBy != nil && usedBy != ""
		items = append(items, map[string]any{"code": code, "created_at": created, "used": used})
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// Stats GET /api/v1/admin/stats —— 监控概览
func (h *MailHandler) Stats(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	var users, mailboxes, mails, queued, sent, failed int64
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users)
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mailboxes`).Scan(&mailboxes)
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mails`).Scan(&mails)
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mail_queue WHERE status='queued'`).Scan(&queued)
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mail_queue WHERE status='sent'`).Scan(&sent)
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM mail_queue WHERE status='failed'`).Scan(&failed)
	dbBytes := int64(0)
	h.Store.DB.QueryRow(`SELECT page_count*page_size FROM pragma_page_count(), pragma_page_size()`).Scan(&dbBytes)
	c.JSON(http.StatusOK, gin.H{"users": users, "mailboxes": mailboxes, "mails": mails,
		"queue":    map[string]int64{"queued": queued, "sent": sent, "failed": failed},
		"db_bytes": dbBytes})
}

// Register POST /api/v1/auth/register {invite, username, password}
func (h *MailHandler) Register(c *gin.Context) {
	var req struct {
		Invite   string `json:"invite" binding:"required"`
		Username string `json:"username" binding:"required,min=2,max=32"`
		Password string `json:"password" binding:"required,min=6"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误（用户名 2-32 位，密码至少 6 位）"})
		return
	}
	var id int64
	err := h.Store.DB.QueryRow(`SELECT id FROM invites WHERE code=? AND used_by IS NULL`, req.Invite).Scan(&id)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "邀请码无效或已使用"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	res, err := h.Store.DB.Exec(`INSERT INTO users(username, password) VALUES(?,?)`, req.Username, string(hash))
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}
	h.Store.DB.Exec(`UPDATE invites SET used_by=(SELECT id FROM users WHERE username=?) WHERE id=?`,
		req.Username, id)
	uid, _ := res.LastInsertId()
	var domainID int64
	var domain string
	h.Store.DB.QueryRow(`SELECT id, domain FROM domains ORDER BY id LIMIT 1`).Scan(&domainID, &domain)
	if domainID > 0 {
		h.Store.DB.Exec(`INSERT INTO mailboxes(user_id, address, domain_id, password) VALUES(?,?,?,?)`,
			uid, req.Username+"@"+domain, domainID, string(hash))
	}
	h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, ip) VALUES(?, 'register', ?)`, uid, c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"ok": true, "address": req.Username + "@" + domain})
}

// AppPasswords GET/POST/DELETE /api/v1/mailboxes/:id/app_passwords（D2）
func (h *MailHandler) AppPasswords(c *gin.Context) {
	uid := c.GetInt64("user_id")
	mbID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if !h.Store.OwnsMailbox(mbID, uid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问"})
		return
	}
	switch c.Request.Method {
	case http.MethodPost:
		var req struct {
			Label string `json:"label" binding:"required"`
		}
		if c.ShouldBindJSON(&req) != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
			return
		}
		pwd := randCode(20)
		hash, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
		h.Store.DB.Exec(`INSERT INTO app_passwords(mailbox_id, label, password_hash) VALUES(?,?,?)`,
			mbID, req.Label, string(hash))
		c.JSON(http.StatusOK, gin.H{"password": pwd})
	case http.MethodDelete:
		id, _ := strconv.ParseInt(c.Query("pid"), 10, 64)
		h.Store.DB.Exec(`DELETE FROM app_passwords WHERE id=? AND mailbox_id=?`, id, mbID)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	default:
		rows, err := h.Store.DB.Query(`SELECT id, label, COALESCE(last_used,''), created_at
			FROM app_passwords WHERE mailbox_id=?`, mbID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var id int64
			var label, lastUsed, created string
			rows.Scan(&id, &label, &lastUsed, &created)
			items = append(items, map[string]any{"id": id, "label": label, "last_used": lastUsed, "created_at": created})
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	}
}
