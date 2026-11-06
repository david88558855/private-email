package handlers

import (
	"context"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/outbound"
	"github.com/david88558855/private-email/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// adminOnly 中间件片段
func adminOK(c *gin.Context) bool {
	if c.GetString("role") != "admin" {
		middleware.DrainBody(c)
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
		if req.Op == "disable" {
			if id == c.GetInt64("user_id") {
				c.JSON(http.StatusBadRequest, gin.H{"error": "不能禁用当前登录的管理员账号"})
				return
			}
			// 至少保留一个启用的管理员，否则系统再也没人能进后台
			var role, status string
			h.Store.DB.QueryRow(`SELECT role, status FROM users WHERE id=?`, id).Scan(&role, &status)
			if role == "admin" && status == "active" {
				var others int
				h.Store.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND status='active' AND id<>?`, id).Scan(&others)
				if others == 0 {
					c.JSON(http.StatusBadRequest, gin.H{"error": "至少保留一个启用的管理员"})
					return
				}
			}
		}
		if _, err := h.Store.DB.Exec(`UPDATE users SET status=? WHERE id=?`, st, id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
			return
		}
	case "reset":
		if len(req.Password) < 6 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "密码至少 6 位"})
			return
		}
		hash, err := hashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "密码不合法（最多 72 字节）"})
			return
		}
		// users 与 mailboxes 必须同事务：否则改密成功而协议密码没同步，
		// 用户的 IMAP/POP3/SMTP 客户端会被静默踢下线。
		tx, err := h.Store.DB.Begin()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
			return
		}
		if _, err := tx.Exec(`UPDATE users SET password=? WHERE id=?`, hash, id); err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
			return
		}
		if _, err := tx.Exec(`UPDATE mailboxes SET password=? WHERE user_id=?`, hash, id); err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
			return
		}
		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "未知操作"})
		return
	}
	if _, err := h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, detail) VALUES(?,?,?)`,
		c.GetInt64("user_id"), "admin_"+req.Op, "user:"+c.Param("id")); err != nil {
		// 主操作已成功，审计失败只记日志，不改响应。
		log.Printf("审计日志写入失败: %v", err)
	}
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
	if !validUsername(req.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名仅限小写字母/数字/-/_，2-32 位"})
		return
	}
	if req.Role != "admin" {
		req.Role = "user"
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "密码不合法（最多 72 字节）"})
		return
	}
	res, err := h.Store.DB.Exec(`INSERT INTO users(username, password, role) VALUES(?,?,?)`,
		req.Username, hash, req.Role)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}
	uid, _ := res.LastInsertId()
	// 自动建邮箱 username@第一个域名（无域名时只建账号）
	var domainID int64
	var domain string
	h.Store.DB.QueryRow(`SELECT id, domain FROM domains WHERE status='verified' ORDER BY id LIMIT 1`).Scan(&domainID, &domain)
	address := ""
	if domainID > 0 {
		address = req.Username + "@" + domain
		if res, err := h.Store.DB.Exec(`INSERT INTO mailboxes(user_id, address, domain_id, password) VALUES(?,?,?,?)`,
			uid, address, domainID, string(hash)); err == nil {
			// 建库即初始化默认文件夹：否则该邮箱收不到信（投递找不到 INBOX），
			// 一直到用户首次用 IMAP/POP3 登录才被补上。
			if mbID, e := res.LastInsertId(); e == nil {
				if e := h.Store.EnsureFolders(mbID); e != nil {
					log.Printf("初始化文件夹失败 %s: %v", address, e)
				}
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "address": address})
}

// Domains GET /api/v1/admin/domains —— 含 DKIM DNS 记录展示
func (h *MailHandler) Domains(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	// 每次列域名前补一次密钥：幂等，成本是一条 SELECT。旧库里 pending 期间
	// 没生成过密钥的域名，在这里就能自动补上，不用重启进程。
	outbound.EnsureDKIMKeys(h.Store)
	rows, err := h.Store.DB.Query(`SELECT d.id, d.domain, d.status, d.created_at, COALESCE(d.verify_token,''),
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
		var domain, status, created, token, selector, key string
		rows.Scan(&id, &domain, &status, &created, &token, &selector, &key)
		item := map[string]any{"id": id, "domain": domain, "status": status, "created_at": created,
			"verify_token": token, "verify_host": "_private-email." + domain,
			"verify_value": "pe-verify=" + token}
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
	if !validDomain(req.Domain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名格式错误（仅允许字母/数字/连字符，需带顶级域）"})
		return
	}
	token := config.RandToken(32)
	status := "pending"
	if h.Config.Security.SkipDomainVerification {
		// 内网/测试部署可跳过 DNS 校验（配置项显式打开）
		status = "verified"
	}
	var err error
	if status == "verified" {
		_, err = h.Store.DB.Exec(`INSERT INTO domains(domain, status, dns_verified_at, verify_token)
			VALUES(?,?,datetime('now'),?)`, req.Domain, status, token)
	} else {
		_, err = h.Store.DB.Exec(`INSERT INTO domains(domain, status, verify_token) VALUES(?,?,?)`,
			req.Domain, status, token)
	}
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "域名已存在"})
		return
	}
	outbound.EnsureDKIMKeys(h.Store)
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": status,
		"verify_host": "_private-email." + req.Domain, "verify_value": "pe-verify=" + token})
}

// DomainVerify POST /api/v1/admin/domains/:id/verify
// 校验 DNS TXT 记录 _private-email.<domain> 是否等于 pe-verify=<token>。
// 通过后才允许在该域名下建邮箱；原来「添加即 verified」让 status 字段形同虚设。
func (h *MailHandler) DomainVerify(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	// force：管理员显式跳过 DNS 校验。自托管/内网/域名没托管在公网 DNS 的
	// 场景下，TXT 校验永远不可能通过，没有这条旁路就是功能死锁：域名卡在
	// pending，邮箱建不了，DKIM 也不出记录。强制通过写审计日志留痕。
	var req struct {
		Force bool `json:"force"`
	}
	_ = c.ShouldBindJSON(&req)
	var domain, token, status string
	if err := h.Store.DB.QueryRow(`SELECT domain, COALESCE(verify_token,''), status FROM domains WHERE id=?`, id).
		Scan(&domain, &token, &status); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "域名不存在"})
		return
	}
	if status == "verified" {
		c.JSON(http.StatusOK, gin.H{"ok": true, "status": "verified"})
		return
	}
	if req.Force {
		if _, err := h.Store.DB.Exec(`UPDATE domains SET status='verified', dns_verified_at=datetime('now') WHERE id=?`, id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
			return
		}
		outbound.EnsureDKIMKeys(h.Store)
		h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, detail) VALUES(?,?,?)`,
			c.GetInt64("user_id"), "domain_verify_force", domain)
		c.JSON(http.StatusOK, gin.H{"ok": true, "status": "verified", "forced": true})
		return
	}
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该域名缺少验证令牌，请删除后重新添加"})
		return
	}
	want := "pe-verify=" + token
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	records, err := net.DefaultResolver.LookupTXT(ctx, "_private-email."+domain)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DNS 查询失败：" + err.Error(),
			"verify_host": "_private-email." + domain, "verify_value": want})
		return
	}
	ok := false
	for _, r := range records {
		if strings.TrimSpace(r) == want {
			ok = true
			break
		}
	}
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TXT 记录未匹配",
			"verify_host": "_private-email." + domain, "verify_value": want,
			"found": records})
		return
	}
	if _, err := h.Store.DB.Exec(`UPDATE domains SET status='verified', dns_verified_at=datetime('now') WHERE id=?`, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}
	outbound.EnsureDKIMKeys(h.Store)
	h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, detail) VALUES(?,?,?)`,
		c.GetInt64("user_id"), "domain_verify", domain)
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": "verified"})
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

// Register POST /api/v1/auth/register {username, password} —— 受管理员注册开关控制（默认关闭）。
func (h *MailHandler) Register(c *gin.Context) {
	// 读失败时按「未开放」处理，避免在设置异常时意外放开注册。
	if reg, _ := h.Store.GetSetting("registration_enabled"); reg != "true" {
		c.JSON(http.StatusForbidden, gin.H{"error": "注册未开放"})
		return
	}
	var req struct {
		Username string `json:"username" binding:"required,min=2,max=32"`
		Password string `json:"password" binding:"required,min=6"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误（用户名 2-32 位，密码至少 6 位）"})
		return
	}
	if !validUsername(req.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名仅限小写字母/数字/-/_，2-32 位"})
		return
	}
	// 注册会自动建成 <username>@<域名>，所以保留字必须在建账号前挡住，
	// 否则自助注册就是绕过 MailboxCreate 保留字检查的后门。
	if reservedAddresses[strings.ToLower(req.Username)] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该用户名为系统保留"})
		return
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "密码不合法（最多 72 字节）"})
		return
	}
	res, err := h.Store.DB.Exec(`INSERT INTO users(username, password) VALUES(?,?)`, req.Username, hash)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}
	uid, _ := res.LastInsertId()
	var domainID int64
	var domain string
	h.Store.DB.QueryRow(`SELECT id, domain FROM domains WHERE status='verified' ORDER BY id LIMIT 1`).Scan(&domainID, &domain)
	if domainID > 0 {
		if res, err := h.Store.DB.Exec(`INSERT INTO mailboxes(user_id, address, domain_id, password) VALUES(?,?,?,?)`,
			uid, req.Username+"@"+domain, domainID, string(hash)); err == nil {
			if mbID, e := res.LastInsertId(); e == nil {
				h.Store.EnsureFolders(mbID) // 注册即初始化文件夹，否则收不到信
			}
		}
	}
	h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, ip) VALUES(?, 'register', ?)`, uid, c.ClientIP())
	// 注册即登录：签发 token
	claims := jwt.MapClaims{"uid": uid, "role": "user", "exp": time.Now().Add(24 * time.Hour).Unix()}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString([]byte(h.Config.Security.JWTSecret))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": true, "address": req.Username + "@" + domain})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "address": req.Username + "@" + domain, "token": token, "role": "user"})
}

// AppPasswords GET/POST/DELETE /api/v1/mailboxes/:id/app_passwords（D2）
//
// App 专用密码与邮箱是**一对一**的：认证侧严格按 mailbox_id 匹配
// （store.appPasswords），A 邮箱的令牌登不了同账号的 B 邮箱。
// 因此这里 GET/POST/DELETE 全部以 :id 这个邮箱为单位，
// 界面上也必须把「令牌属于哪个邮箱」显示出来。
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
		pwd, err := randCode(20)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成失败"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成失败"})
			return
		}
		// 密文用于「随时查看」；哈希保留给未升级的旧库/旧代码路径比对。
		// 加密器缺失（未配置密钥）时降级为只存哈希：令牌仍能登录，只是不能回显。
		secret := ""
		if h.Store.Enc != nil {
			if secret, err = h.Store.Enc.Encrypt(pwd); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "生成失败"})
				return
			}
		}
		if _, err := h.Store.DB.Exec(`INSERT INTO app_passwords(mailbox_id, label, password_hash, secret) VALUES(?,?,?,?)`,
			mbID, req.Label, string(hash), secret); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"password": pwd})
	case http.MethodDelete:
		id, _ := strconv.ParseInt(c.Query("pid"), 10, 64)
		h.Store.DB.Exec(`DELETE FROM app_passwords WHERE id=? AND mailbox_id=?`, id, mbID)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	default:
		rows, err := h.Store.DB.Query(`SELECT ap.id, ap.label, COALESCE(ap.last_used,''), ap.created_at,
			m.address, ap.secret FROM app_passwords ap JOIN mailboxes m ON m.id = ap.mailbox_id
			WHERE ap.mailbox_id=? ORDER BY ap.id DESC`, mbID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var id int64
			var label, lastUsed, created, mailbox, secret string
			rows.Scan(&id, &label, &lastUsed, &created, &mailbox, &secret)
			// 解密失败（密钥丢失/历史数据）时 password 为空，前端会提示「不可查看」，
			// 绝不能让整张列表 500。
			pwd := ""
			if h.Store.Enc != nil {
				if v, derr := h.Store.Enc.Decrypt(secret); derr != nil {
					log.Printf("app_passwords 解密失败 id=%d: %v", id, derr)
				} else {
					pwd = v
				}
			}
			items = append(items, map[string]any{"id": id, "label": label, "last_used": lastUsed,
				"created_at": created, "mailbox": mailbox, "password": pwd, "viewable": pwd != ""})
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	}
}
