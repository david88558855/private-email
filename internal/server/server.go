// Package server 组装 HTTP 服务：API 路由 + 内嵌前端静态资源（go:embed 单文件交付）。
package server

import (
	"database/sql"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/server/handlers"
	"github.com/david88558855/private-email/internal/server/middleware"
	"github.com/david88558855/private-email/internal/store"
	"github.com/david88558855/private-email/internal/web"
	"github.com/gin-gonic/gin"
)

func New(db *sql.DB, cfg *config.Config, st *store.Store) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(middleware.SecurityHeaders(), gin.Recovery())
	// 不信任任何代理头：否则 X-Forwarded-For 可伪造，登录限速形同虚设
	_ = r.SetTrustedProxies(nil)

	auth := &handlers.AuthHandler{DB: db, Config: cfg}
	api := r.Group("/api/v1")
	// 请求体上限：单封上限的 2 倍（正文 base64 膨胀 + JSON 转义余量）
	bodyMax := cfg.SMTP.MaxSize * 1024 * 1024 * 2
	if bodyMax <= 0 {
		bodyMax = 50 * 1024 * 1024
	}
	api.Use(middleware.BodyLimit(bodyMax))
	api.POST("/auth/login", middleware.LoginRateLimit(cfg.Security.LoginRate), auth.Login)
	authed := api.Group("", middleware.Auth(cfg.Security.JWTSecret, db))
	authed.GET("/me", auth.Me)
	authed.POST("/me/password", auth.ChangePassword)

	mail := &handlers.MailHandler{Store: st, Config: cfg}
	authed.GET("/mailboxes", mail.Mailboxes)
	authed.GET("/mailboxes/:id/folders", mail.Folders)
	authed.GET("/folders/:id/mails", mail.List)
	authed.GET("/mails/:id", mail.Get)
	authed.GET("/mails/:id/raw", mail.Raw)
	authed.PATCH("/mails/:id", mail.Patch)
	authed.DELETE("/mails/:id", mail.Delete)
	authed.POST("/mailboxes/:id/compose", mail.Compose)
	authed.GET("/queue", mail.Queue)

	// 管理端（M5）
	authed.GET("/admin/users", mail.Users)
	authed.POST("/admin/users", mail.UserAdd)
	authed.PATCH("/admin/users/:id", mail.UserPatch)
	authed.GET("/admin/domains", mail.Domains)
	authed.POST("/admin/domains", mail.DomainAdd)
	authed.DELETE("/admin/domains/:id", mail.DomainDelete)
	authed.POST("/admin/domains/:id/verify", mail.DomainVerify)
	authed.GET("/admin/settings", mail.Settings)
	authed.PUT("/admin/settings", mail.SettingsPut)
	authed.GET("/domains", mail.DomainsList)
	authed.POST("/mailboxes", mail.MailboxCreate)
	authed.PATCH("/mailboxes/:id", mail.MailboxPatch)
	authed.GET("/dashboard", mail.Dashboard)
	authed.GET("/mailboxes/:id/rules", mail.Rules)
	authed.POST("/mailboxes/:id/rules", mail.Rules)
	authed.DELETE("/mailboxes/:id/rules", mail.Rules)
	authed.GET("/admin/ports", mail.Ports)
	authed.PUT("/admin/ports", mail.PortsPut)
	authed.GET("/admin/stats", mail.Stats)
	authed.GET("/mailboxes/:id/app_passwords", mail.AppPasswords)
	authed.POST("/mailboxes/:id/app_passwords", mail.AppPasswords)
	authed.DELETE("/mailboxes/:id/app_passwords", mail.AppPasswords)
	api.POST("/auth/register", middleware.LoginRateLimit(cfg.Security.LoginRate), mail.Register)
	api.GET("/settings", mail.PublicSettings)

	// 内嵌前端静态资源；dist 取不到时必须在启动期就暴露，否则全站 404 无线索。
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		log.Fatalf("内嵌前端资源不可用: %v", err)
	}
	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		// 精确匹配 /api 与 /api/ 前缀：原来的前缀判断会把 /apixxx 误判成 API，
		// 而 /api 本身反而落到静态分支。
		if p == "/api" || strings.HasPrefix(p, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.FileFromFS(p, http.FS(dist))
	})
	return r
}
