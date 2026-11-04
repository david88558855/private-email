// Package server 组装 HTTP 服务：API 路由 + 内嵌前端静态资源（go:embed 单文件交付）。
package server

import (
	"database/sql"
	"io/fs"
	"net/http"

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
	r.Use(gin.Recovery())

	auth := &handlers.AuthHandler{DB: db, Config: cfg}
	api := r.Group("/api/v1")
	api.POST("/auth/login", middleware.LoginRateLimit(cfg.Security.LoginRate), auth.Login)
	authed := api.Group("", middleware.Auth(cfg.Security.JWTSecret))
	authed.GET("/me", auth.Me)

	mail := &handlers.MailHandler{Store: st}
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
	authed.GET("/admin/settings", mail.Settings)
	authed.PUT("/admin/settings", mail.SettingsPut)
	authed.GET("/admin/stats", mail.Stats)
	authed.GET("/mailboxes/:id/app_passwords", mail.AppPasswords)
	authed.POST("/mailboxes/:id/app_passwords", mail.AppPasswords)
	authed.DELETE("/mailboxes/:id/app_passwords", mail.AppPasswords)
	api.POST("/auth/register", mail.Register)
	api.GET("/settings", mail.PublicSettings)

	// 内嵌前端：SPA 回退到 index.html
	dist, _ := fs.Sub(web.Dist, "dist")
	r.NoRoute(func(c *gin.Context) {
		if len(c.Request.URL.Path) > 4 && c.Request.URL.Path[:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.FileFromFS(c.Request.URL.Path, http.FS(dist))
	})
	return r
}
