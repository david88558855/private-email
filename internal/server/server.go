// Package server 组装 HTTP 服务：API 路由 + 内嵌前端静态资源（go:embed 单文件交付）。
package server

import (
	"database/sql"
	"io/fs"
	"net/http"

	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/server/handlers"
	"github.com/david88558855/private-email/internal/server/middleware"
	"github.com/david88558855/private-email/internal/web"
	"github.com/gin-gonic/gin"
)

func New(db *sql.DB, cfg *config.Config) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	auth := &handlers.AuthHandler{DB: db, Config: cfg}
	api := r.Group("/api/v1")
	api.POST("/auth/login", auth.Login)
	authed := api.Group("", middleware.Auth(cfg.Security.JWTSecret))
	authed.GET("/me", auth.Me)

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
