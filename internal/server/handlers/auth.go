package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/david88558855/private-email/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	DB     *sql.DB
	Config *config.Config
}

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login Web 登录，签发 24h JWT。
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	var id int64
	var hash, role, status string
	err := h.DB.QueryRow(`SELECT id, password, role, status FROM users WHERE username = ?`,
		req.Username).Scan(&id, &hash, &role, &status)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	if status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "账号已禁用"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	claims := jwt.MapClaims{"uid": id, "role": role, "exp": time.Now().Add(24 * time.Hour).Unix()}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(h.Config.Security.JWTSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	h.DB.Exec(`INSERT INTO audit_logs(user_id, action, ip) VALUES(?,?,?)`,
		id, "login", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"token": tok, "role": role})
}

// Me 当前登录用户信息。
func (h *AuthHandler) Me(c *gin.Context) {
	uid := c.GetInt64("user_id")
	var username, role string
	if err := h.DB.QueryRow(`SELECT username, role FROM users WHERE id = ?`, uid).
		Scan(&username, &role); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": uid, "username": username, "role": role})
}
