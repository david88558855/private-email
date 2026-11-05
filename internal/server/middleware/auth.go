package middleware

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Auth JWT 鉴权中间件，解析并注入 user_id / role。
// 每次请求回查用户状态：账号被禁用或删除后 token 立即失效，不必等 24h 过期。
func Auth(secret string, db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			DrainBody(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		tok, err := jwt.Parse(h[7:], func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(secret), nil
		}, jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}))
		if err != nil || !tok.Valid {
			DrainBody(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		uidF, ok := claims["uid"].(float64)
		if !ok || uidF <= 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		uid := int64(uidF)
		// 角色与状态以库为准，避免令牌签发后权限变化不生效
		var status, role string
		if err := db.QueryRow(`SELECT status, role FROM users WHERE id=?`, uid).Scan(&status, &role); err != nil || status != "active" {
			DrainBody(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("user_id", uid)
		c.Set("role", role)
		c.Next()
	}
}
