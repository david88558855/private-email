package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BodyLimit 限制请求体大小：gin 默认不限长，超大 JSON 会在解析前就把内存吃掉。
func BodyLimit(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if max > 0 {
			if c.Request.ContentLength > max {
				c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "请求体过大"})
				return
			}
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		}
		c.Next()
	}
}
