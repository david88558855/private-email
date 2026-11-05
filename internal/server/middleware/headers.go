package middleware

import (
	"io"

	"github.com/gin-gonic/gin"
)

// DrainBody 提前拒绝请求前排干请求体：带着未读数据关闭连接会触发 RST，
// 客户端只看到「连接被重置」而拿不到真正的 401/403。
func DrainBody(c *gin.Context) {
	if c.Request.Body != nil {
		io.Copy(io.Discard, io.LimitReader(c.Request.Body, 1<<16))
	}
}

// SecurityHeaders 基础安全响应头：防 MIME 嗅探、防被第三方页面套框、不外泄 Referer。
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		c.Next()
	}
}
