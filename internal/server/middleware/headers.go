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

// SecurityHeaders 基础安全响应头。
// CSP 是最后一道 XSS 兜底：前端用了内联 onclick，所以 script-src 必须
// 保留 'unsafe-inline'；其余指令一律收紧到同源。
func SecurityHeaders() gin.HandlerFunc {
	const csp = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: blob:; " +
		"font-src 'self' data:; " +
		"connect-src 'self'; " +
		"frame-src 'self' data: blob:; " +
		"object-src 'none'; base-uri 'none'; form-action 'self'"
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", csp)
		c.Next()
	}
}
