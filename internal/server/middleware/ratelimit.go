package middleware

import (
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// LoginRateLimit 登录限速：每 IP 每分钟 max 次尝试（内存实现，重启清零）。
func LoginRateLimit(max int) gin.HandlerFunc {
	type bucket struct {
		count int
		reset time.Time
	}
	var mu sync.Mutex
	var seen = map[string]*bucket{}
	return func(c *gin.Context) {
		ip := c.ClientIP()
		mu.Lock()
		b, ok := seen[ip]
		now := time.Now()
		if !ok || now.After(b.reset) {
			seen[ip] = &bucket{1, now.Add(time.Minute)}
			mu.Unlock()
			c.Next()
			return
		}
		b.count++
		over := b.count > max
		mu.Unlock()
		if over {
			// 先排干请求体再拒绝：否则连接带着未读数据关闭会回 RST，客户端拿不到 429
			io.Copy(io.Discard, io.LimitReader(c.Request.Body, 4096))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "尝试过于频繁，请稍后再试"})
			return
		}
		c.Next()
	}
}
