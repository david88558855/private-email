// Package authlimit 协议层认证失败限速（SMTP/IMAP/POP3）。
//
// Web 登录有中间件限速，但协议端口之前没有：攻击者可以对着 25/143/110 端口
// 持续试密码，每次只付一次 bcrypt 的成本，却能无限次尝试。
// 这里按「来源 IP」记失败次数，成功即清零；超限后直接拒绝，不再进入 bcrypt。
package authlimit

import (
	"sync"
	"time"
)

const (
	// MaxFails 单个窗口内允许的失败次数
	MaxFails = 10
	// Window 计数窗口
	Window = 5 * time.Minute
	// maxEntries 防止 map 随攻击者伪造来源无限增长
	maxEntries = 20000
)

type bucket struct {
	fails int
	reset time.Time
}

var (
	mu   sync.Mutex
	seen = map[string]*bucket{}
)

// Allow 判断该来源是否还能继续尝试认证（在验证密码之前调用）。
func Allow(key string) bool {
	mu.Lock()
	defer mu.Unlock()
	b, ok := seen[key]
	now := time.Now()
	if !ok || now.After(b.reset) {
		seen[key] = &bucket{fails: 0, reset: now.Add(Window)}
		return true
	}
	return b.fails < MaxFails
}

// Fail 记一次失败并返回剩余可用次数（<=0 表示已封禁）。
func Fail(key string) int {
	mu.Lock()
	defer mu.Unlock()
	b, ok := seen[key]
	now := time.Now()
	if !ok || now.After(b.reset) {
		b = &bucket{reset: now.Add(Window)}
		seen[key] = b
	}
	b.fails++
	if len(seen) > maxEntries {
		sweepLocked(now)
	}
	return MaxFails - b.fails
}

// Reset 认证成功后清零该来源的失败计数。
func Reset(key string) {
	mu.Lock()
	delete(seen, key)
	mu.Unlock()
}

// sweepLocked 清理过期条目（调用方需持锁）。
func sweepLocked(now time.Time) {
	for k, b := range seen {
		if now.After(b.reset) {
			delete(seen, k)
		}
	}
}
