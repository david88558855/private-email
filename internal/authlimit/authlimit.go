// Package authlimit 协议层认证失败限速（SMTP/IMAP/POP3）。
//
// Web 登录有中间件限速，但协议端口之前没有：攻击者可以对着 25/143/110 端口
// 持续试密码，每次只付一次 bcrypt 的成本，却能无限次尝试。
// 这里按「来源 IP」记失败次数，成功即清零；超限后直接拒绝，不再进入 bcrypt。
package authlimit

import (
	"strings"
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
	// 账号维度阈值更宽：按 IP 10 次/5 分钟已经挡住了单机爆破，
	// 账号维度只用于拦截分布式撞库；阈值太低会让攻击者用 10 个错误密码
	// 就把受害者账号锁死（DoS）。
	MaxFailsAccount = 100
	WindowAccount   = 15 * time.Minute
)

type bucket struct {
	fails int
	reset time.Time
}

var (
	mu        sync.Mutex
	seen      = map[string]*bucket{}
	lastSweep time.Time
)

// reserveSlotLocked 防止 seen 被伪造来源（acct:<任意用户名>）无限撑大。
// 达到上限时先清过期项（全表扫描最多每分钟一次），仍满则拒绝新条目（fail-closed）。
func reserveSlotLocked(now time.Time) bool {
	if len(seen) < maxEntries {
		return true
	}
	if now.Sub(lastSweep) > time.Minute {
		sweepLocked(now)
		lastSweep = now
	}
	return len(seen) < maxEntries
}

// limits 按 key 前缀选择阈值。
func limits(key string) (int, time.Duration) {
	if strings.HasPrefix(key, "acct:") {
		return MaxFailsAccount, WindowAccount
	}
	return MaxFails, Window
}

// Allow 判断该来源是否还能继续尝试认证（在验证密码之前调用）。
func Allow(key string) bool {
	mu.Lock()
	defer mu.Unlock()
	max, window := limits(key)
	b, ok := seen[key]
	now := time.Now()
	if !ok || now.After(b.reset) {
		if !reserveSlotLocked(now) {
			return false
		}
		seen[key] = &bucket{fails: 0, reset: now.Add(window)}
		return true
	}
	return b.fails < max
}

// Fail 记一次失败并返回剩余可用次数（<=0 表示已封禁）。
func Fail(key string) int {
	mu.Lock()
	defer mu.Unlock()
	max, window := limits(key)
	b, ok := seen[key]
	now := time.Now()
	if !ok || now.After(b.reset) {
		if !reserveSlotLocked(now) {
			return 0
		}
		b = &bucket{reset: now.Add(window)}
		seen[key] = b
	}
	b.fails++
	return max - b.fails
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
