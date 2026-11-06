package store

import (
	"crypto/subtle"
	"log"

	"golang.org/x/crypto/bcrypt"
)

// maxLegacyBcryptChecks 一次认证里最多比对多少个「旧式」令牌（只有 bcrypt 哈希、
// 没有密文的历史行）。
//
// 新令牌走「解密 + 定长比较」，成本是微秒级，数量再多也不影响一次登录；
// 但历史行的 bcrypt 每次约 50ms，一个账号挂几十个就会把一个登录请求拖到几秒，
// 既慢又能被用来打 CPU。这里只对旧行设上限，并在超出时留日志提示重新生成。
const maxLegacyBcryptChecks = 10

// dummyHash 是真实的 cost-10 哈希，用于补齐空槽位与空转。
const dummyHash = "$2a$10$BGDCnqjABEAOAVObzz.cXuCI5aOdnZEuuv/f9QFTZrrixVl6uAX4G"

// burnMainHash 空转一次 bcrypt。
//
// 账号不存在 / 已停用 / 查库失败时也要付与真实校验同等的 CPU 成本，
// 否则「有效邮箱」的失败响应会比「无效邮箱」快一个数量级而被枚举。
// 主密码校验本身就是一次 bcrypt，所以这里空转一次即可对齐。
func burnMainHash() {
	bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte("unused-constant-dummy-x"))
}

// appPassword 一份 App 专用密码。
type appPassword struct {
	id     int64
	hash   string // 历史数据只有 bcrypt 哈希
	secret string // 新数据额外存密文，用于 Web 回显
}

// VerifyMailboxAuth 协议层认证（D2：Web 密码或 App 专用密码）。
func (s *Store) VerifyMailboxAuth(address, password string) (*Mailbox, bool) {
	// bcrypt 只用前 72 字节，更长的口令会在 ExpandKeyWithSalt 里线性放大 CPU；
	// 放在查库之前早拒，避免一次认证就能打满 CPU。
	if len(password) == 0 || len(password) > 72 {
		burnMainHash()
		return nil, false
	}
	mb, err := s.MailboxByAddress(address)
	if err != nil || mb == nil {
		burnMainHash()
		return nil, false
	}
	// 账号被管理员停用时，Web 侧会立刻 401，但协议侧（IMAP/POP3/SMTP）原本不受影响，
	// 等于停用只挡住了网页。这里统一按 users.status 判定，App 专用密码一并失效。
	var status string
	if err := s.DB.QueryRow(`SELECT status FROM users WHERE id=?`, mb.UserID).Scan(&status); err != nil || status != "active" {
		burnMainHash()
		return nil, false
	}
	var mainHash string
	if err := s.DB.QueryRow(`SELECT password FROM mailboxes WHERE id=?`, mb.ID).Scan(&mainHash); err != nil {
		burnMainHash()
		return nil, false
	}
	if bcrypt.CompareHashAndPassword([]byte(mainHash), []byte(password)) == nil {
		return mb, true
	}
	// 令牌数量不设上限：新令牌是「解密 + 定长比较」，再多的成本也可以忽略。
	// 只有历史 hash-only 行仍走 bcrypt，为了不让一次登录被拖成几秒，
	// 这类行最多比对 maxLegacyBcryptChecks 个（超出会打日志提醒重新生成）。
	matched := int64(0)
	legacySeen := 0
	for _, t := range s.appPasswords(mb) {
		if t.secret == "" {
			legacySeen++
			if legacySeen > maxLegacyBcryptChecks {
				if legacySeen == maxLegacyBcryptChecks+1 {
					log.Printf("app_passwords 账号 user=%d 的旧式令牌（无密文）过多，本次只比对最近 %d 个；请到 Web 端重新生成以恢复可回显与快速校验",
						mb.UserID, maxLegacyBcryptChecks)
				}
				continue
			}
		}
		if s.appPasswordMatch(t, password) {
			matched = t.id
			break
		}
	}
	if matched == 0 {
		return nil, false
	}
	if _, err := s.DB.Exec(`UPDATE app_passwords SET last_used=datetime('now') WHERE id=?`, matched); err != nil {
		log.Printf("app_passwords 更新 last_used 失败 id=%d mailbox=%d: %v", matched, mb.ID, err)
	}
	return mb, true
}

// appPasswordMatch 比对一份令牌。
//
//   - 新数据带密文：解密后做定长比较（令牌是 20 位随机串，~99 bit 熵，
//     不需要 bcrypt 的抗暴力特性，快速比对即可）；
//   - 历史数据只有 bcrypt 哈希：退回慢比对，仍可正常登录，只是不能回显；
//   - 密文存在但解不开（密钥被换/丢失）：记日志并退回哈希比对，不让令牌整体失效。
func (s *Store) appPasswordMatch(t appPassword, password string) bool {
	if t.secret != "" && s.Enc != nil {
		if plain, err := s.Enc.Decrypt(t.secret); err == nil {
			return subtle.ConstantTimeCompare([]byte(plain), []byte(password)) == 1
		} else {
			log.Printf("app_passwords 密文解密失败 id=%d: %v", t.id, err)
		}
	}
	if t.hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(t.hash), []byte(password)) == nil
}

// appPasswords 取「本次登录的那个邮箱」名下的 App 专用密码（严格一对一）。
//
// 一份令牌只属于生成它的那个邮箱：拿 A 邮箱的令牌去登同账号的 B 邮箱必须失败。
// 主密码另算——那是 Web 口令，同一用户的所有邮箱共用同一个哈希，能登全部邮箱；
// 两者的作用域本就不同，不要在认证逻辑里混为一谈。
//
// 因为作用域严格到邮箱，界面必须显示/可选择「令牌归属哪个邮箱」，
// 否则用户很容易在默认邮箱下生成、却拿另一个地址去配客户端，
// 看到的现象就是「独立密码怎么都不对、普通密码反而正常」。
func (s *Store) appPasswords(mb *Mailbox) []appPassword {
	// DB 抖动时不要静默退化成「只认主密码」——那正是这个 bug 的观感。
	// 重试一次再放弃，并且必须留下日志。
	for attempt := 0; attempt < 2; attempt++ {
		list, err := s.queryAppPasswords(mb)
		if err == nil {
			return list
		}
		log.Printf("app_passwords 查询失败 mailbox=%d user=%d attempt=%d: %v", mb.ID, mb.UserID, attempt+1, err)
	}
	return nil
}

func (s *Store) queryAppPasswords(mb *Mailbox) ([]appPassword, error) {
	// 新的优先（id 倒序）：常见场景是刚生成的那个令牌正在被配置进客户端。
	rows, err := s.DB.Query(`SELECT id, password_hash, secret FROM app_passwords
		WHERE mailbox_id = ? ORDER BY id DESC`, mb.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]appPassword, 0, 8)
	for rows.Next() {
		var t appPassword
		if err := rows.Scan(&t.id, &t.hash, &t.secret); err != nil {
			log.Printf("app_passwords 扫描失败 mailbox=%d: %v", mb.ID, err)
			continue
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// AppPasswordCountOfUser 返回某账号名下（全部邮箱合计）已有的 App 密码数量。
// 只用于前端展示/审计，不再作为创建上限。
func (s *Store) AppPasswordCountOfUser(userID int64) int {
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM app_passwords ap
		JOIN mailboxes m ON m.id = ap.mailbox_id WHERE m.user_id=?`, userID).Scan(&n); err != nil {
		log.Printf("app_passwords 计数失败 user=%d: %v", userID, err)
		return 0
	}
	return n
}
