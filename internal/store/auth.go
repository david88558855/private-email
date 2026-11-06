package store

import (
	"log"

	"golang.org/x/crypto/bcrypt"
)

// MaxAppPasswords 单个邮箱允许的 App 专用密码上限。
//
// 认证时是逐个 bcrypt 比对的（cost 10，约 50ms/次），没有上限时
// 一个用户挂 10 个密码，一次失败登录就要烧 0.5 秒 CPU；攻击者从
// 多个 IP 打同一个地址就能把 CPU 打满（IP 限速挡不住）。
const MaxAppPasswords = 5

// authHashSlots 固定比较槽位：主密码 1 个 + 最多 5 个 App 专用密码。
// 账号不存在/停用/查库失败时也跑满同样次数，否则「有效邮箱」会因耗时
// 比「无效邮箱」长几十倍而被枚举。
const authHashSlots = MaxAppPasswords + 1

// dummyHash 是真实的 cost-10 哈希，用于补齐空槽位与空转。
const dummyHash = "$2a$10$BGDCnqjABEAOAVObzz.cXuCI5aOdnZEuuv/f9QFTZrrixVl6uAX4G"

func burnHashes() {
	// 返回值必定不相等，故意丢弃：只为消耗固定次数的 bcrypt 计算。
	for i := 0; i < authHashSlots; i++ {
		bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte("unused-constant-dummy-x"))
	}
}

// VerifyMailboxAuth 协议层认证（D2：Web 密码或 App 专用密码）。
func (s *Store) VerifyMailboxAuth(address, password string) (*Mailbox, bool) {
	// bcrypt 只用前 72 字节，更长的口令会在 ExpandKeyWithSalt 里线性放大 CPU；
	// 放在查库之前早拒，避免一次认证就能打满 CPU。
	if len(password) == 0 || len(password) > 72 {
		burnHashes()
		return nil, false
	}
	mb, err := s.MailboxByAddress(address)
	if err != nil || mb == nil {
		burnHashes()
		return nil, false
	}
	// 账号被管理员停用时，Web 侧会立刻 401，但协议侧（IMAP/POP3/SMTP）原本不受影响，
	// 等于停用只挡住了网页。这里统一按 users.status 判定，App 专用密码一并失效。
	var status string
	if err := s.DB.QueryRow(`SELECT status FROM users WHERE id=?`, mb.UserID).Scan(&status); err != nil || status != "active" {
		burnHashes()
		return nil, false
	}
	var mainHash string
	if err := s.DB.QueryRow(`SELECT password FROM mailboxes WHERE id=?`, mb.ID).Scan(&mainHash); err != nil {
		burnHashes()
		return nil, false
	}
	hashes := []string{mainHash}
	rows, err := s.DB.Query(`SELECT password_hash FROM app_passwords WHERE mailbox_id=? ORDER BY id LIMIT ?`,
		mb.ID, MaxAppPasswords)
	if err != nil {
		log.Printf("app_passwords 查询失败 mailbox=%d: %v", mb.ID, err)
	} else {
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				log.Printf("app_passwords 扫描失败 mailbox=%d: %v", mb.ID, err)
				continue
			}
			hashes = append(hashes, h)
		}
		if err := rows.Err(); err != nil {
			log.Printf("app_passwords 迭代失败 mailbox=%d: %v", mb.ID, err)
		}
		rows.Close()
	}
	// 补齐到固定槽数：失败登录的耗时与该邮箱实际有几个 App 密码无关。
	for len(hashes) < authHashSlots {
		hashes = append(hashes, dummyHash)
	}
	matchedApp := ""
	ok := false
	for i := 0; i < authHashSlots; i++ {
		if bcrypt.CompareHashAndPassword([]byte(hashes[i]), []byte(password)) != nil {
			continue
		}
		ok = true
		if i > 0 {
			matchedApp = hashes[i]
		}
		// 成功可提前返回：成功与失败的耗时差不会泄露账号是否存在。
		break
	}
	if !ok {
		return nil, false
	}
	if matchedApp != "" {
		if _, err := s.DB.Exec(`UPDATE app_passwords SET last_used=datetime('now') WHERE password_hash=?`, matchedApp); err != nil {
			log.Printf("app_passwords 更新 last_used 失败 mailbox=%d: %v", mb.ID, err)
		}
	}
	return mb, true
}

// AppPasswordCount 返回某邮箱已有的 App 密码数量（创建前校验上限）。
// 查询失败时按「已满」处理：否则会写入第 6 个密码，而认证只比前 5 个，静默失效。
func (s *Store) AppPasswordCount(mailboxID int64) int {
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM app_passwords WHERE mailbox_id=?`, mailboxID).Scan(&n); err != nil {
		log.Printf("app_passwords 计数失败 mailbox=%d: %v", mailboxID, err)
		return MaxAppPasswords
	}
	return n
}
