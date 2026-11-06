package store_test

import (
	"fmt"
	"testing"

	"github.com/david88558855/private-email/internal/secrets"
	"github.com/david88558855/private-email/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// withCipher 给 store 挂上加解密器（生产由 main.go 注入）。
func withCipher(t *testing.T, s *store.Store) *secrets.Cipher {
	t.Helper()
	c, err := secrets.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	s.Enc = c
	return c
}

// seedUserWithMailboxes 建一个用户 + 若干邮箱，邮箱密码统一为该用户的主密码哈希
// （与 D2 一致：一个用户的所有邮箱共用同一个主密码哈希）。
func seedUserWithMailboxes(t *testing.T, s *store.Store, user string, mainPwd string, addrs ...string) int64 {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(mainPwd), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	res, err := s.DB.Exec(`INSERT INTO users(username, password) VALUES(?,?)`, user, string(hash))
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	uid, _ := res.LastInsertId()
	for _, a := range addrs {
		if _, err := s.DB.Exec(`INSERT INTO mailboxes(user_id, address, domain_id, password) VALUES(?,?,1,?)`,
			uid, a, string(hash)); err != nil {
			t.Fatalf("mailbox %s: %v", a, err)
		}
	}
	return uid
}

func mailboxID(t *testing.T, s *store.Store, addr string) int64 {
	t.Helper()
	var id int64
	if err := s.DB.QueryRow(`SELECT id FROM mailboxes WHERE address=?`, addr).Scan(&id); err != nil {
		t.Fatalf("mailbox id %s: %v", addr, err)
	}
	return id
}

// addAppPassword 模拟 Web 端「生成」：哈希（兼容旧数据）+ 密文（用于回显），返回明文。
func addAppPassword(t *testing.T, s *store.Store, mbID int64, plain string) {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash app pwd: %v", err)
	}
	secret := ""
	if s.Enc != nil {
		if secret, err = s.Enc.Encrypt(plain); err != nil {
			t.Fatalf("encrypt app pwd: %v", err)
		}
	}
	if _, err := s.DB.Exec(`INSERT INTO app_passwords(mailbox_id, label, password_hash, secret) VALUES(?,?,?,?)`,
		mbID, "test", string(h), secret); err != nil {
		t.Fatalf("insert app pwd: %v", err)
	}
}

// TestAppPasswordIsPerMailbox 回归：App 专用密码与邮箱严格一对一。
//
// 一份令牌只能在生成它的那个邮箱上登录；同账号的另一个邮箱即便共用同一个
// 主密码哈希，也必须拒绝。这条同时也是对「误配」的保护：
// 界面必须让用户看清令牌属于哪个地址。
func TestAppPasswordIsPerMailbox(t *testing.T) {
	s := newStore(t)
	withCipher(t, s)
	const pwd = "main-secret"
	seedUserWithMailboxes(t, s, "alice", pwd, "alice@example.test", "alice-work@example.test")
	seedUserWithMailboxes(t, s, "bob", "bob-secret", "bob@example.test")

	addAppPassword(t, s, mailboxID(t, s, "alice@example.test"), "tokabcdefghjk234567")

	// 主密码是账号口令：本账号任一邮箱都可登录（既有行为，防回归）
	for _, addr := range []string{"alice@example.test", "alice-work@example.test"} {
		if _, ok := s.VerifyMailboxAuth(addr, pwd); !ok {
			t.Fatalf("主密码应可用于 %s", addr)
		}
	}
	// 独立密码只在颁发它的邮箱上有效，且返回的就是这个邮箱
	mb, ok := s.VerifyMailboxAuth("alice@example.test", "tokabcdefghjk234567")
	if !ok {
		t.Fatal("独立密码应可用于颁发它的邮箱")
	}
	if mb.Address != "alice@example.test" {
		t.Fatalf("登录 alice 却返回 %s", mb.Address)
	}
	// 同账号的另一个邮箱必须拒绝（一对一）
	if _, ok := s.VerifyMailboxAuth("alice-work@example.test", "tokabcdefghjk234567"); ok {
		t.Fatal("独立密码不得用于同账号的其它邮箱")
	}
	// 别的账号更不能被这份令牌登进来
	if _, ok := s.VerifyMailboxAuth("bob@example.test", "tokabcdefghjk234567"); ok {
		t.Fatal("独立密码不得跨账号生效")
	}
	// 错误口令必须拒绝
	if _, ok := s.VerifyMailboxAuth("alice@example.test", "tokwrongwrongwrong1"); ok {
		t.Fatal("错误独立密码被放行")
	}
}

// TestAppPasswordSecretPath 密文比对路径：即使哈希被人为写坏，凭密文也能登录。
// 证明新写入的令牌走的是「解密 + 定长比较」，不依赖 bcrypt。
func TestAppPasswordSecretPath(t *testing.T) {
	s := newStore(t)
	c := withCipher(t, s)
	seedUserWithMailboxes(t, s, "anna", "anna-secret", "anna@example.test")
	secret, err := c.Encrypt("toksecretpath234567")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO app_passwords(mailbox_id, label, password_hash, secret) VALUES(?,?,?,?)`,
		mailboxID(t, s, "anna@example.test"), "x", "not-a-bcrypt-hash", secret); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.VerifyMailboxAuth("anna@example.test", "toksecretpath234567"); !ok {
		t.Fatal("密文路径未生效")
	}
}

// TestAppPasswordLegacyHashOnly 升级前只有 bcrypt 哈希的老令牌必须继续可用（只是不能回显）。
func TestAppPasswordLegacyHashOnly(t *testing.T) {
	s := newStore(t)
	seedUserWithMailboxes(t, s, "legacy", "legacy-secret", "legacy@example.test")
	h, _ := bcrypt.GenerateFromPassword([]byte("toklegacy23456789ab"), bcrypt.DefaultCost)
	if _, err := s.DB.Exec(`INSERT INTO app_passwords(mailbox_id, label, password_hash) VALUES(?,?,?)`,
		mailboxID(t, s, "legacy@example.test"), "old", string(h)); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.VerifyMailboxAuth("legacy@example.test", "toklegacy23456789ab"); !ok {
		t.Fatal("历史令牌（仅哈希）应继续可用")
	}
}

// TestAppPasswordUndecryptableStillWorks 密钥被换掉时，密文解不开要退回哈希比对，
// 而不是让用户手里的令牌整体失效。
func TestAppPasswordUndecryptableStillWorks(t *testing.T) {
	s := newStore(t)
	withCipher(t, s)
	seedUserWithMailboxes(t, s, "rot", "rot-secret", "rot@example.test")
	addAppPassword(t, s, mailboxID(t, s, "rot@example.test"), "tokrotkey23456789ab")
	// 换一把密钥（模拟 data/keys 被替换）
	other, err := secrets.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Enc = other
	if _, ok := s.VerifyMailboxAuth("rot@example.test", "tokrotkey23456789ab"); !ok {
		t.Fatal("密钥更换后令牌不应整体失效（应退回哈希比对）")
	}
}

// TestAppPasswordDisabledUser App 专用密码随账号停用一起失效。
func TestAppPasswordDisabledUser(t *testing.T) {
	s := newStore(t)
	withCipher(t, s)
	uid := seedUserWithMailboxes(t, s, "carol", "carol-secret", "carol@example.test")
	addAppPassword(t, s, mailboxID(t, s, "carol@example.test"), "tokcarol23456789ab")

	if _, ok := s.VerifyMailboxAuth("carol@example.test", "tokcarol23456789ab"); !ok {
		t.Fatal("停用前独立密码应可用")
	}
	if _, err := s.DB.Exec(`UPDATE users SET status='disabled' WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.VerifyMailboxAuth("carol@example.test", "tokcarol23456789ab"); ok {
		t.Fatal("账号停用后独立密码仍被放行")
	}
}

// TestAppPasswordNoCountLimit 令牌数量不设上限：都能登录，也不依赖前 N 个槽位。
func TestAppPasswordNoCountLimit(t *testing.T) {
	s := newStore(t)
	withCipher(t, s)
	seedUserWithMailboxes(t, s, "dave", "dave-secret", "dave@example.test")
	mbID := mailboxID(t, s, "dave@example.test")

	const n = 12
	toks := make([]string, 0, n)
	for i := 0; i < n; i++ {
		tok := fmt.Sprintf("tok%02dabcdefghjk234", i)
		addAppPassword(t, s, mbID, tok)
		toks = append(toks, tok)
	}
	if got := s.AppPasswordCountOfUser(1); got != n {
		t.Fatalf("计数=%d want=%d", got, n)
	}
	for i, tok := range toks {
		if _, ok := s.VerifyMailboxAuth("dave@example.test", tok); !ok {
			t.Fatalf("第 %d 个令牌被拒绝（不应有数量上限）", i+1)
		}
	}
	if _, ok := s.VerifyMailboxAuth("dave@example.test", "tok-not-exists-00000"); ok {
		t.Fatal("不存在的令牌被放行")
	}
}
