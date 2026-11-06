package outbound

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/david88558855/private-email/internal/database"
	"github.com/david88558855/private-email/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "t.sqlite"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &store.Store{DB: db}
}

// 待验证域名也必须生成 DKIM 密钥。
// 回归场景：域名刚添加、TXT 还没生效时，后台应该已经能看到 DKIM 记录，
// 否则管理员要先验证再回头配 DKIM，中间界面一直显示"生成中"。
func TestEnsureDKIMKeysForPendingDomain(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.DB.Exec(`INSERT INTO domains(domain, status) VALUES('pending.test','pending')`); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	EnsureDKIMKeys(st)

	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM dkim_keys`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("pending 域名应生成 1 条密钥，实际 %d 条", n)
	}

	// 幂等：重复调用（每次列域名都会调）不能重复生成
	EnsureDKIMKeys(st)
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM dkim_keys`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("重复调用不应重复生成，实际 %d 条", n)
	}
}

// 生成的私钥必须能解析成 crypto.Signer，否则签名时才发现坏，太晚。
func TestDKIMKeyParsable(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.DB.Exec(`INSERT INTO domains(domain) VALUES('key.test')`); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	EnsureDKIMKeys(st)

	var pemStr, selector string
	if err := st.DB.QueryRow(`SELECT private_key, selector FROM dkim_keys LIMIT 1`).
		Scan(&pemStr, &selector); err != nil {
		t.Fatalf("query key: %v", err)
	}
	if selector != "default" {
		t.Fatalf("selector 应为 default，实际 %q", selector)
	}
	signer, err := parseDKIMKey([]byte(pemStr))
	if err != nil {
		t.Fatalf("私钥解析失败: %v", err)
	}
	if signer.Public() == nil {
		t.Fatal("公钥为空，无法生成 DNS 记录")
	}
}

// 有密钥时必须真的签出 DKIM-Signature，而不是静默返回原文。
// 之前 dkimSign 出错只 return raw，日志里完全看不出来，等于"签了个寂寞"。
func TestDKIMSignProducesSignature(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.DB.Exec(`INSERT INTO domains(domain, status) VALUES('sign.test','verified')`); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	EnsureDKIMKeys(st)

	w := &Worker{Store: st}
	raw := []byte("From: a@sign.test\r\nTo: b@example.test\r\nSubject: t\r\n" +
		"Date: Thu, 05 Nov 2026 21:00:00 +0800\r\nMessage-ID: <x@sign.test>\r\n\r\nbody 正文\r\n")
	out := w.dkimSign("a@sign.test", raw)
	s := string(out)
	for _, want := range []string{"DKIM-Signature:", "d=sign.test", "s=default"} {
		if !strings.Contains(s, want) {
			t.Fatalf("签名结果缺少 %q\n----\n%s", want, s)
		}
	}
	if !strings.Contains(s, "body 正文") {
		t.Fatal("签名后正文丢失")
	}
}

// 没有密钥的域必须原样返回，不能吞掉邮件。
func TestDKIMSignWithoutKey(t *testing.T) {
	st := newTestStore(t)
	w := &Worker{Store: st}
	raw := []byte("From: a@nokey.test\r\nTo: b@example.test\r\n\r\nbody\r\n")
	out := w.dkimSign("a@nokey.test", raw)
	if string(out) != string(raw) {
		t.Fatal("无密钥时应原样返回")
	}
}
