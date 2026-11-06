package mailutil

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func gbk(s string) []byte {
	b, _ := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(s))
	return b
}

// TestExtractCodeLongBody 长正文里的自定义规则不能因为超过 4096 字符被整体跳过。
// 原实现 `if len(text) > 4096 { continue }` 让所有自定义规则 100% 失效。
func TestExtractCodeLongBody(t *testing.T) {
	long := strings.Repeat("这是一段很长的营销文案，", 2000) // ~78KB，低于 256KB 截断线
	long += " 您的验证码是 778899。"

	if got := ExtractCodeWith(long, []string{`验证码是\s*([0-9]{6})`}); got != "778899" {
		t.Fatalf("custom rule on long text: got=%q want=778899", got)
	}
}

func TestExtractCodeDefault(t *testing.T) {
	cases := map[string]string{
		"您的验证码是 482913，5分钟内有效。":     "482913",
		"Verification code: 998877": "998877",
		"482913 是本次登录验证码":           "482913",
		"没有数字":                      "",
	}
	for text, want := range cases {
		if got := ExtractCodeWith(text, nil); got != want {
			t.Errorf("ExtractCode(%q)=%q want %q", text, got, want)
		}
	}
}

// TestParseGBK GBK 邮件的主题与正文必须能解码（原来正文为空、主题还是 encoded-word）。
func TestParseGBK(t *testing.T) {
	subject := "=?gbk?B?" + base64.StdEncoding.EncodeToString(gbk("GBK主题测试")) + "?="
	raw := []byte("From: gbk@test.test\r\n" +
		"To: alice@example.test\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=gbk\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	raw = append(raw, gbk("这是一封GBK邮件，验证码 654321\r\n")...)

	p := Parse(raw)
	if !strings.Contains(p.TextBody, "验证码 654321") {
		t.Fatalf("gbk body=%q", p.TextBody)
	}
	if p.Subject != "GBK主题测试" {
		t.Fatalf("subject=%q", p.Subject)
	}
	if p.CharsetFallback {
		t.Fatal("unexpected fallback")
	}
}

// TestStripHTML 纯 HTML 邮件要能抽出可搜索的纯文本。
func TestStripHTML(t *testing.T) {
	got := StripHTML("<p>您的验证码是&nbsp;<b>123456</b></p>")
	if !strings.Contains(got, "123456") || strings.Contains(got, "<") {
		t.Fatalf("got=%q", got)
	}
}
