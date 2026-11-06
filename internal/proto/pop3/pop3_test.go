package pop3

import (
	"bytes"
	"strings"
	"testing"
)

// TestParsePlain 覆盖 RFC 4616 的 PLAIN 凭据格式与反向边界。
func TestParsePlain(t *testing.T) {
	ok := []struct {
		name, payload, user, pass string
	}{
		{"标准格式", "\x00user@example.test\x00secret", "user@example.test", "secret"},
		{"密码含冒号等符号", "\x00a@b.test\x00p:a s/s", "a@b.test", "p:a s/s"},
	}
	for _, c := range ok {
		u, p, err := parsePlain([]byte(c.payload))
		if err != nil || u != c.user || p != c.pass {
			t.Errorf("%s: got (%q,%q,%v)", c.name, u, p, err)
		}
	}
	bad := [][]byte{
		nil,                             // 空值
		[]byte("user\x00pass"),          // 缺 authzid 分隔
		[]byte("admin\x00user\x00pass"), // authzid 非空（禁止身份代理）
		[]byte("\x00\x00pass"),          // 用户名为空
		[]byte("\x00user\x00"),          // 密码为空
	}
	for _, b := range bad {
		if _, _, err := parsePlain(b); err == nil {
			t.Errorf("parsePlain(%q) 应报错", b)
		}
	}
}

// TestTopBody TOP n 必须返回头部 + 正文前 n 行（原实现忽略 n）。
func TestTopBody(t *testing.T) {
	raw := []byte("From: a@b.test\r\nSubject: x\r\n\r\nline1\r\nline2\r\nline3\r\nline4\r\n")
	got := string(topBody(raw, 2))
	if !strings.Contains(got, "Subject: x") {
		t.Fatalf("missing header: %q", got)
	}
	if !strings.Contains(got, "line1") || !strings.Contains(got, "line2") {
		t.Fatalf("missing body lines: %q", got)
	}
	if strings.Contains(got, "line3") {
		t.Fatalf("returned too many body lines: %q", got)
	}
	if !strings.Contains(got, "\r\n\r\n") {
		t.Fatalf("header/body separator lost: %q", got)
	}
}

// TestDotStuff 行首点必须翻倍，且不能破坏已有内容。
func TestDotStuff(t *testing.T) {
	raw := []byte(".first\r\nnormal\r\n.dot\r\n")
	got := dotStuff(raw)
	want := []byte("..first\r\nnormal\r\n..dot\r\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}
