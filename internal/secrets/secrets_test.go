package secrets

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRoundTrip 加解密往返；同一明文两次加密必须得到不同密文（nonce 随机）。
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	const tok = "abcdefghjk23456789ab"
	enc1, err := c.Encrypt(tok)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	enc2, _ := c.Encrypt(tok)
	if enc1 == enc2 {
		t.Fatal("两次加密密文相同：nonce 未随机化")
	}
	if strings.Contains(enc1, tok) {
		t.Fatal("密文里出现了明文")
	}
	got, err := c.Decrypt(enc1)
	if err != nil || got != tok {
		t.Fatalf("decrypt=%q err=%v", got, err)
	}
	// 重新加载（模拟重启）必须能解开旧密文
	c2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got, err := c2.Decrypt(enc1); err != nil || got != tok {
		t.Fatalf("重启后 decrypt=%q err=%v", got, err)
	}
	// 密钥文件权限不能放开（Windows 不支持 POSIX 权限位，只在类 Unix 上校验）
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dir, keyFile))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("密钥文件权限过宽: %v", fi.Mode().Perm())
		}
	}
}

// TestCorruptKeyFailsLoudly 密钥损坏必须报错，不能静默重建（否则历史密文全废）。
func TestCorruptKeyFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keyFile), []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("损坏的密钥文件被静默接受")
	}
}

// TestWrongKeyCannotDecrypt 换一把密钥不能解开旧密文。
func TestWrongKeyCannotDecrypt(t *testing.T) {
	c1, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c2, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := c1.Encrypt("secret-token")
	if _, err := c2.Decrypt(enc); err == nil {
		t.Fatal("错误密钥解开了密文")
	}
}
