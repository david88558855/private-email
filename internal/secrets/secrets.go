// Package secrets 管理「需要回显的凭据」的对称加密（AES-256-GCM）。
//
// App 专用密码要求用户随时可以在 Web 查看，所以不能再只存 bcrypt 单向哈希：
// 密文落库、明文只在内存里出现，密钥单独放在 data/keys/app.key（0600）。
// 这样单独泄露 db.sqlite 拿不到令牌；data 目录整体泄露才会同时失守，
// 备份时两者必须一起（README 有说明）。
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// KeyLen AES-256 密钥长度。
const KeyLen = 32

// keyFile 密钥文件名（十六进制文本，便于人工备份与核对）。
const keyFile = "app.key"

// Cipher 加解密器；nil 值不可用，调用方需判空。
type Cipher struct {
	aead cipher.AEAD
}

// LoadOrCreate 读取 <dir>/app.key，不存在则生成。
//
// 文件存在但内容不合法时必须报错而不是重建：重建会让历史密文全部作废，
// 用户手里的独立密码集体失效且无法察觉。
func LoadOrCreate(dir string) (*Cipher, error) {
	p := filepath.Join(dir, keyFile)
	raw, err := os.ReadFile(p)
	switch {
	case err == nil:
		key, derr := hex.DecodeString(trimSpace(string(raw)))
		if derr != nil || len(key) != KeyLen {
			return nil, fmt.Errorf("%s 内容损坏（需 %d 字节十六进制），请从备份恢复", p, KeyLen)
		}
		return New(key)
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("读取 %s 失败: %w", p, err)
	}
	key := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("生成密钥失败: %w", err)
	}
	// 先写临时文件再 rename：写入过程中崩溃不能留下半截密钥。
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("写入 %s 失败: %w", tmp, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("落盘 %s 失败: %w", p, err)
	}
	return New(key)
}

// New 用给定密钥构造加解密器。
func New(key []byte) (*Cipher, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("密钥长度 %d，需 %d", len(key), KeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt 返回 base64url(nonce||密文)，空串原样返回。
func (c *Cipher) Encrypt(plain string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("未配置加密器")
	}
	if plain == "" {
		return "", nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	// Seal 直接追加在 nonce 之后，解包时按 NonceSize 切开。
	out := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Decrypt 还原 Encrypt 的结果。
func (c *Cipher) Decrypt(enc string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("未配置加密器")
	}
	if enc == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	n := c.aead.NonceSize()
	if len(raw) <= n {
		return "", fmt.Errorf("密文长度异常")
	}
	plain, err := c.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
