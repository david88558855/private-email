package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

// hashPassword 统一口令哈希。bcrypt 只接受 ≤72 字节口令，超长时
// GenerateFromPassword 返回错误；旧代码丢弃该错误会把空哈希写进库，
// 账号与协议密码同时变空，用户永久无法登录。
func hashPassword(pw string) (string, error) {
	if len(pw) > 72 {
		return "", fmt.Errorf("密码过长（最多 72 字节）")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// randCode 生成 App 专用密码。CSPRNG 失败必须让接口报错，
// 否则会退化成全 'a' 的可预测口令。
func randCode(n int) (string, error) {
	const cs = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, n)
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = cs[int(buf[i])%len(cs)]
	}
	return string(b), nil
}

// dnsTXTFor 从 PEM 私钥导出 DKIM TXT 记录的 p= 值。
func dnsTXTFor(pemKey string) string {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return ""
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		k8, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return ""
		}
		rk, ok := k8.(*rsa.PrivateKey)
		if !ok {
			return ""
		}
		key = rk
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// 每个邮箱的自定义规则上限：规则越多，每封入站邮件要跑的正则越多。
const maxRulesPerMailbox = 50

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,31}$`)

func validUsername(s string) bool { return usernameRe.MatchString(s) }

// domainRe 严格域名格式：标签只能是小写字母/数字/连字符，必须以字母数字开头结尾。
// 之前只校验「含点」，导致带引号的字符串可以入库并拼进管理端 HTML。
var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func validDomain(s string) bool { return len(s) <= 253 && domainRe.MatchString(s) }
