package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"regexp"

)

func randCode(n int) string {
	const cs = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, n)
	buf := make([]byte, n)
	rand.Read(buf)
	for i := range b {
		b[i] = cs[int(buf[i])%len(cs)]
	}
	return string(b)
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

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,31}$`)

func validUsername(s string) bool { return usernameRe.MatchString(s) }

// domainRe 严格域名格式：标签只能是小写字母/数字/连字符，必须以字母数字开头结尾。
// 之前只校验「含点」，导致带引号的字符串可以入库并拼进管理端 HTML。
var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func validDomain(s string) bool { return len(s) <= 253 && domainRe.MatchString(s) }
