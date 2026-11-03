package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/david88558855/private-email/internal/store"
)

type storeAlias = store.Store

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
