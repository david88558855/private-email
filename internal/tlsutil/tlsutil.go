// Package tlsutil TLS 证书管理（D4：自签自动生成 + 支持上传自有证书）。
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Load 取 TLS 配置：优先用户证书，否则自签生成。
func Load(cfgDir string, certFile, keyFile string) *tls.Certificate {
	if certFile != "" && keyFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err == nil {
			log.Println("TLS：使用配置证书", certFile)
			return &c
		}
		log.Printf("TLS：配置证书加载失败，回退自签: %v", err)
	}
	return selfSigned(cfgDir)
}

func selfSigned(dir string) *tls.Certificate {
	crt := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	if c, err := tls.LoadX509KeyPair(crt, key); err == nil {
		return &c
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "private-email"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	log.Println("TLS：已生成自签证书", crt)
	c, _ := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return &c
}
