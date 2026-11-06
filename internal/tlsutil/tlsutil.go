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
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Load 取 TLS 配置：优先用户证书，否则自签生成。
//
// hostname 会写进自签证书的 SAN。原来只写了 localhost/127.0.0.1，
// 用户用 mail.example.com:993 连的时候证书必然不匹配，Thunderbird
// 直接拒绝，多数手机客户端也不给「继续」选项。
func Load(cfgDir, certFile, keyFile, hostname string) (*tls.Certificate, error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("TLS 配置不完整：cert_file 与 key_file 必须同时设置")
		}
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			// 配了正式证书却加载失败必须终止。静默回退自签会让客户端收到
			// 不受信证书，而运维以为正式证书已生效。
			return nil, fmt.Errorf("加载配置的 TLS 证书失败 (%s): %w", certFile, err)
		}
		log.Println("TLS：使用配置证书", certFile)
		return &c, nil
	}
	return selfSigned(cfgDir, hostname)
}

func selfSigned(dir, hostname string) (*tls.Certificate, error) {
	crt := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	if c, err := tls.LoadX509KeyPair(crt, key); err == nil {
		if hostname == "" || certCovers(c, hostname) {
			return &c, nil
		}
		log.Printf("TLS：已有自签证书不包含主机名 %s，重新生成", hostname)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	dns := []string{"localhost"}
	if h := strings.TrimSpace(hostname); h != "" && !strings.EqualFold(h, "localhost") {
		dns = append(dns, h)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "private-email"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  localIPs(),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	// 写盘失败必须报错：否则服务用内存证书跑着，重启后密钥轮换，客户端要重新信任。
	if err := os.WriteFile(crt, crtPEM, 0o644); err != nil {
		return nil, fmt.Errorf("写入自签证书失败: %w", err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("写入自签私钥失败: %w", err)
	}
	if err := os.Chmod(key, 0o600); err != nil {
		return nil, fmt.Errorf("设置自签私钥权限失败: %w", err)
	}
	log.Println("TLS：已生成自签证书", crt)
	c, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("装配自签证书失败: %w", err)
	}
	return &c, nil
}

// certCovers 判断证书里是否已包含指定主机名或 IP。
func certCovers(c tls.Certificate, host string) bool {
	if len(c.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, v := range leaf.IPAddresses {
			if v.Equal(ip) {
				return true
			}
		}
		return false
	}
	for _, v := range leaf.DNSNames {
		if strings.EqualFold(v, host) {
			return true
		}
	}
	return false
}

// localIPs 收集本机非回环 IPv4 地址，方便手机在同一局域网里直连。
func localIPs() []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ips = append(ips, ipnet.IP)
		}
	}
	return ips
}
