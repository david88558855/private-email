// Package insecureauth 统一判定「未加密链路上能否提交凭据」。
//
// SASL PLAIN 的 base64 只是编码，不是加密。未加密链路上抓包即可还原用户名与密码，
// 所以明文认证不能只靠一个布尔开关：必须由 SMTP/IMAP/POP3 共用同一份策略，
// 否则三个端口会出现三套安全口径，运维改配置时顾此失彼。
package insecureauth

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// Policy 明文认证策略。
//   - Enabled=false：任何未加密连接都不允许认证（默认，公网部署必须保持）。
//   - Enabled=true 且 Nets 为空：允许所有来源，依赖部署者自己做网络隔离。
//   - Enabled=true 且 Nets 非空：仅白名单网段可在未加密连接上认证。
type Policy struct {
	Enabled bool
	Nets    []*net.IPNet
}

// New 解析来源网段并输出风险提示。配置写错时直接报错，不静默忽略——
// 一个拼错的 CIDR 如果悄悄跳过，等于白名单形同虚设。
func New(enabled bool, cidrs []string) (*Policy, error) {
	p := &Policy{Enabled: enabled}
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			ip := net.ParseIP(raw)
			if ip == nil {
				return nil, fmt.Errorf("insecure_auth_cidrs 含无效地址 %q", raw)
			}
			if ip.To4() != nil {
				raw += "/32"
			} else {
				raw += "/128"
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("insecure_auth_cidrs 含无效网段 %q: %w", raw, err)
		}
		p.Nets = append(p.Nets, n)
	}
	if !enabled {
		if len(p.Nets) > 0 {
			log.Printf("提示：allow_insecure_auth=false，insecure_auth_cidrs 当前不生效")
		}
		return p, nil
	}
	if len(p.Nets) == 0 {
		log.Printf("警告：allow_insecure_auth=true 且未配置 insecure_auth_cidrs，任意来源都可在明文端口提交凭据；PLAIN 凭据为 base64 明文，须确保监听地址只在隔离内网可达")
	} else {
		log.Printf("警告：明文认证已启用，仅允许来源网段 %v；PLAIN 凭据为 base64 明文，须确保这些网段不承载不可信流量", cidrs)
	}
	return p, nil
}

// Allow 判断本次认证是否放行。
// TLS 连接一律放行：PLAIN over TLS 是 RFC 4616 的标准用法，不受白名单限制。
// 未加密连接必须显式开启，且（若配置了白名单）来源 IP 命中网段。
func (p *Policy) Allow(isTLS bool, remote net.Addr) bool {
	if p == nil { // 未注入策略时采用最保守默认值
		return isTLS
	}
	if isTLS {
		return true
	}
	if !p.Enabled {
		return false
	}
	if len(p.Nets) == 0 {
		return true
	}
	ip := addrIP(remote)
	if ip == nil {
		return false
	}
	for _, n := range p.Nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func addrIP(a net.Addr) net.IP {
	if a == nil {
		return nil
	}
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.IP
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return net.ParseIP(a.String())
	}
	return net.ParseIP(host)
}
