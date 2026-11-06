package insecureauth

import (
	"net"
	"testing"
)

func addr(s string) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(s), Port: 12345}
}

func TestAllow(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		cidrs   []string
		isTLS   bool
		remote  net.Addr
		want    bool
	}{
		{"默认关闭时明文拒绝", false, nil, false, addr("192.168.1.10"), false},
		{"默认关闭时 TLS 放行", false, nil, true, addr("203.0.113.9"), true},
		{"开启后未配白名单全放行", true, nil, false, addr("203.0.113.9"), true},
		{"白名单内网放行", true, []string{"192.168.0.0/16", "10.0.0.0/8"}, false, addr("192.168.1.10"), true},
		{"白名单外网拒绝", true, []string{"192.168.0.0/16"}, false, addr("203.0.113.9"), false},
		{"白名单不影响 TLS", true, []string{"192.168.0.0/16"}, true, addr("203.0.113.9"), true},
		{"单 IP 自动补掩码", true, []string{"127.0.0.1"}, false, addr("127.0.0.1"), true},
		{"单 IP 之外的来源拒绝", true, []string{"127.0.0.1"}, false, addr("127.0.0.2"), false},
		{"IPv6 网段", true, []string{"fd00::/8"}, false, addr("fd00::1234"), true},
		{"来源地址缺失时拒绝", true, []string{"192.168.0.0/16"}, false, nil, false},
	}
	for _, c := range cases {
		p, err := New(c.enabled, c.cidrs)
		if err != nil {
			t.Fatalf("%s: New: %v", c.name, err)
		}
		if got := p.Allow(c.isTLS, c.remote); got != c.want {
			t.Errorf("%s: Allow=%v want %v", c.name, got, c.want)
		}
	}
}

func TestNewRejectsBadCIDR(t *testing.T) {
	for _, bad := range []string{"192.168.1.0/99", "not-an-ip", "192.168.1.1/24/8"} {
		if _, err := New(true, []string{bad}); err == nil {
			t.Errorf("New(true, %q) 应报错", bad)
		}
	}
}

func TestNilPolicyIsFailClosed(t *testing.T) {
	var p *Policy
	if p.Allow(false, addr("127.0.0.1")) {
		t.Fatal("nil 策略不应放行明文认证")
	}
	if !p.Allow(true, addr("127.0.0.1")) {
		t.Fatal("nil 策略不应拦住 TLS 认证")
	}
}
