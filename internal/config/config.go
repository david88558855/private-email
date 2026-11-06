package config

import (
	crand "crypto/rand"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 全局配置，首次启动自动生成默认 config.yaml 到数据目录。
type Config struct {
	HTTP struct {
		Listen string `yaml:"listen"`
	} `yaml:"http"`
	SMTP struct {
		Listen     string `yaml:"listen"`      // 25 明文/STARTTLS
		Submission string `yaml:"submission"`  // 587 STARTTLS
		TLS        string `yaml:"tls"`         // 465 隐式 TLS，空则关闭
		MaxSize    int64  `yaml:"max_size_mb"` // 单封上限 MB
	} `yaml:"smtp"`
	IMAP struct {
		Listen string `yaml:"listen"` // 143 STARTTLS
		TLS    string `yaml:"tls"`    // 993
	} `yaml:"imap"`
	POP3 struct {
		Listen string `yaml:"listen"` // 110
		TLS    string `yaml:"tls"`    // 995
	} `yaml:"pop3"`
	SMTPClient struct {
		Smarthost string `yaml:"smarthost"` // host:port，留空直连 MX（决策 D3）
		Username  string `yaml:"username"`  // relay 凭据（可空）
		Password  string `yaml:"password"`  // relay 凭据（可空）
		From      string `yaml:"from"`      // relay 信封发件人（可空）
		// TLS 连 relay 时跳过证书校验（自签 relay 场景）
		InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	} `yaml:"smtp_client"`
	TLS struct {
		CertFile string `yaml:"cert_file"` // 留空自签（决策 D4）
		KeyFile  string `yaml:"key_file"`
		Hostname string `yaml:"hostname"` // 自签证书里的主机名（如 mail.example.com）
	} `yaml:"tls"`
	Security struct {
		JWTSecret string `yaml:"jwt_secret"`
		LoginRate int    `yaml:"login_rate_per_min"`
		// AllowInsecureAuth 允许在未加密端口（25/587/143/110）上用密码认证。
		// 默认 false：公网部署时避免密码明文上网。内网/本机调试可显式打开。
		AllowInsecureAuth bool `yaml:"allow_insecure_auth"`
		// InsecureAuthCIDRs 允许在明文端口提交凭据的来源网段（CIDR，也接受单个 IP）。
		// 留空且开启上面的开关时不限制来源，仅适用于已做网络隔离的内网。
		// 配置后，白名单外的来源在明文连接上一律拒绝认证，但仍可走 TLS 端口。
		InsecureAuthCIDRs []string `yaml:"insecure_auth_cidrs"`
		// MaxConns 每个协议监听的最大并发连接数，0 表示用内置默认值。
		MaxConns int `yaml:"max_conns"`
		// IdleTimeoutMin 协议连接空闲超时（分钟），0 表示用内置默认值。
		IdleTimeoutMin int `yaml:"idle_timeout_min"`
		// SkipDomainVerification 为 true 时新增域名直接标记已验证（内网/测试用）。
		// 默认 false：域名需通过 DNS TXT 校验后才能建邮箱。
		SkipDomainVerification bool `yaml:"skip_domain_verification"`
	} `yaml:"security"`
}

func defaults() *Config {
	c := &Config{}
	c.HTTP.Listen = ":9000"
	c.SMTP.Listen = ":25"
	c.SMTP.Submission = ":587"
	c.SMTP.TLS = ":465"
	c.SMTP.MaxSize = 25
	c.IMAP.Listen = ":143"
	c.IMAP.TLS = ":993"
	c.POP3.Listen = ":110"
	c.POP3.TLS = ":995"
	c.Security.LoginRate = 10
	c.Security.MaxConns = 512
	c.Security.IdleTimeoutMin = 30
	return c
}

// Load 读取数据目录下 config.yaml，不存在则写入默认配置。
// 已有配置里 jwt_secret 为空时（官方 example 就是空值）自动补一个并写回，
// 否则任何人都能用空密钥伪造管理员 token。
func Load(dataDir string) (*Config, error) {
	c := defaults()
	p := filepath.Join(dataDir, "config.yaml")
	if b, err := os.ReadFile(p); err == nil {
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, err
		}
		if len(c.Security.JWTSecret) < 16 {
			c.Security.JWTSecret = randToken(48)
			// 写回失败必须终止：只读数据目录会让每次重启都换新密钥，
			// 所有已签发 token 静默失效，且多实例会各自生成不同密钥。
			if err := save(p, c); err != nil {
				return nil, fmt.Errorf("写入 jwt_secret 失败: %w", err)
			}
			log.Printf("配置缺少有效的 jwt_secret，已自动生成并写回 %s", p)
		}
		return c, nil
	}
	c.Security.JWTSecret = randToken(48)
	if err := save(p, c); err != nil {
		return nil, err
	}
	return c, nil
}

// save 原子写配置：先写临时文件再 rename，避免断电留下半截 YAML。
func save(p string, c *Config) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// RandToken 生成 n 字符随机串（密码/令牌用）。
func RandToken(n int) string { return randToken(n) }

func randToken(n int) string {
	const cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	buf := make([]byte, n)
	if _, err := crand.Read(buf); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = cs[int(buf[i])%len(cs)]
	}
	return string(b)
}

// ValidateListenPorts 检查监听地址的端口是否冲突、格式是否合法。
// 各协议 Serve 对 net.Listen 失败只打日志跳过，两个服务配成同一端口时
// 进程仍会打印「服务就绪」，实际上有一个协议根本没在听。
// 空串表示关闭该监听，不参与校验。
func ValidateListenPorts(addrs map[string]string) error {
	byPort := map[string]string{}
	for name, raw := range addrs {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		_, port, err := net.SplitHostPort(v)
		if err != nil {
			return fmt.Errorf("%s 监听地址格式错误 %q: %w", name, v, err)
		}
		if prev, ok := byPort[port]; ok {
			return fmt.Errorf("监听端口冲突：%s 与 %s 都使用端口 %s", prev, name, port)
		}
		byPort[port] = name
	}
	return nil
}

// TrimHost 去掉监听地址里的主机部分，返回端口（用于日志/校验）。
func TrimHost(s string) string {
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return s
}
