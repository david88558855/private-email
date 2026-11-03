package config

import (
	crand "crypto/rand"
	"os"
	"path/filepath"

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
	} `yaml:"smtp_client"`
	TLS struct {
		CertFile string `yaml:"cert_file"` // 留空自签（决策 D4）
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`
	Security struct {
		JWTSecret string `yaml:"jwt_secret"`
		LoginRate int    `yaml:"login_rate_per_min"`
	} `yaml:"security"`
}

func defaults() *Config {
	c := &Config{}
	c.HTTP.Listen = ":8080"
	c.SMTP.Listen = ":25"
	c.SMTP.Submission = ":587"
	c.SMTP.TLS = ":465"
	c.SMTP.MaxSize = 25
	c.IMAP.Listen = ":143"
	c.IMAP.TLS = ":993"
	c.POP3.Listen = ":110"
	c.POP3.TLS = ":995"
	c.Security.LoginRate = 10
	return c
}

// Load 读取数据目录下 config.yaml，不存在则写入默认配置。
func Load(dataDir string) (*Config, error) {
	c := defaults()
	p := filepath.Join(dataDir, "config.yaml")
	if b, err := os.ReadFile(p); err == nil {
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, err
		}
		return c, nil
	}
	c.Security.JWTSecret = randToken(32)
	b, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return nil, err
	}
	return c, nil
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
