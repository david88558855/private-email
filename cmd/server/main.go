// Private Email 自托管邮件服务器 · 单文件二进制入口。
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/database"
	"github.com/david88558855/private-email/internal/outbound"
	"github.com/david88558855/private-email/internal/proto/imap"
	"github.com/david88558855/private-email/internal/proto/pop3"
	"github.com/david88558855/private-email/internal/proto/smtp"
	"github.com/david88558855/private-email/internal/server"
	"github.com/david88558855/private-email/internal/store"
	"github.com/david88558855/private-email/internal/tlsutil"
	"golang.org/x/crypto/bcrypt"
)

var version = "dev"

var dataDirP string

func main() {
	var dataFlag string
	var showVersion bool
	flag.StringVar(&dataFlag, "data", "", "数据目录（默认：二进制所在目录/data）")
	flag.BoolVar(&showVersion, "version", false, "打印版本")
	flag.Parse()

	if showVersion {
		fmt.Println("private-email", version)
		return
	}

	dataDir := dataFlag
	if dataDir == "" {
		exe, err := os.Executable()
		if err != nil {
			log.Fatalf("解析可执行文件路径失败: %v", err)
		}
		dataDir = filepath.Join(filepath.Dir(exe), "data")
	}
	for _, d := range []string{dataDir, filepath.Join(dataDir, "backup"), filepath.Join(dataDir, "keys"),
		filepath.Join(dataDir, "certs"), filepath.Join(dataDir, "logs")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			log.Fatalf("创建数据目录失败 %s: %v", d, err)
		}
	}
	dataDirP = dataDir
	log.Printf("数据目录: %s", dataDir)

	cfg, err := config.Load(dataDir)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	db, err := database.Open(filepath.Join(dataDir, "db.sqlite"))
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}
	bootstrapAdmin(db)

	st := &store.Store{DB: db}
	st.Bootstrap()
	st.RebuildFTSBody()

	// 端口设置（管理员可在 Web 修改，优先于 config.yaml）
	applyPortSettings(cfg, st)

	// TLS（M6：D4 自签或自有证书）
	cert := tlsutil.Load(filepath.Join(dataDir, "certs"), cfg.TLS.CertFile, cfg.TLS.KeyFile)

	// SMTP 入站（M2）
	smtpBackend := &smtp.Backend{Store: st, Config: cfg, Cert: cert}
	smtp.Serve(smtpBackend)

	// IMAP / POP3（M3）
	imap.Serve(&imap.Backend{Store: st, Config: cfg, Cert: cert}, cfg)
	pop3.Serve(st, cfg, cert)

	// SMTP 出站（M4）
	outbound.EnsureDKIMKeys(st)
	(&outbound.Worker{Store: st, Cfg: cfg}).Start()

	r := server.New(db, cfg, st)
	log.Printf("Private Email %s · HTTP %s 就绪", version, cfg.HTTP.Listen)
	if err := r.Run(cfg.HTTP.Listen); err != nil {
		log.Fatal(err)
	}
}

// bootstrapAdmin 首次启动创建 admin 账号并输出随机密码。
func bootstrapAdmin(db *sql.DB) {
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	if n > 0 {
		return
	}
	pw := "adnin" // 默认管理员密码，登录后请立即修改
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if _, err := db.Exec(`INSERT INTO users(username, password, role) VALUES('admin', ?, 'admin')`, string(hash)); err != nil {
		log.Fatalf("创建管理员失败: %v", err)
	}
	p := filepath.Join(dataDirP, "initial_admin_password.txt")
	os.WriteFile(p, []byte("username: admin\npassword: "+pw+"\n"), 0o600)
	log.Printf("首次启动：已创建管理员 admin，初始密码见 %s", p)
}

// applyPortSettings 端口类设置覆盖配置（设置表有值则以 Web 设置为准）。
func applyPortSettings(cfg *config.Config, st *store.Store) {
	pairs := map[string]*string{
		"smtp_listen":     &cfg.SMTP.Listen,
		"smtp_submission": &cfg.SMTP.Submission,
		"smtp_tls":        &cfg.SMTP.TLS,
		"imap_listen":     &cfg.IMAP.Listen,
		"imap_tls":        &cfg.IMAP.TLS,
		"pop3_listen":     &cfg.POP3.Listen,
		"pop3_tls":        &cfg.POP3.TLS,
	}
	for k, dst := range pairs {
		if !st.HasSetting(k) {
			// 首次播种：设置表以 config.yaml 现值为初始事实源
			st.SetSetting(k, *dst)
		}
		if v := st.GetSetting(k); v != "" {
			*dst = v
		}
	}
}
