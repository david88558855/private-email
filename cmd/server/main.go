// Private Email 自托管邮件服务器 · 单文件二进制入口。
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/david88558855/private-email/internal/config"
	"github.com/david88558855/private-email/internal/database"
	"github.com/david88558855/private-email/internal/insecureauth"
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
	var httpFlag string
	var showVersion bool
	flag.StringVar(&dataFlag, "data", "", "数据目录（默认：二进制所在目录/data）")
	flag.StringVar(&httpFlag, "port", "", "Web 端口（默认 :9000，如 -port 8080；优先于配置文件）")
	flag.BoolVar(&showVersion, "version", false, "打印版本")
	flag.Parse()
	if httpFlag != "" {
		// 归一化：8080 → :8080
		if !strings.Contains(httpFlag, ":") {
			httpFlag = ":" + httpFlag
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(httpFlag, ":")); err != nil || n < 1 || n > 65535 {
			log.Fatalf("-port 无效：%s（应为 1-65535）", httpFlag)
		}
	}

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
	if httpFlag != "" {
		// -port 参数：覆盖 Web 端口（最高优先级）
		cfg.HTTP.Listen = httpFlag
		log.Printf("Web 端口（参数覆盖）: %s", httpFlag)
	}

	db, err := database.Open(filepath.Join(dataDir, "db.sqlite"))
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}
	bootstrapAdmin(db, dataDir)

	st := &store.Store{DB: db}
	st.Bootstrap()
	// 大库回填全文索引可能耗时几分钟，不能阻塞服务启动；
	// 后台 goroutine 的 panic 必须留痕，否则全文检索静默残缺。
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("FTS 回填 panic: %v\n%s", r, debug.Stack())
			}
		}()
		st.RebuildFTSBody()
	}()

	// 端口设置（管理员可在 Web 修改，优先于 config.yaml）
	applyPortSettings(cfg, st)
	if err := config.ValidateListenPorts(map[string]string{
		"http":            cfg.HTTP.Listen,
		"smtp_listen":     cfg.SMTP.Listen,
		"smtp_submission": cfg.SMTP.Submission,
		"smtp_tls":        cfg.SMTP.TLS,
		"imap_listen":     cfg.IMAP.Listen,
		"imap_tls":        cfg.IMAP.TLS,
		"pop3_listen":     cfg.POP3.Listen,
		"pop3_tls":        cfg.POP3.TLS,
	}); err != nil {
		log.Fatalf("监听配置错误: %v", err)
	}
	probeListenAddrs(cfg)

	// 明文认证策略：SMTP/IMAP/POP3 共用一份判定，避免各端口安全口径不一致
	authPolicy, err := insecureauth.New(cfg.Security.AllowInsecureAuth, cfg.Security.InsecureAuthCIDRs)
	if err != nil {
		log.Fatalf("明文认证策略配置错误: %v", err)
	}

	// TLS（M6：D4 自签或自有证书）
	cert, err := tlsutil.Load(filepath.Join(dataDir, "certs"), cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.Hostname)
	if err != nil {
		log.Fatalf("TLS 初始化失败: %v", err)
	}

	// SMTP 入站（M2）
	smtpBackend := &smtp.Backend{Store: st, Config: cfg, Cert: cert, Policy: authPolicy}
	smtp.Serve(smtpBackend)

	// IMAP / POP3（M3）
	imap.Serve(imap.NewBackend(st, cfg, cert, authPolicy), cfg)
	pop3.Serve(st, cfg, cert, authPolicy)

	// SMTP 出站（M4）
	outbound.EnsureDKIMKeys(st)
	(&outbound.Worker{Store: st, Cfg: cfg}).Start()

	r := server.New(db, cfg, st)
	// ReadHeaderTimeout 挡住 Slowloris 式慢请求头；不设整体 Read/WriteTimeout，
	// 避免 50MB 附件在慢速网络下被服务端掐断（体积由 BodyLimit 控制）。
	srv := &http.Server{
		Addr:              cfg.HTTP.Listen,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("Private Email %s · HTTP %s 就绪", version, cfg.HTTP.Listen)

	// 优雅退出：收到 SIGINT/SIGTERM 后先停止接新请求，给在途请求 10 秒收尾，
	// 避免重启时把正在写的邮件拦腰截断。
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		log.Fatal(err)
	case <-ctx.Done():
		log.Println("收到退出信号，正在停止 HTTP 服务…")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP 关闭超时: %v", err)
	}
	db.Close()
	log.Println("已退出")
}

// bootstrapAdmin 首次启动创建 admin 账号。
// 初始密码默认随机生成，只写进 0600 的 data/initial_admin.txt 并在日志打印一次；
// 自动化部署可用 PRIVATE_EMAIL_ADMIN_PASSWORD 显式指定（此时日志不回显密码）。
func bootstrapAdmin(db *sql.DB, dataDir string) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		log.Fatalf("检查管理员账号失败: %v", err)
	}
	if n > 0 {
		return
	}
	fromEnv := os.Getenv("PRIVATE_EMAIL_ADMIN_PASSWORD") != ""
	pw := os.Getenv("PRIVATE_EMAIL_ADMIN_PASSWORD")
	if pw == "" {
		pw = config.RandToken(20)
	}
	if len(pw) > 72 {
		log.Fatalf("初始管理员密码超过 72 字节，bcrypt 无法处理（请缩短 PRIVATE_EMAIL_ADMIN_PASSWORD）")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("生成管理员密码哈希失败: %v", err)
	}
	// 先落盘再建号：写盘失败就必须终止，否则账号已建而密码无人知晓，
	// 重启时 n>0 会跳过 bootstrap，实例永久锁死。
	// 环境变量模式不落盘，秘密只留在环境变量里。
	p := filepath.Join(dataDir, "initial_admin.txt")
	if !fromEnv {
		if err := os.WriteFile(p, []byte("admin / "+pw+"\n"), 0o600); err != nil {
			log.Fatalf("写入初始管理员密码失败 %s: %v", p, err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			log.Fatalf("设置初始管理员密码文件权限失败 %s: %v", p, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO users(username, password, role) VALUES('admin', ?, 'admin')`, string(hash)); err != nil {
		log.Fatalf("创建管理员失败: %v", err)
	}
	if fromEnv {
		log.Printf("首次启动：管理员 admin 已创建，初始密码由环境变量指定（未落盘，请登录后立即修改）")
	} else {
		log.Printf("首次启动：管理员 admin，初始密码 %s，已保存到 %s（请登录后立即修改）", pw, p)
	}
}

// probeListenAddrs 启动前实际 bind 一次每个非空监听地址。
// 各协议 Serve 对 net.Listen 失败只打印「跳过」继续跑：端口被占用或多实例误启动时
// 进程照样打印「HTTP 就绪」，实际上一个协议端口都没在听，必须启动期就拦住。
func probeListenAddrs(cfg *config.Config) {
	addrs := []string{
		cfg.HTTP.Listen, cfg.SMTP.Listen, cfg.SMTP.Submission, cfg.SMTP.TLS,
		cfg.IMAP.Listen, cfg.IMAP.TLS, cfg.POP3.Listen, cfg.POP3.TLS,
	}
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("监听地址不可用 %s（端口被占用或无权限）: %v", addr, err)
		}
		ln.Close()
	}
}

// applyPortSettings 端口类设置覆盖配置（设置表有值则以 Web 设置为准）。
// 注意：设置项为空串表示「关闭该监听」，必须以设置表为准，不能被 config.yaml 覆盖回去。
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
		has, err := st.HasSetting(k)
		if err != nil {
			log.Fatalf("读取端口设置失败 %s: %v", k, err)
		}
		if !has {
			// 首次播种：设置表以 config.yaml 现值为初始事实源
			if err := st.SetSetting(k, *dst); err != nil {
				log.Fatalf("初始化端口设置失败 %s: %v", k, err)
			}
			continue
		}
		v, err := st.GetSetting(k)
		if err != nil {
			log.Fatalf("读取端口设置失败 %s: %v", k, err)
		}
		*dst = v
	}
}
