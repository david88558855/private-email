# Private Email

自托管邮件服务器 · 单文件二进制 · 数据跟随二进制。

Go 1.27.3 · Gin · modernc.org/sqlite（纯 Go，无 CGO）· 前端 go:embed 内嵌。

## 功能

- **SMTP 入站**（25 / 587 submission / 465 隐式 TLS）：RCPT 校验拒收未知邮箱、SPF+DKIM 验签记分、验证码自动提取、转发规则
- **SMTP 出站**：直连 MX（RFC 5321 A 记录回落）或 smarthost 中继；DKIM 签名（RSA2048 自动生成）；15m/1h/6h/24h 指数退避重试
- **IMAP4rev1**（143 STARTTLS / 993 SSL）：LIST/SELECT/FETCH/SEARCH/FLAGS/COPY/APPEND/EXPUNGE
- **POP3**（110 / 995 SSL）：RFC 1939 全集（USER/PASS/STAT/LIST/UIDL/RETR/TOP/DELE/RSET）
- **Web 邮件客户端**：三栏收件箱、HTML 沙箱渲染、验证码点击复制、全文检索、撰写发送、亮/暗主题
- **管理端**：用户管理、域名 + DKIM DNS 记录展示、邀请码注册、投递队列监控、库体积统计
- **存储**：全 SQLite 单库（元数据 + 邮件 BLOB + FTS5 全文索引），WAL 多连接，备份 = 拷贝一个 db.sqlite
- **认证**：客户端协议复用 Web 密码，或生成 App 专用密码；登录限速
- **TLS**：自签证书自动生成，支持上传自有证书

## 快速开始

```bash
./private-email                 # 数据目录 = 二进制所在目录/data/
./private-email -data /path     # 或显式指定
./private-email -version
```

首次启动：

1. 自动建库、生成默认 `data/config.yaml`、自签 TLS 证书
2. 创建管理员 `admin`，随机密码写入 `data/initial_admin_password.txt`（请立即登录并修改）
3. 默认域名 `local.test` 自动创建；Web 端口 `:8080`

生产部署（假设域名 mail.example.com，服务器 IP 可达）：

```bash
sudo setcap 'cap_net_bind_service=+ep' ./private-email   # 非 root 绑 25/143 等
```

DNS 记录：

| 记录 | 值 |
|---|---|
| A   | mail.example.com → 服务器 IP |
| MX  | example.com → mail.example.com（优先级 10） |
| SPF (TXT) | `v=spf1 mx -all` |
| DKIM (TXT) | 管理面板「域名」页展示的 `default._domainkey` 记录 |
| DMARC (TXT, 可选) | `_dmarc` → `v=DMARC1; p=quarantine` |

管理面板「域名」新增域名后，DKIM 密钥自动生成，TXT 记录值直接可复制。

## 构建

```bash
make build      # 输出 dist/private-email-linux-x64 与 dist/private-email-win-x64.exe
make test
```

Docker：

```bash
docker build -t private-email .
docker run -p 8080:8080 -p 25:25 -v $PWD/data:/app/data private-email
```

## 配置（data/config.yaml，首次启动生成）

关键项：

```yaml
smtp:
  listen: ":25"          # 入站
  submission: ":587"     # 客户端提交
  tls: ":465"            # 隐式 TLS（留空关闭）
smtp_client:
  smarthost: ""          # 如 "relay.example.com:587"，留空直连 MX
tls:
  cert_file: ""          # 自有证书（留空自签）
  key_file: ""
security:
  login_rate_per_min: 10
```

## 目录结构

```
data/
├── db.sqlite      # 全部数据（元数据 + 邮件 BLOB），备份/迁移即拷此文件
├── config.yaml    # 配置
├── backup/        # VACUUM INTO 快照
├── certs/         # TLS 证书
├── keys/          # （预留）
└── logs/          # 日志
```

## 里程碑

- [x] M1 骨架（配置/迁移/嵌入/登录）
- [x] M2 SMTP 入站 + 收件箱
- [x] M3 IMAP + POP3
- [x] M4 SMTP 出站 + DKIM + 队列
- [x] M5 管理端
- [x] M6 TLS + 加固 + 打包
