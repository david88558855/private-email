# Private Email

自托管邮件服务器 · 单文件二进制 · 数据跟随二进制 · 前端内嵌。

Go 1.27 · Gin · modernc.org/sqlite（纯 Go，无 CGO）· go:embed 内嵌 Web 客户端。
一个可执行文件同时是 SMTP / IMAP / POP3 服务端、Web 邮件客户端和管理后台，全部数据落在一个 `db.sqlite` 里，备份=拷一个文件。

---

## 功能

**收信（SMTP 入站）**

- 25 明文/STARTTLS、587 提交、465 隐式 TLS（三端口可分别关闭）
- `RCPT TO` 校验：只收本机已存在且启用的邮箱，未知地址直接 550 拒收
- SPF 校验 + DKIM 验签记分（各 1.5 分，写入 `spam_score`，前端超过 4 分标记「可疑」）
- 验证码自动提取：自定义规则（可按邮箱）→ 全局规则 → 内置中英文规则
- 转发规则：命中即复制一份进投递队列
- 已认证会话强制 `MAIL FROM` 等于登录邮箱，禁止冒用他人发件人

**发信（SMTP 出站）**

- 直连对方 MX（无 MX 记录按 RFC 5321 回落 A 记录），或配置 smarthost 中继
- DKIM 签名：域名添加时自动生成 RSA2048 密钥，selector 默认 `default`
- 指数退避重试：首次失败后 15m / 1h / 6h / 24h，五次失败标记 `failed`
- 写信即入队，Web 端立刻能在「已发送」看到副本

**收信协议**

- IMAP4rev1（143 STARTTLS / 993 SSL）：LIST / SELECT / STATUS / FETCH / SEARCH / STORE / COPY / APPEND / EXPUNGE
- POP3（110 / 995 SSL）：USER / PASS / STAT / LIST / UIDL / RETR / TOP / DELE / RSET / QUIT
- 协议登录复用 Web 密码，或使用「App 专用密码」（可单独撤销）

**Web 客户端**

- 三栏布局：文件夹导航（全部邮件 + 四文件夹）+ 邮件列表 + 阅读区，多邮箱下拉切换
- HTML 正文用 `sandbox` iframe 渲染，脚本全禁
- 验证码高亮一键复制、FTS5 全文检索、亮/暗主题、8 秒轮询 + 聚焦即刷

**管理后台**

- 用户管理（启用/禁用/重置密码）、域名管理（含 DKIM TXT 记录一键复制）
- 投递队列监控、库体积统计、注册开关、协议端口在线配置

---

## 快速开始

### 1. 拿到二进制

从 [Releases](https://github.com/david88558855/private-email/releases) 下载对应平台产物，或自己编译（见下）。

```bash
./private-email                 # 数据目录 = 二进制所在目录/data
./private-email -data /path     # 或显式指定数据目录
./private-email -port 9000      # 临时覆盖 Web 端口（优先级最高）
./private-email -version        # 打印版本
```

### 2. 首次启动

程序会自动完成：

1. 建数据目录（`data/`、`backup/`、`certs/`、`keys/`、`logs/`，权限 0700）
2. 建库并执行迁移（含 FTS5 全文索引与同步触发器）
3. 生成 `data/config.yaml`（默认值）
4. 生成自签 TLS 证书 `data/certs/server.crt`（10 年有效）
5. 创建管理员 **admin / admin**（**请立即登录改密**）

Web 控制台：<http://localhost:8080>

> 首次启动**不会**自动创建域名或邮箱。登录后到「后台管理 → 域名」添加域名，再回「邮箱管理」建邮箱。

### 3. 生产部署

绑定 25/143/110 等低位端口需要权限：

```bash
sudo setcap 'cap_net_bind_service=+ep' ./private-email   # Linux
```

DNS 记录（假设域名 `example.com`、服务器 `mail.example.com`）：

| 类型 | 主机 | 值 |
|---|---|---|
| A | `mail.example.com` | 服务器公网 IP |
| MX | `example.com` | `mail.example.com`（优先级 10） |
| TXT | `example.com` | `v=spf1 mx -all` |
| TXT | `default._domainkey.example.com` | 管理后台「域名」页展示的完整值 |
| TXT | `_dmarc.example.com` | `v=DMARC1; p=quarantine`（可选） |

Docker：

```bash
docker build -t private-email .
docker run -d --name mail \
  -p 8080:8080 -p 25:25 -p 587:587 -p 465:465 \
  -p 143:143 -p 993:993 -p 110:110 -p 995:995 \
  -v $PWD/data:/app/data private-email
```

---

## 端口

| 用途 | 默认 | 配置键 |
|---|---|---|
| Web / API | `:8080` | `http.listen`（也可用 `-port`） |
| SMTP 收信 | `:25` | `smtp.listen` |
| SMTP 提交（需认证） | `:587` | `smtp.submission` |
| SMTPS 隐式 TLS | `:465` | `smtp.tls` |
| IMAP / IMAPS | `:143` / `:993` | `imap.listen` / `imap.tls` |
| POP3 / POP3S | `:110` / `:995` | `pop3.listen` / `pop3.tls` |

**留空即关闭该监听。** 管理后台「系统设置 → 协议端口」写入的值存在 `settings` 表，
优先级高于 `config.yaml`，**重启后生效**（Web 端口除外，Web 只能用 `-port` 或配置文件改）。

---

## 配置（`data/config.yaml`）

```yaml
http:
  listen: ":8080"
smtp:
  listen: ":25"
  submission: ":587"
  tls: ":465"
  max_size_mb: 25          # 单封上限，入站超限 552
imap:
  listen: ":143"
  tls: ":993"
pop3:
  listen: ":110"
  tls: ":995"
smtp_client:
  smarthost: ""            # 如 "relay.example.com:587"；留空直连 MX
  username: ""             # relay 认证（可选）
  password: ""
  insecure_skip_verify: false
tls:
  cert_file: ""            # 自有证书；留空用自签
  key_file: ""
security:
  jwt_secret: ""           # 留空首次启动自动生成
  login_rate_per_min: 10   # 每 IP 每分钟登录尝试上限
```

---

## 数据与备份

```
data/
├── db.sqlite      # 全部数据：用户、域名、邮箱、邮件原文 BLOB、队列、设置
├── config.yaml    # 配置
├── certs/         # TLS 证书（自签或自有）
├── backup/        # 预留目录（当前代码未写入）
├── keys/          # 预留目录
└── logs/          # 预留目录（日志当前输出到 stdout）
```

备份方式：**停服务后拷贝 `db.sqlite`**（连同 `-wal`/`-shm` 一并拷，或先执行一次 checkpoint）。
运行中直接用 `sqlite3 db.sqlite ".backup out.sqlite"` 也可得到一致快照。

---

## 构建

```bash
make build            # 同时产出 linux-x64 与 win-x64
make build-linux      # dist/private-email-linux-x64
make build-win        # dist/private-email-win-x64.exe
make test             # go test ./...
make version          # 打印本次注入的版本号
make clean            # 删除 dist/
```

版本号通过 ldflags 注入 `main.version`，优先级：`make VERSION=x.y.z` > `git describe --tags` > 时间戳。

```bash
make build VERSION=v2.2.0
./dist/private-email-win-x64.exe -version   # → private-email v2.2.0
```

交叉编译无需 CGO（SQLite 用纯 Go 实现），Dockerfile 内也是同一套参数。

---

## 测试

`tools/e2e_suite.py` 是端到端套件（约 76 条），覆盖认证、SMTP 收发、IMAP/POP3、TLS、
权限隔离、管理端、限速等。它默认连以下端口，需要一套与之匹配的配置：

| 服务 | 端口 |
|---|---|
| HTTP | 8080 |
| SMTP / Submission / SMTPS | 2525 / 2587 / 9465 |
| IMAP / IMAPS | 2143 / 9943 |
| POP3 / POP3S | 2110 / 9955 |

```bash
# data/config.yaml 里把上面这些端口配好，启动服务后：
python3 tools/e2e_suite.py
# 可用环境变量覆盖：PE_BASE（默认 http://localhost:8080/api/v1）、PE_PW（默认 admin）
```

其中「出站回环送达」依赖测试域名能被 DNS 解析（`.test` 域名默认不可解析），
在无本地 DNS 兜底的环境会失败并连带影响紧随其后的 POP3 STAT 计数，其余用例应全绿。

---

## 安全说明

- **默认密码 admin/admin 必须首登即改**；改密会同步该用户所有邮箱的协议密码。
- **账号禁用立即生效**：JWT 每次请求都回查用户状态，禁用后旧 token 立刻失效（不必等 24h 过期）。
- **登录限速按真实来源 IP**：服务不信任 `X-Forwarded-For`。若部署在 Nginx/Cloudflare 之后，
  所有请求会呈现为反代 IP，限速粒度随之变粗——这需要在反代层做限速。
- **协议层允许明文认证**（`AllowInsecureAuth`，兼容内网老客户端）。公网部署请让客户端走
  STARTTLS/SSL，或只暴露加密端口并关闭明文端口。
- 邮件 HTML 正文在 `sandbox` iframe 内渲染，脚本、表单、同源访问全部禁用。
- DKIM 私钥与邮件原文同库存储，`db.sqlite` 泄露等同于邮箱与发信身份泄露，注意文件权限。

---

## 已知限制

- 出站直连 MX 需要服务器本身具备公网 DNS 与出站 25 端口；多数云厂商默认封 25，需申请解封或配 smarthost。
- POP3 单次会话最多索引 500 封（正文按需拉取，不整体载入内存）；`QUIT` 时对 `DELE` 的邮件执行**永久删除**，不进垃圾箱。
- IMAP `SEARCH` 会逐封解析正文，单邮箱体量很大时较慢。
- 暂无邮箱删除、附件下载、多用户共享文件夹等能力。

---

## 目录结构

```
cmd/server/            程序入口（flag、启动编排、端口设置覆盖）
internal/config/       配置加载与默认值
internal/database/     连接、迁移（含 FTS5 触发器）
internal/store/        SQLite 读写层（邮件、邮箱、设置、认证）
internal/mailutil/     MIME 解析、验证码提取
internal/proto/smtp/   SMTP 服务端（入站 + 提交）
internal/proto/imap/   IMAP4rev1 服务端
internal/proto/pop3/   POP3 服务端
internal/outbound/     出站队列、DKIM 签名、MX 投递
internal/tlsutil/      自签证书
internal/server/       路由、中间件、API handler
internal/web/dist/     前端静态资源（go:embed 内嵌）
tools/e2e_suite.py     端到端测试套件
```

## 版本

当前版本见 `-version` 或 Releases 页面。变更记录按 `v2.x.y` 打 tag，正文写在 Release 说明里。
