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

- IMAP4rev1（143 STARTTLS / 993 SSL）：`LOGIN` / `AUTHENTICATE PLAIN`，LIST / SELECT / STATUS / FETCH / SEARCH / STORE / COPY / APPEND / EXPUNGE
- POP3（110 / 995 SSL）：`USER/PASS` / `AUTH PLAIN`（RFC 5034）、STAT / LIST / UIDL / RETR / TOP / DELE / RSET / QUIT
- SMTP 提交（587）：`AUTH PLAIN` / `AUTH LOGIN`
- 三协议统一接受 Web 主密码或「App 专用密码」（独立令牌，**与邮箱一对一**：只能在生成它的那个地址上登录，
  数量不设上限，可单独撤销、带 `last_used` 审计，Web 端可**随时回显查看**；界面上「归属邮箱」可切换）

**Web 客户端**

- 三栏布局：文件夹导航（全部邮件 + 四文件夹）+ 邮件列表 + 阅读区，多邮箱下拉切换
- HTML 正文用 `sandbox` iframe + 文档内 CSP 渲染：脚本/表单/同源访问全禁，
  远程图片与外链资源默认阻断（避免追踪像素泄露收件人 IP、UA 与已读状态）；`data:` URI 图片可显示，
  `cid:` 内嵌图片暂不还原（后端未提取 Content-ID 附件），这类图片不会显示
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
5. 创建管理员 `admin`，**初始密码固定为 `admin`**（不再随机生成、也不写密码文件）

Web 控制台：<http://localhost:9000>，用 `admin` / `admin` 登录。

> 默认口令是公开信息，**首登必须立即改密**（账号设置 → 修改密码）；改密会同步该用户
> 所有邮箱的 IMAP/SMTP/POP3 协议密码。
> 自动化部署可用环境变量 `PRIVATE_EMAIL_ADMIN_PASSWORD` 覆盖初始密码，避免公开发布的默认值。
> 日志里会打印一条「默认口令」警告，直到你改密为止。

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

---

## 端口

| 用途 | 默认 | 配置键 |
|---|---|---|
| Web / API | `:9000` | `http.listen`（也可用 `-port`） |
| SMTP 收信 | `:25` | `smtp.listen` |
| SMTP 提交（需认证） | `:587` | `smtp.submission` |
| SMTPS 隐式 TLS | `:465` | `smtp.tls` |
| IMAP / IMAPS | `:143` / `:993` | `imap.listen` / `imap.tls` |
| POP3 / POP3S | `:110` / `:995` | `pop3.listen` / `pop3.tls` |

**留空即关闭该监听。** 管理后台「系统设置 → 协议端口」写入的值存在 `settings` 表，
优先级高于 `config.yaml`，**重启后生效**（Web 端口除外，Web 只能用 `-port` 或配置文件改）。
启动时会校验端口两两不冲突、并实际探测每个非空监听地址是否可绑定；
任何一项失败都直接拒绝启动，避免「打印了服务就绪却没有端口在听」。

---

## 配置（`data/config.yaml`）

```yaml
http:
  listen: ":9000"
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
  allow_insecure_auth: false        # 明文端口允许认证（默认关闭）
  insecure_auth_cidrs: []           # 允许明文认证的内网来源网段，如 ["192.168.10.0/24"]
  max_conns: 512
  idle_timeout_min: 30
```

各明文认证开关的含义与生产约束见下方「AUTH=PLAIN 与明文认证」。

---

## 数据与备份

```
data/
├── db.sqlite      # 全部数据：用户、域名、邮箱、邮件原文 BLOB、队列、设置
├── config.yaml    # 配置
├── certs/         # TLS 证书（自签或自有）
├── backup/        # 预留目录（当前代码未写入）
├── keys/          # App 专用密码密文密钥 app.key（0600，务必与 db.sqlite 一起备份）
└── logs/          # 预留目录（日志当前输出到 stdout）
```

备份方式：**停服务后拷贝 `db.sqlite`**（连同 `-wal`/`-shm` 一并拷，或先执行一次 checkpoint），
并把 `keys/app.key` 一起带走，否则恢复后 App 专用密码无法回显。
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

交叉编译无需 CGO（SQLite 用纯 Go 实现），Linux / Windows 产物使用同一套参数。

---

## 测试

`tools/e2e_suite.py` 是端到端套件（约 76 条），覆盖认证、SMTP 收发、IMAP/POP3、TLS、
权限隔离、管理端、限速等。它默认连以下端口，需要一套与之匹配的配置：

| 服务 | 端口 |
|---|---|
| HTTP | 9000 |
| SMTP / Submission / SMTPS | 2525 / 2587 / 9465 |
| IMAP / IMAPS | 2143 / 9943 |
| POP3 / POP3S | 2110 / 9955 |

```bash
# data/config.yaml 里把上面这些端口配好，启动服务后：
python3 tools/e2e_suite.py
# 可用环境变量覆盖：PE_BASE（默认 http://localhost:9000/api/v1）、PE_PW（默认 admin）
# 管理员默认口令就是 admin；若启动前设了 PRIVATE_EMAIL_ADMIN_PASSWORD，PE_PW 要跟着改。
```

其中「出站回环送达」依赖测试域名能被 DNS 解析（`.test` 域名默认不可解析），
在无本地 DNS 兜底的环境会失败并连带影响紧随其后的 POP3 STAT 计数，其余用例应全绿。

`tools/auth_plain_suite.py` 是独立令牌 / `AUTH=PLAIN` 专项套件（63 条），**自带构建与临时实例**，
不需要预先配置端口或已有数据：`python3 tools/auth_plain_suite.py`。详见「AUTH=PLAIN 与明文认证」。

---

## 安全说明

- **管理员初始密码固定为 `admin`**（不随机、不落盘成文件）：方便直接登录，但默认口令是公开信息，
  首次登录后必须立即改密；对外网暴露前建议改用环境变量 `PRIVATE_EMAIL_ADMIN_PASSWORD` 指定初始密码。
  改密会同步该用户所有邮箱的协议密码。
- **账号禁用立即生效**：JWT 每次请求都回查用户状态，禁用后旧 token 立刻失效（不必等 24h 过期）。
- **登录限速按真实来源 IP**：服务不信任 `X-Forwarded-For`。若部署在 Nginx/Cloudflare 之后，
  所有请求会呈现为反代 IP，限速粒度随之变粗——这需要在反代层做限速。
- **协议层允许明文认证**（`allow_insecure_auth`，兼容内网老客户端），默认关闭。
  启用条件、来源白名单与必要约束见下方「AUTH=PLAIN 与明文认证」；公网部署请只暴露
  STARTTLS/SSL 端口。
- 邮件 HTML 正文在 `sandbox` iframe 内渲染，脚本、表单、同源访问全部禁用；
  iframe 文档自带 CSP（`default-src 'none'`），远程图片/样式外链默认不加载。
- **App 专用密码可回显，因此是「密文落库」而不是单向哈希**：明文用 AES-256-GCM 加密后存
  `app_passwords.secret`，密钥在 `data/keys/app.key`（0600，首次启动生成）。
  单独泄露 `db.sqlite` 拿不到令牌；**备份必须把 `db.sqlite` 与 `keys/app.key` 一起带走**，
  只恢复数据库会导致历史令牌无法回显（仍能登录，因为同时保留了 bcrypt 哈希）。
  密钥文件损坏时程序拒绝启动，不会静默重建。
- DKIM 私钥与邮件原文同库存储，`db.sqlite` 泄露等同于邮箱与发信身份泄露，注意文件权限。

---

## AUTH=PLAIN 与明文认证（自建邮箱 / 局域网客户端）

**结论**：SMTP / IMAP / POP3 均已支持 SASL PLAIN，独立令牌（App 专用密码）在明文与 TLS 链路上
都能被真实客户端用于登录；无 TLS 模式**仅**适用于受控内网，必须按下述约束启用。

### 能力对照

| 协议 | 客户端命令 | 服务端能力发布 | 实现位置 |
|---|---|---|---|
| SMTP | `AUTH PLAIN <base64>` | EHLO `250-AUTH PLAIN LOGIN` | `internal/proto/smtp/smtp.go`（go-sasl） |
| IMAP | `AUTHENTICATE PLAIN <base64>` | CAPABILITY `AUTH=PLAIN` | go-imap v1 内置 SASL，本项目只做约束 |
| POP3 | `AUTH PLAIN [base64]` | CAPA `SASL PLAIN` | `internal/proto/pop3/pop3.go`（RFC 5034） |

PLAIN 载荷是 `[authzid]\0用户名\0密码` 的 base64（RFC 4616）；服务端不接受非空 `authzid`，
避免身份代理。POP3 同时支持带初始响应的 `AUTH PLAIN <base64>` 与先收空 challenge 再送凭据的两段式，
也保留原 `USER/PASS`。**base64 只是编码，不是加密**：未加密链路上能抓包就能还原凭据，
这是 PLAIN 的固有属性，不是实现缺陷。

### 适用范围

- **适用**：物理/逻辑隔离的局域网、家庭实验室、离线测试环境；老客户端或嵌入式设备不支持
  STARTTLS/隐式 TLS；客户端与服务端之间没有不可信设备。
- **不适用**：公网可达的 25/587/143/110；不可信 Wi-Fi、跨机房/跨运营商链路、经过不受控 NAT 的路径；
  有「禁止明文凭据传输」合规要求的场景。这些一律走 993/995/465 或 STARTTLS。

### 必要约束（生产启用前逐条确认）

1. **默认保持关闭**：`allow_insecure_auth: false`。此时明文端口不公布认证能力，客户端必须加密。
2. **绑定内网地址**：明文端口写 `192.168.10.5:143` 这类具体地址，不要用 `:143` 通配；
   防火墙上 25/110/143/587 只对内网开放。
3. **配置来源白名单**：`insecure_auth_cidrs` 明确列出客户端网段，如 `["192.168.10.0/24"]`。
   配好后即使监听写成通配，白名单外来源在明文连接上也一律拒绝；TLS 连接不受限制。
   CIDR 写错会**拒绝启动**，不会静默忽略（否则白名单形同虚设）。
4. **客户端一律用独立令牌**：Web 端「账号设置 → App 专用密码」每台客户端生成一个（先在「归属邮箱」选好地址，
   客户端用户名必须填同一个地址，令牌与邮箱严格一对一），
   **绝不把 Web 主密码填进明文客户端**。令牌泄露可单独撤销、不改主密码；`last_used` 有审计记录。
5. **注意 L4 代理**：来源判定用 TCP `RemoteAddr`。前面有 L4 代理时服务端看到的是代理 IP，
   必须把代理 IP 加进白名单并在代理层限制来源（HTTP 反代不影响协议端口）。
6. **保留加密端口**：启用明文也不要关闭 993/995/465，管理员与外网用户必须走加密。
7. **不要关掉既有防护**：认证失败限速（单 IP 10 次/5 分钟）、并发上限、空闲超时照常生效。

```yaml
# data/config.yaml（内网明文场景示例）
imap:
  listen: "192.168.10.5:143"
  tls: ":993"
pop3:
  listen: "192.168.10.5:110"
  tls: ":995"
security:
  allow_insecure_auth: true
  insecure_auth_cidrs: ["192.168.10.0/24"]
```

开启后启动日志会打印醒目警告；若白名单为空，会明确提示「任意来源都可在明文端口提交凭据」。

### 已知边界

- go-imap / go-smtp 的 `AllowInsecureAuth` 是**全局**开关，无法按连接隐藏能力：开启白名单后，
  白名单外来源仍能看到 `AUTH=PLAIN` / `250-AUTH PLAIN`，但认证必然失败
  （IMAP `NO`、SMTP `538 5.7.11`）。POP3 的 CAPA 是按连接判断的，白名单外来源看不到 `SASL PLAIN`。
- 25/587/465 共用同一个 SMTP Server：开启明文认证后 **25 入站端口同样提供 AUTH**。请靠防火墙或
  白名单约束 25 的来源，不要把它当成「只收信、不能认证」的端口。
- 这些边界已写进回归套件断言，升级依赖库后行为变化会直接暴露。

### 验证方式

```bash
go test ./...
python3 tools/auth_plain_suite.py
```

套件自动构建二进制、在临时目录用高位端口起隔离实例，依次切换 4 组策略并核对三协议明文/TLS 登录、
能力发布、令牌撤销与 `last_used` 审计、白名单放行/拒绝、非法 CIDR 拒绝启动（共 63 条断言）。
它使用真实 `imaplib` / `poplib` / `smtplib` 客户端，并用原生 socket 校验 SASL 交互细节。

---

## 已知限制

- 出站直连 MX 需要服务器本身具备公网 DNS 与出站 25 端口；多数云厂商默认封 25，需申请解封或配 smarthost。
- POP3 会话会一次性索引该文件夹**全部**邮件的元数据（正文按需拉取，不整体载入内存），
  超大邮箱的内存占用随邮件数增长；`QUIT` 时对 `DELE` 的邮件在一个事务内执行**永久删除**，不进垃圾箱。
- IMAP `SEARCH` 会逐封解析正文，单邮箱体量很大时较慢。
- 暂无邮箱删除、附件下载、多用户共享文件夹等能力。

**部署前必须知道的剩余风险**（三轮审查确认，属架构取舍，未在本次改动范围内）：

- **JWT 无服务端会话**：改密或管理员重置密码后，旧 24h token 仍有效（中间件只回查 status/role）。
  `sessions` 表已在迁移中建好但未启用；公网部署应缩短 token 有效期或接入该表。
- **前端 CSP 仍保留 `unsafe-inline`**：内联 `onclick` 尚未改成事件委托，`script-src` 无法收紧。
  服务端插值已做 `esc()` 转义，但 XSS 兜底弱于严格 CSP。
- **出站队列按单实例设计**：单 goroutine 串行投递、无 in-flight 认领，多副本或崩溃重启可能重复投递；
  认证限速桶与 POP3 maildrop 锁同样是进程内状态，多实例不共享。
- **出站默认放行私网地址（有意设计，已确认保持）**：自建/局域网邮箱需要直连内网 MX，
  默认禁止会直接打断内网投递。公网部署请配 smarthost 并在防火墙限制出站 25，
  避免被当作内网探测跳板。

---

## 目录结构

```
cmd/server/            程序入口（flag、启动编排、端口设置覆盖）
internal/config/       配置加载与默认值
internal/database/     连接、迁移（含 FTS5 触发器）
internal/store/        SQLite 读写层（邮件、邮箱、设置、认证）
internal/mailutil/     MIME 解析、验证码提取
internal/proto/smtp/   SMTP 服务端（入站 + 提交）
internal/insecureauth/ 明文认证来源策略（三协议共用）
internal/proto/imap/   IMAP4rev1 服务端
internal/proto/pop3/   POP3 服务端（含 RFC 5034 AUTH PLAIN）
internal/outbound/     出站队列、DKIM 签名、MX 投递
internal/tlsutil/      自签证书
internal/secrets/      App 专用密码密文（AES-256-GCM，密钥 data/keys/app.key）
internal/server/       路由、中间件、API handler
internal/web/dist/     前端静态资源（go:embed 内嵌）
tools/e2e_suite.py     端到端测试套件
tools/auth_plain_suite.py  独立令牌 / AUTH=PLAIN 专项套件
```

## 版本

当前版本见 `-version` 或 Releases 页面。变更记录按 `v2.x.y` 打 tag，正文写在 Release 说明里。
