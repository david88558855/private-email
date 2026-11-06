#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AUTH=PLAIN 与独立令牌（App 专用密码）三协议回归套件。

自行构建二进制、用高位端口启动隔离实例，依次切换 4 组明文认证策略并验证：
  A  allow_insecure_auth=true / 无白名单      -> 明文 PLAIN 全协议可用
  B  allow_insecure_auth=false                -> 明文认证全拒，TLS 端口仍可用
  C1 allow_insecure_auth=true / 白名单不含本机 -> 本机明文认证被拒，TLS 仍可用
  C2 allow_insecure_auth=true / 白名单含本机   -> 本机明文认证放行

用法：python3 tools/auth_plain_suite.py
退出码 0 表示全部通过。需要 go、python3，且下面这组端口未被占用。
"""
import base64, json, os, secrets, shutil, socket, ssl, subprocess, sys, tempfile, time, urllib.error, urllib.request
import imaplib, poplib, smtplib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = '127.0.0.1'
P = dict(http=19180, smtp=22525, submission=22587, smtps=29465,
         imap=22143, imaps=29943, pop3=22110, pop3s=29955)
BASE = f'http://{HOST}:{P["http"]}/api/v1'
# 套件自启实例用固定的初始口令（与默认值一致，写出来只是显式化）：
# 默认管理员口令本身就是 admin，服务不会再生成 initial_admin.txt。
CHILD_ENV = dict(os.environ, PRIVATE_EMAIL_ADMIN_PASSWORD='admin')
# 每次运行生成一次测试密钥并在所有场景间保持稳定，避免重启导致 JWT 失效；
# 不硬编码固定串，防止模板被误抄到生产。
TEST_JWT = secrets.token_hex(32)
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

PASS_N, FAIL = 0, []

def ok(name, cond, detail=''):
    global PASS_N
    if cond:
        PASS_N += 1
        print(f'  [PASS] {name}')
    else:
        FAIL.append(name)
        print(f'  [FAIL] {name} {detail}')

def rejected(name, fn):
    """期望被拒绝：任何异常都算通过，正常返回算失败。"""
    try:
        r = fn()
        ok(name, False, f'竟被放行: {r}')
    except Exception as e:
        ok(name, True)

def accepted(name, fn):
    try:
        fn()
        ok(name, True)
    except Exception as e:
        ok(name, False, f'{type(e).__name__}: {e}')

def http(path, data=None, token=None, method=None):
    h = {'Content-Type': 'application/json'}
    if token:
        h['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(BASE + path,
                                 json.dumps(data).encode() if data is not None else None, h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=6)
        return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')
    except Exception as e:
        return 0, {'error': str(e)}

def plain(user, pw):
    return base64.b64encode(b'\x00' + user.encode() + b'\x00' + pw.encode())

def connect(port, tls=False):
    s = socket.create_connection((HOST, port), 5)
    if tls:
        s = CTX.wrap_socket(s, server_hostname='localhost')
    return s, s.makefile('rb')

def imap_capability():
    s, f = connect(P['imap'])
    banner = f.readline().decode(errors='replace')
    s.sendall(b'A001 CAPABILITY\r\n')
    lines = [banner]
    for _ in range(10):
        ln = f.readline().decode(errors='replace').strip()
        if not ln:
            break
        lines.append(ln)
        if ln.startswith('A001 '):
            break
    s.close()
    return ' '.join(lines)

def smtp_capability(port=None):
    c = smtplib.SMTP(HOST, port or P['submission'], timeout=6)
    c.ehlo()
    caps = c.esmtp_features.get('auth', '')
    c.quit()
    return caps

def pop3_capa():
    s, f = connect(P['pop3'])
    f.readline()
    s.sendall(b'CAPA\r\n')
    lines = []
    for _ in range(12):
        ln = f.readline().decode(errors='replace').strip()
        if ln == '.' or not ln:
            break
        lines.append(ln)
    s.close()
    return ' '.join(lines)

def imap_auth_plain(user, pw, tls=False):
    s, f = connect(P['imaps'] if tls else P['imap'], tls)
    f.readline()
    s.sendall(b'A001 AUTHENTICATE PLAIN ' + plain(user, pw) + b'\r\n')
    reply = f.readline().decode(errors='replace').strip()
    s.close()
    if 'OK' not in reply:
        raise RuntimeError('IMAP AUTHENTICATE PLAIN: ' + reply)
    return reply

def pop3_auth_plain(user, pw, initial=True, tls=False):
    s, f = connect(P['pop3s'] if tls else P['pop3'], tls)
    f.readline()
    if initial:
        s.sendall(b'AUTH PLAIN ' + plain(user, pw) + b'\r\n')
    else:
        s.sendall(b'AUTH PLAIN\r\n')
        challenge = f.readline().decode(errors='replace').strip()
        if not challenge.startswith('+'):
            raise RuntimeError('缺少 SASL challenge: ' + challenge)
        s.sendall(plain(user, pw) + b'\r\n')
    reply = f.readline().decode(errors='replace').strip()
    if not reply.startswith('+OK'):
        raise RuntimeError('POP3 AUTH PLAIN: ' + reply)
    s.sendall(b'STAT\r\n')
    stat = f.readline().decode(errors='replace').strip()
    s.close()
    if not stat.startswith('+OK'):
        raise RuntimeError('认证后未进入 TRANSACTION: ' + stat)
    return reply, stat

def imap_login(user, pw, tls=False):
    m = imaplib.IMAP4_SSL(HOST, P['imaps'], ssl_context=CTX) if tls else imaplib.IMAP4(HOST, P['imap'])
    m.login(user, pw)
    m.logout()

def pop3_login(user, pw, tls=False):
    p = poplib.POP3_SSL(HOST, P['pop3s'], context=CTX) if tls else poplib.POP3(HOST, P['pop3'])
    p.user(user)
    p.pass_(pw)
    p.stat()
    p.quit()

def smtp_auth(user, pw, tls=False):
    c = smtplib.SMTP_SSL(HOST, P['smtps'], context=CTX, timeout=6) if tls else smtplib.SMTP(HOST, P['submission'], timeout=6)
    c.ehlo()
    c.login(user, pw)
    c.quit()

CONFIG = """http:
  listen: ":{http}"
smtp:
  listen: ":{smtp}"
  submission: ":{submission}"
  tls: ":{smtps}"
  max_size_mb: 25
imap:
  listen: ":{imap}"
  tls: ":{imaps}"
pop3:
  listen: ":{pop3}"
  tls: ":{pop3s}"
tls:
  hostname: "localhost"
security:
  jwt_secret: "{jwt}"
  login_rate_per_min: 100
  allow_insecure_auth: {allow}
  insecure_auth_cidrs: {cidrs}
  skip_domain_verification: true
"""

def write_config(data_dir, allow, cidrs):
    body = CONFIG.format(allow='true' if allow else 'false',
                         cidrs='[' + ', '.join(f'"{c}"' for c in cidrs) + ']',
                         jwt=TEST_JWT, **P)
    with open(os.path.join(data_dir, 'config.yaml'), 'w', encoding='utf-8') as f:
        f.write(body)

def precheck_ports():
    """启动前确认整组端口空闲，避免误连到别的服务而「假通过」。"""
    for name, port in P.items():
        s = socket.socket()
        try:
            s.bind((HOST, port))
        except OSError:
            print(f'端口 {port} ({name}) 已被占用，请先释放后重试')
            sys.exit(1)
        finally:
            s.close()


def start(binary, data_dir, logf):
    proc = subprocess.Popen([binary, '-data', data_dir], stdout=logf,
                            stderr=subprocess.STDOUT, env=CHILD_ENV)
    for _ in range(60):
        try:
            s = socket.create_connection((HOST, P['http']), 0.3)
            s.close()
            if proc.poll() is None:
                return proc
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError('服务启动即退出，见日志')
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError('HTTP 端口未就绪')

def stop(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    time.sleep(0.6)

def tls_group(label, mbox, token):
    accepted(f'{label} IMAPS LOGIN + 独立令牌', lambda: imap_login(mbox, token, tls=True))
    accepted(f'{label} IMAPS AUTHENTICATE PLAIN + 独立令牌', lambda: imap_auth_plain(mbox, token, tls=True))
    accepted(f'{label} POP3S AUTH PLAIN + 独立令牌', lambda: pop3_auth_plain(mbox, token, tls=True))
    accepted(f'{label} SMTPS AUTH + 独立令牌', lambda: smtp_auth(mbox, token, tls=True))

def plaintext_allowed_group(label, mbox, token, main):
    accepted(f'{label} IMAP LOGIN + 独立令牌', lambda: imap_login(mbox, token))
    accepted(f'{label} IMAP AUTHENTICATE PLAIN + 独立令牌', lambda: imap_auth_plain(mbox, token))
    accepted(f'{label} POP3 USER/PASS + 独立令牌', lambda: pop3_login(mbox, token))
    accepted(f'{label} POP3 AUTH PLAIN (initial response) + 独立令牌',
             lambda: pop3_auth_plain(mbox, token, initial=True))
    accepted(f'{label} POP3 AUTH PLAIN (challenge/response) + 独立令牌',
             lambda: pop3_auth_plain(mbox, token, initial=False))
    accepted(f'{label} SMTP AUTH PLAIN + 独立令牌', lambda: smtp_auth(mbox, token))
    accepted(f'{label} 主密码同样可用（回归保护）', lambda: smtp_auth(mbox, main))

def plaintext_rejected_group(label, mbox, token):
    rejected(f'{label} IMAP LOGIN 被拒', lambda: imap_login(mbox, token))
    rejected(f'{label} IMAP AUTHENTICATE PLAIN 被拒', lambda: imap_auth_plain(mbox, token))
    rejected(f'{label} POP3 USER/PASS 被拒', lambda: pop3_login(mbox, token))
    rejected(f'{label} POP3 AUTH PLAIN 被拒', lambda: pop3_auth_plain(mbox, token))
    rejected(f'{label} SMTP AUTH PLAIN 被拒', lambda: smtp_auth(mbox, token))

def main():
    tmp = tempfile.mkdtemp(prefix='pe-authplain-')
    data_dir = os.path.join(tmp, 'data')
    os.makedirs(data_dir)
    binary = os.path.join(tmp, 'private-email.exe' if os.name == 'nt' else 'private-email')
    print(f'工作目录: {tmp}')
    print('=== 构建 ===')
    r = subprocess.run(['go', 'build', '-o', binary, './cmd/server'], cwd=ROOT,
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        return 1
    print('  构建通过')

    precheck_ports()
    log_path = os.path.join(tmp, 'server.log')
    proc = None
    try:
        with open(log_path, 'w', encoding='utf-8') as logf:
            # ---------- 场景 A：明文认证开启，无白名单 ----------
            print('\n=== A. allow_insecure_auth=true / 无白名单 ===')
            write_config(data_dir, True, [])
            proc = start(binary, data_dir, logf)
            st, r = http('/auth/login', {'username': 'admin', 'password': 'admin'})
            if st != 200:
                print('登录失败', st, r)
                return 1
            T = r['token']
            http('/admin/domains', {'domain': 'suite.test'}, token=T, method='POST')
            _, dl = http('/admin/domains', token=T)
            dom = [d for d in dl['items'] if d['domain'] == 'suite.test'][0]
            _, mb = http('/mailboxes', {'prefix': 'suite', 'domain_id': dom['id']}, token=T, method='POST')
            MBOX = mb['address']
            _, mbs = http('/mailboxes', token=T)
            MBID = [m['id'] for m in mbs['items'] if m['address'] == MBOX][0]
            _, ap = http(f'/mailboxes/{MBID}/app_passwords', {'label': 'suite'}, token=T, method='POST')
            TOKEN = ap['password']
            ok('独立令牌生成', len(TOKEN) >= 16, f'len={len(TOKEN)}')
            ok('IMAP CAPABILITY 公布 AUTH=PLAIN', 'AUTH=PLAIN' in imap_capability())
            ok('SMTP EHLO 公布 AUTH PLAIN', 'PLAIN' in smtp_capability().upper(), smtp_capability())
            ok('POP3 CAPA 公布 SASL PLAIN', 'SASL PLAIN' in pop3_capa().upper(), pop3_capa())
            # 25/587/465 共用同一个 go-smtp Server，25 入站端口也会公布 AUTH。
            # 这是既有设计，明文模式下必须靠白名单或防火墙约束 25 的来源。
            ok('A 25 入站端口同样提供 AUTH（已知边界）', 'PLAIN' in smtp_capability(P['smtp']).upper())
            plaintext_allowed_group('A', MBOX, TOKEN, 'admin')
            tls_group('A', MBOX, TOKEN)
            rejected('A 错误令牌被拒', lambda: smtp_auth(MBOX, 'wrong-token-value'))

            # ---------- 令牌与邮箱一对一 / 随时可回显 ----------
            # 回归点：一份令牌只属于生成它的邮箱。拿它去登同账号的另一个地址必须失败，
            # 否则等于「一个客户端的凭据能开全部信箱」。主密码则是账号口令，仍能登。
            _, mb2 = http('/mailboxes', {'prefix': 'suite2nd', 'domain_id': dom['id']},
                          token=T, method='POST')
            MBOX2 = mb2.get('address', '')
            ok('A 同账号第二个邮箱创建成功', bool(MBOX2), str(mb2))
            rejected('A 独立令牌不得用于同账号另一邮箱（IMAP）', lambda: imap_login(MBOX2, TOKEN))
            rejected('A 独立令牌不得用于同账号另一邮箱（SMTP）', lambda: smtp_auth(MBOX2, TOKEN))
            accepted('A 同账号另一邮箱主密码仍可用（回归保护）', lambda: imap_login(MBOX2, 'admin'))
            accepted('A 独立令牌可用于颁发它的邮箱（回归保护）', lambda: imap_login(MBOX, TOKEN))
            _, lst = http(f'/mailboxes/{MBID}/app_passwords', token=T)
            ok('A 独立令牌可随时回看（列表回显明文）',
               any(x.get('password') == TOKEN for x in lst['items']), str(lst)[:200])

            # ---------- 撤销令牌 / 审计 ----------
            _, used = http(f'/mailboxes/{MBID}/app_passwords', token=T)
            ok('独立令牌 last_used 有审计记录',
               any(x['label'] == 'suite' and x['last_used'] for x in used['items']), str(used))
            _, items = http(f'/mailboxes/{MBID}/app_passwords', token=T)
            pid = [x['id'] for x in items['items'] if x['label'] == 'suite'][0]
            http(f'/mailboxes/{MBID}/app_passwords?pid={pid}', token=T, method='DELETE')
            rejected('撤销后独立令牌失效', lambda: imap_login(MBOX, TOKEN))
            _, ap2 = http(f'/mailboxes/{MBID}/app_passwords', {'label': 'suite2'}, token=T, method='POST')
            TOKEN = ap2['password']
            accepted('新令牌生效', lambda: imap_login(MBOX, TOKEN))

            # ---------- 场景 B：默认关闭 ----------
            stop(proc); proc = None
            print('\n=== B. allow_insecure_auth=false（默认）===')
            write_config(data_dir, False, [])
            proc = start(binary, data_dir, logf)
            st, r = http('/auth/login', {'username': 'admin', 'password': 'admin'})
            T = r['token']
            ok('B IMAP 不公布 AUTH=PLAIN', 'AUTH=PLAIN' not in imap_capability(), imap_capability())
            ok('B SMTP 不公布 AUTH PLAIN', 'PLAIN' not in smtp_capability().upper(), smtp_capability())
            ok('B POP3 不公布 SASL PLAIN', 'SASL PLAIN' not in pop3_capa().upper(), pop3_capa())
            plaintext_rejected_group('B', MBOX, TOKEN)
            tls_group('B', MBOX, TOKEN)

            # ---------- 场景 C1：白名单不含本机 ----------
            stop(proc); proc = None
            print('\n=== C1. allow_insecure_auth=true / 白名单 10.0.0.0/8（不含 127.0.0.1）===')
            write_config(data_dir, True, ['10.0.0.0/8'])
            proc = start(binary, data_dir, logf)
            ok('C1 POP3 不公布 SASL PLAIN', 'SASL PLAIN' not in pop3_capa().upper(), pop3_capa())
            # go-imap / go-smtp 的 AllowInsecureAuth 是全局开关，无法按来源隐藏能力：
            # 白名单外来源仍能看到 AUTH，但认证回调一律拒绝（IMAP NO / SMTP 538）。
            ok('C1 IMAP 仍公布 AUTH=PLAIN（库边界，认证回调拒绝）', 'AUTH=PLAIN' in imap_capability())
            ok('C1 SMTP 仍公布 AUTH PLAIN（库边界，认证回调拒绝）', 'PLAIN' in smtp_capability().upper())
            plaintext_rejected_group('C1', MBOX, TOKEN)
            tls_group('C1', MBOX, TOKEN)

            # ---------- 场景 C2：白名单含本机 ----------
            stop(proc); proc = None
            print('\n=== C2. allow_insecure_auth=true / 白名单 127.0.0.1/32 ===')
            write_config(data_dir, True, ['127.0.0.1/32'])
            proc = start(binary, data_dir, logf)
            ok('C2 POP3 公布 SASL PLAIN', 'SASL PLAIN' in pop3_capa().upper(), pop3_capa())
            plaintext_allowed_group('C2', MBOX, TOKEN, 'admin')
            tls_group('C2', MBOX, TOKEN)

            # ---------- 配置错误必须拒绝启动 ----------
            stop(proc); proc = None
            print('\n=== D. 非法 CIDR 必须拒绝启动 ===')
            write_config(data_dir, True, ['192.168.1.0/99'])
            bad = subprocess.Popen([binary, '-data', data_dir], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, env=CHILD_ENV)
            try:
                out, _ = bad.communicate(timeout=8)
                rc = bad.returncode
            except subprocess.TimeoutExpired:
                bad.kill()
                out, _ = bad.communicate()
                rc = 'timeout'
            ok('D 非法 CIDR 拒绝启动', rc != 0 and 'insecure_auth_cidrs' in out, f'rc={rc}')
    finally:
        stop(proc)
        shutil.rmtree(tmp, ignore_errors=True)

    print(f'\n通过 {PASS_N} · 失败 {len(FAIL)}')
    if FAIL:
        print('失败项:', *FAIL, sep='\n  - ')
    return 1 if FAIL else 0

if __name__ == '__main__':
    sys.exit(main())
