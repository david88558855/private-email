#!/usr/bin/env python3
# Private Email 全功能测试套件（v1.0）
import json, os, re, smtplib, ssl, subprocess, sys, time, imaplib, poplib, urllib.request, urllib.error, urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

BASE = os.environ.get('PE_BASE', 'http://localhost:8080/api/v1')
TAG = str(os.getpid())[-4:]  # 幂等后缀：可重复跑
PASS_N = 0; FAIL = []
def ok(name, cond, extra=''):
    global PASS_N
    if cond: PASS_N += 1; print(f'  ✓ {name}')
    else: FAIL.append(name); print(f'  ✗ {name} {extra}')

def http(path, data=None, token=None, method=None, timeout=6, raw=False, _retry=3):
    h = {'Content-Type': 'application/json'}
    if token: h['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(BASE + path, json.dumps(data).encode() if data is not None else None, h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        body = r.read()
        if raw: return r.status, body
        return r.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        if e.code == 429 and _retry > 0:
            time.sleep(15)
            return http(path, data, token, method, timeout, raw, _retry - 1)
        return e.code, json.loads(e.read() or b'{}')
    except Exception as e:
        return 0, {'error': str(e)}

def smtp_send(frm, to, subject, text, html=None):
    if html:
        m = MIMEMultipart('alternative')
        m.attach(MIMEText(text, 'plain', 'utf-8')); m.attach(MIMEText(html, 'html', 'utf-8'))
    else:
        m = MIMEText(text, 'plain', 'utf-8')
    m['From'] = frm; m['To'] = to; m['Subject'] = subject
    s = smtplib.SMTP('127.0.0.1', 2525, timeout=8)
    s.sendmail(frm, [to], m.as_string()); s.quit()

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

print('=== 1. 认证 ===')
pw = open(os.environ.get('PE_DATA', '/tmp/pe-run/data') + '/initial_admin_password.txt').read().split('password: ')[1].strip()
st, r = http('/auth/login', {'username': 'admin', 'password': 'wrong'}); ok('错误密码拒绝', st == 401)
st, r = http('/auth/login', {'username': 'admin', 'password': pw}); ok('登录', st == 200 and r.get('token')); T = r['token']
st, r = http('/auth/login', {'username': 'admin', 'password': pw}); T2 = r.get('token', '')
st, r = http('/me', token=T); ok('会话 /me', st == 200 and r.get('role') == 'admin')
st, _ = http('/me'); ok('无 token 401', st == 401)
st, _ = http('/me', token='x' * 40); ok('伪造 token 401', st == 401)

print('=== 2. SMTP 入站 ===')
smtp_send('noreply@service-a.com', 'admin@local.test', 'Plain Mail', 'code is 111222', '<p>code is <b>111222</b></p>')
smtp_send('noreply@service-b.com', 'admin@local.test', 'Chinese 中文主题', '验证码 334455 到期')
time.sleep(1.5)

print('=== 3. 邮件读取/搜索/操作 ===')
st, r = http('/mailboxes', token=T); ok('邮箱列表', st == 200 and len(r['items']) >= 1); MB = r['items'][0]['id']
st, r = http(f'/mailboxes/{MB}/folders', token=T)
folders = {f['name']: f for f in r['items']}
ok('默认四文件夹', all(n in folders for n in ['INBOX', 'Sent', 'Drafts', 'Trash']))
INBOX = folders['INBOX']['id']
st, r = http(f'/folders/{INBOX}/mails', token=T); ok('列表非空', st == 200 and r['total'] >= 2)
mails = r['items']; m0 = mails[0]
ok('验证码提取', m0['code'] in ('111222', '334455'), f"got={m0['code']}")
ok('中英主题解码', '中文主题' in ''.join(m['subject'] for m in mails))
st, r = http(f'/folders/{INBOX}/mails?q=334455', token=T); ok('FTS 数字检索', r['total'] >= 1)
st, r = http(f'/folders/{INBOX}/mails?q=service', token=T); ok('FTS 发件人检索', r['total'] >= 1)
st, r = http(f'/folders/{INBOX}/mails?q=' + urllib.parse.quote('中文'), token=T); ok('FTS 中文检索', r.get('total', 0) >= 1)
MID = m0['id']
st, r = http(f'/mails/{MID}', token=T); ok('详情+HTML', st == 200 and ('111222' in r['html_body'] or '334455' in r['text_body']))
ok('已读自动标记', 'Seen' in r['flags'])
st, r = http(f'/mails/{MID}/raw', token=T, raw=True); ok('EML 原文下载', st == 200 and b'MIME-Version' in r)
st, r = http(f'/mails/{MID}', token=T, method='DELETE'); ok('删除→Trash', st == 200)
st, r = http(f'/folders/{folders["Trash"]["id"]}/mails', token=T); ok('Trash 收纳', r['total'] >= 1)

print('=== 4. 越权防护 ===')
st, _ = http(f'/folders/{INBOX}/mails', token='faketoken'); ok('无效 token 列表 401', st == 401)
st, r = http('/admin/stats', token=T); ok('管理员 stats', st == 200)
st, r = http(f'/mails/{MID + 999999}', token=T); ok('不存在邮件 404/403', st in (403, 404))

print('=== 5. 撰写与出站（smarthost 回环） ===')
st, r = http(f'/mailboxes/{MB}/compose', {'to': 'admin@local.test', 'subject': 'Roundtrip self', 'text': 'loop body'}, token=T, method='POST')
ok('撰写入队', st == 200)
st, r = http('/queue', token=T); ok('队列接口', st == 200 and len(r.get('items', [])) >= 1)
time.sleep(24)
st, r = http(f'/folders/{INBOX}/mails?q=Roundtrip', token=T); ok('出站回环送达', r['total'] >= 1, f"total={r.get('total')}")

print('=== 6. IMAP ===')
M = imaplib.IMAP4('127.0.0.1', 2143)
try: M.login('admin@local.test', 'badpw'); ok('IMAP 错密码拒绝', False)
except Exception: ok('IMAP 错密码拒绝', True)
M.login('admin@local.test', pw)
typ, d = M.list(); ok('LIST', len(d) >= 4)
M.select('INBOX')
typ, d = M.search(None, 'ALL'); ids = d[0].split(); ok('SEARCH ALL', len(ids) >= 1, f'n={len(ids)}')
typ, d = M.fetch(ids[0], '(RFC822.SIZE FLAGS ENVELOPE BODY.PEEK[TEXT])'); ok('FETCH 全项', typ == 'OK' and len(d) >= 1)
typ, d = M.search(None, 'FROM', 'service'); ok('SEARCH FROM', len(d[0].split()) >= 1)
typ, d = M.search(None, 'SINCE', '01-Jan-2020'); ok('SEARCH SINCE', len(d[0].split()) >= 1)
typ, d = M.uid('SEARCH', 'ALL'); u = d[0].split()[0]
FOLDER = f'Qa{TAG}{int(time.time())}'
M.create(FOLDER)
M.uid('COPY', u, FOLDER); M.select(FOLDER)
typ, d = M.search(None, 'ALL'); ok('COPY 生效', len(d[0].split()) == 1)
typ, d = M.store('1', '+FLAGS', '\\Deleted'); M.select(FOLDER); M.expunge(); ok('EXPUNGE', True)
M.delete(FOLDER)
typ, d = M.status('INBOX', '(MESSAGES UNSEEN UIDNEXT UIDVALIDITY)'); ok('STATUS', typ == 'OK')
M.append('Sent', '(\\Seen)', None, b'From: admin@local.test\r\nSubject: via append ' + TAG.encode() + b'\r\n\r\nbody')
M.select('Sent'); typ, d = M.search(None, 'SUBJECT', 'append'); ok('APPEND', len(d[0].split()) >= 1)
M.logout()

print('=== 7. POP3 ===')
P = poplib.POP3('127.0.0.1', 2110)
P.user('admin@local.test'); P.pass_(pw)
n, sz = P.stat(); ok('STAT', n >= 2, f'n={n}')
ok('UIDL', len(P.uidl()[1]) == n)
resp, lines, oct = P.retr(1); ok('RETR', oct > 50)
resp, lines, oct = P.top(1, 2); ok('TOP', resp.startswith(b'+OK'))
P.dele(1); n2, _ = P.stat(); ok('DELE', n2 == n - 1)
P.rset(); n3, _ = P.stat(); ok('RSET', n3 == n)
P.quit()

print('=== 8. TLS ===')
try:
    s = smtplib.SMTP_SSL('127.0.0.1', 9465, context=ctx, timeout=5); s.noop(); s.quit(); ok('SMTPS', True)
except Exception as e: ok('SMTPS', False, str(e))
try:
    M = imaplib.IMAP4_SSL('127.0.0.1', 9943, ssl_context=ctx); M.login('admin@local.test', pw); M.logout(); ok('IMAPS', True)
except Exception as e: ok('IMAPS', False, str(e))
try:
    P = poplib.POP3_SSL('127.0.0.1', 9955, context=ctx); P.user('admin@local.test'); P.pass_(pw); P.quit(); ok('POP3S', True)
except Exception as e: ok('POP3S', False, str(e))
s = smtplib.SMTP('127.0.0.1', 2525, timeout=5); s.starttls(context=ctx); s.quit(); ok('SMTP STARTTLS', True)
M = imaplib.IMAP4('127.0.0.1', 2143); M.starttls(ssl_context=ctx); M.login('admin@local.test', pw); M.logout(); ok('IMAP STARTTLS', True)

print('=== 9. 邮箱自助管理 ===')
st, r = http('/domains', token=T); ok('域名列表(普通用户)', st == 200 and len(r['items']) >= 1); dom_id = r['items'][0]['id']
st, r = http('/mailboxes', {'prefix': 'qa-extra' + TAG, 'domain_id': dom_id}, token=T, method='POST')
ok('创建邮箱', st == 200 and ('qa-extra' + TAG) in r.get('address', ''))
st, r = http('/mailboxes', {'prefix': 'BAD NAME!', 'domain_id': dom_id}, token=T, method='POST'); ok('非法前缀拒绝', st == 400)
st, r = http('/mailboxes', {'prefix': 'admin', 'domain_id': dom_id}, token=T, method='POST'); ok('占用地址拒绝', st == 409)
mbs2 = http('/mailboxes', token=T)[1]['items']
newmb = [m for m in mbs2 if (TAG) in m['address'] and 'qa-extra' in m['address']]
st, r = http(f"/mailboxes/{newmb[0]['id']}", {'active': False}, token=T, method='PATCH'); ok('停用邮箱', st == 200)
mbs3 = http('/mailboxes', token=T)[1]['items']
ok('停用生效', [m for m in mbs3 if m['id'] == newmb[0]['id']][0]['is_active'] == False)

print('=== 10. 管理端 ===')
st, r = http('/admin/domains', token=T)
ok('域名列表', st == 200 and any('dkim_dns' in d for d in r['items']))
dkim_host = [d for d in r['items'] if 'dkim_dns' in d][0]['dkim_dns']['host']
ok('DKIM 记录格式', dkim_host.startswith('default._domainkey.'))
st, r = http('/admin/domains', token=T, method='POST', data={'domain': f'test-add-{TAG}.io'})
ok('新增域名', st == 200)
st, r = http('/admin/domains', token=T, method='POST', data={'domain': 'not a domain!'}); ok('非法域名拒绝', st == 400)
st, r = http('/admin/users', token=T, method='POST', data={'username': 'qa_user' + TAG, 'password': 'qapass99'})
ok('新增用户', st == 200)
st, r = http('/admin/users', token=T); qa = [u for u in r['items'] if u['username'] == 'qa_user' + TAG][0]
st, r = http(f'/admin/users/{qa["id"]}', {'op': 'disable'}, token=T, method='PATCH'); ok('禁用用户', st == 200)
st, r = http(f'/admin/users/{qa["id"]}', {'op': 'reset', 'password': 'newpass77'}, token=T, method='PATCH'); ok('重置密码', st == 200)
st, r = http(f'/admin/users/{qa["id"]}', {'op': 'enable'}, token=T, method='PATCH'); ok('重新启用', st == 200)
st, r = http('/auth/login', {'username': 'qa_user' + TAG, 'password': 'newpass77'}); ok('新密码登录', st == 200); QT = r['token']
st, r = http('/admin/stats', token=QT); ok('普通用户禁管理', st == 403)
st, r = http(f'/mailboxes/{MB}/folders', token=QT); ok('跨用户邮箱隔离', st == 403)
st, r = http('/auth/register', {'username': 'reg0' + TAG, 'password': 'regpass88'}); ok('默认关闭注册拒绝', st == 403)
st, r = http('/admin/settings', token=T); ok('读取设置', st == 200 and r.get('registration_enabled') == False)
st, r = http('/admin/settings', {'registration_enabled': True}, token=T, method='PUT'); ok('开启注册', st == 200)
st, r = http('/auth/register', {'username': 'reg1' + TAG, 'password': 'regpass88'}); ok('开放后注册成功', st == 200 and '@' in r.get('address', ''))
st, r = http('/auth/register', {'username': 'REG INVALID', 'password': 'regpass88'}); ok('非法用户名拒绝', st == 400)
st, r = http('/admin/settings', {'registration_enabled': False}, token=T, method='PUT'); ok('关闭注册', st == 200)
st, r = http('/auth/register', {'username': 'reg2' + TAG, 'password': 'regpass88'}); ok('关闭后注册拒绝', st == 403)
st, r = http('/admin/settings', token=T); ok('设置持久化', r.get('registration_enabled') == False)
st, r = http('/admin/users', token=T); ok('注册用户在列', any(u['username'] == 'reg1' + TAG for u in r['items']))
st, r = http(f'/mailboxes/{MB}/app_passwords', {'label': 'audit'}, token=T, method='POST'); apw = r.get('password', '')
ok('生成 App 密码', len(apw) >= 16)
M = imaplib.IMAP4('127.0.0.1', 2143); M.login('admin@local.test', apw); M.logout(); ok('App 密码 IMAP 登录', True)
st, r = http(f'/mailboxes/{MB}/app_passwords', token=T); ok('App 密码列表', any(x['label'] == 'audit' for x in r['items']))

print('=== 11. RCPT 拒收与限速 ===')
try:
    smtp_send('x@y.com', 'nobody@local.test', 't', 't'); ok('未知收件人拒收', False)
except smtplib.SMTPRecipientsRefused: ok('未知收件人拒收', True)
served = 0
for i in range(12):
    st, _ = http('/auth/login', {'username': 'admin', 'password': 'bad'}, _retry=0); served += (st == 429)
ok('登录限速触发', served >= 1, f'429x{served}')

print()
print(f'通过 {PASS_N} · 失败 {len(FAIL)}')
if FAIL: print('失败项:', *FAIL, sep='\n  - ')
sys.exit(1 if FAIL else 0)
