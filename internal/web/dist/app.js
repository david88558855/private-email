/* Private Email WebUI · @material/web 版（V2.1 设计稿对齐） */
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const api = {
  token: localStorage.getItem('pe_token') || '',
  async req(path, opt = {}) {
    const h = { 'Content-Type': 'application/json', ...(opt.headers || {}) };
    if (this.token) h.Authorization = 'Bearer ' + this.token;
    const r = await fetch('/api/v1' + path, { ...opt, headers: h });
    if (r.status === 401) { this.token = ''; throw new Error('unauthorized'); }
    if (!r.ok) throw (await r.json().catch(() => ({ error: r.statusText })));
    return r.json();
  },
};

const state = {
  view: 'dashboard', folder: null, mail: null, mails: [], filter: 'all',
  mailboxes: [], folders: [], mb: null, me: null, q: '', admTab: 'ov',
};

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmtSize = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + 'M' : n > 1024 ? (n / 1024).toFixed(0) + 'K' : n + 'B';
function fmtTime(s) {
  const d = new Date(s.includes('T') ? s : s.replace(' ', 'T') + 'Z');
  const now = new Date();
  return d.toDateString() === now.toDateString()
    ? d.toTimeString().slice(0, 5)
    : `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.open = true; }

/* ---------- 主题 ---------- */
function setTheme(t) { document.documentElement.dataset.theme = t; localStorage.setItem('pe_theme', t); }
setTheme(localStorage.getItem('pe_theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
$('#btnTheme').onclick = () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');

/* ---------- 路由 ---------- */
const VIEWS = {
  dashboard: { title: '仪表板', icon: 'i-dash', group: '邮件' },
  inbox: { title: '收件箱', icon: 'i-inbox', group: '邮件' },
  mailboxes: { title: '邮箱管理', icon: 'i-mail', group: '管理' },
  forward: { title: '转发规则', icon: 'i-fwd', group: '管理' },
  verif: { title: '验证码规则', icon: 'i-key', group: '管理' },
  settings: { title: '账号设置', icon: 'i-tune', group: '管理' },
  admin: { title: '管理面板', icon: 'i-shield', group: '管理', adminOnly: true },
};
function renderNav() {
  const nav = $('#sideNav');
  const unread = state.folders.find((f) => f.name === 'INBOX')?.unread || 0;
  let html = '', group = '';
  for (const [id, v] of Object.entries(VIEWS)) {
    if (v.adminOnly && state.me?.role !== 'admin') continue;
    if (v.group !== group) { group = v.group; html += `<div class="nav-label">${group}</div>`; }
    const badge = id === 'inbox' ? `<span class="nav-badge ${unread ? '' : 'zero'}">${unread}</span>` : '';
    html += `<button class="nav-item ${state.view === id ? 'on' : ''}" data-v="${id}">
      <svg class="ic"><use href="#${v.icon}"/></svg>${v.title}${badge}</button>`;
  }
  nav.innerHTML = html;
  nav.querySelectorAll('.nav-item').forEach((b) => b.onclick = () => showView(b.dataset.v));
}
async function showView(v) {
  if (v === 'login') return;
  state.view = v;
  $$('#content .view').forEach((e) => (e.hidden = true));
  $(`#v-${v}`).hidden = false;
  $('#viewTitle').textContent = VIEWS[v].title;
  renderNav();
  const loaders = { dashboard: loadDashboard, inbox: loadInbox, mailboxes: loadMailboxes,
    forward: () => loadRules('forward'), verif: () => loadRules('verif'),
    settings: loadSettings, admin: loadAdmin };
  try { await (loaders[v] || (() => {}))(); } catch (e) { if (e.message !== 'unauthorized') toast(e.error || '加载失败'); }
}

/* ---------- 登录 ---------- */
async function initLogin() {
  try {
    const s = await fetch('/api/v1/settings').then((r) => r.json());
    if (s.registration_enabled) $('#lgReg').style.display = 'inline';
  } catch {}
}
async function doLogin() {
  $('#lgErr').textContent = '';
  try {
    const r = await api.req('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: $('#lgUser').value.trim(), password: $('#lgPass').value }),
    });
    api.token = r.token;
    localStorage.setItem('pe_token', r.token);
    boot();
  } catch (e) { $('#lgErr').textContent = e.error || '登录失败'; }
}
$('#lgBtn').onclick = doLogin;
$('#lgPass').addEventListener('keydown', (e) => e.key === 'Enter' && doLogin());
$('#lgAdmin').onclick = () => { $('#lgUser').focus(); toast('请使用管理员账号登录'); };
$('#lgForgot').onclick = () => toast('请联系管理员重置密码');
$('#lgReg').onclick = () => toast('注册功能未开放或请联系管理员');

$('#btnLogout').onclick = () => { localStorage.removeItem('pe_token'); location.reload(); };
$('#btnRefresh').onclick = () => showView(state.view);

/* ---------- 启动 ---------- */
async function boot() {
  try { state.me = await api.req('/me'); } catch { return showLogin(); }
  $('#v-login').style.display = 'none';
  $('#shell').style.display = 'flex';
  const initial = (state.me.username || '?')[0].toUpperCase();
  $('#sideName').textContent = state.me.username;
  $('#topAvatar').textContent = initial;
  $('#sideAvatar').textContent = initial;
  $('#sideRole').textContent = state.me.role === 'admin' ? '管理员工作台' : '用户工作台';
  state.mailboxes = (await api.req('/mailboxes')).items;
  state.mb = state.mailboxes[0] || null;
  if (state.mb) state.folders = (await api.req(`/mailboxes/${state.mb.id}/folders`)).items;
  renderNav();
  showView(state.me.role === 'admin' ? 'dashboard' : 'dashboard');
  setInterval(async () => {
    if (state.view === 'inbox' && !state.q && state.folder) { await refreshFolders(); await loadMails(true); }
  }, 20000);
}
async function refreshFolders() {
  if (state.mb) state.folders = (await api.req(`/mailboxes/${state.mb.id}/folders`)).items;
  renderNav();
}
function showLogin() {
  $('#shell').style.display = 'none';
  $('#v-login').style.display = 'flex';
  initLogin();
}

/* ---------- 仪表板 ---------- */
async function loadDashboard() {
  const d = await api.req('/dashboard');
  $('#stMb').textContent = d.mailboxes;
  $('#stToday').textContent = d.today;
  $('#stUnread').textContent = d.unread;
  $('#stUnreadSub').textContent = d.unread ? '含验证码邮件' : '已全部处理';
  $('#stStore').innerHTML = fmtSize(d.storage_bytes);
  $('#stStoreSub').textContent = '全部邮件占用';
  const hour = new Date().getHours();
  $('#greet').textContent = (hour < 6 ? '夜深了' : hour < 12 ? '早上好' : hour < 18 ? '下午好' : '晚上好')
    + '，' + state.me.username;
  $('#greetSub').textContent = `今天有 ${d.today} 封新邮件，${d.unread} 封未读`;
  const max = Math.max(...d.trend.map((t) => t.count), 1);
  $('#trendChart').innerHTML = d.trend.map((t) => `
    <div class="tcol"><div class="tbar" title="${t.count} 封" style="height:${Math.max(t.count / max * 100, 3)}%"></div>
      <span class="tday">${t.day.slice(5)}</span></div>`).join('');
  $('#dashRecent').innerHTML = d.recent.length ? d.recent.map((m) => `
    <div class="dm-item" data-id="${m.id}">
      <span class="dm-dot ${m.unread ? '' : 'read'}"></span>
      <div class="dm-main"><div class="dr-from">${esc(m.sender)}
        ${m.code ? `<span class="snip">${esc(m.code)}</span>` : ''}</div>
      <div class="dr-sub">${m.subject ? esc(m.subject) : '(无主题)'}</div></div>
      <span class="dm-time">${esc((m.created_at || '').slice(5, 10))}</span>
    </div>`).join('')
    : '<p class="hint">暂无邮件</p>';
  $('#dashRecent').querySelectorAll('.dm-item').forEach((el) => el.onclick = () => showView('inbox'));
}

/* ---------- 收件箱 ---------- */
async function loadInbox() {
  await refreshFolders();
  if (!state.folder) {
    const inbox = state.folders.find((f) => f.name === 'INBOX');
    state.folder = inbox?.id || state.folders[0]?.id;
  }
  await loadMails(true);
}
async function loadMails(silent) {
  const p = state.q ? `?q=${encodeURIComponent(state.q)}&limit=50` : '?limit=50';
  const r = await api.req(`/folders/${state.folder}/mails${p}`);
  let items = r.items;
  if (state.filter === 'unread') items = items.filter((m) => !m.flags.includes('\\Seen'));
  state.mails = items;
  $('#listMeta').textContent = `共 ${r.total} 封 · 未读 ${state.folders.find((f) => f.id === state.folder)?.unread ?? 0}`;
  renderList();
  if (!silent) renderReader();
}
function renderList() {
  const box = $('#mailList');
  if (!state.mails.length) { box.innerHTML = '<div style="padding:32px;text-align:center;color:var(--osv)">暂无邮件</div>'; return; }
  box.innerHTML = state.mails.map((m) => `
    <div class="m-item ${state.mail?.id === m.id ? 'on' : ''} ${m.flags.includes('\\Seen') ? '' : 'unread'}" data-id="${m.id}">
      <div class="l1"><span class="from">${esc(m.sender)}</span><span class="time">${fmtTime(m.created_at)}</span></div>
      <div class="l2"><span class="subj">${m.subject ? esc(m.subject) : '(无主题)'}</span>
        <span>${m.code ? `<span class="chip">${esc(m.code)}</span>` : ''}${m.spam_score >= 4 ? '<span class="chip warn">可疑</span>' : ''}</span></div>
      <div class="snip">${m.code ? '验证码 ' + esc(m.code) : ''} ${fmtSize(m.size)}</div>
    </div>`).join('');
  box.querySelectorAll('.m-item').forEach((el) => el.onclick = () => openMail(+el.dataset.id));
}
async function openMail(id) {
  state.mail = await api.req(`/mails/${id}`);
  renderList();
  renderReader();
  refreshFolders();
}
function renderReader() {
  const box = $('#reader');
  const m = state.mail;
  if (!m) { box.innerHTML = '<div class="reader-empty">选择左侧邮件查看</div>'; return; }
  box.innerHTML = `
    <div class="reader-head">
      <h3>${m.subject ? esc(m.subject) : '(无主题)'}</h3>
      <div class="meta-row">
        <div class="avatar">${esc((m.sender || '?')[0].toUpperCase())}</div>
        <div><div><b>${esc(m.sender)}</b> → ${esc(m.to)}</div>
        <div>${esc(m.created_at.replace('T', ' ').slice(0, 19))} · ${fmtSize(m.size)}
          ${m.spam_score >= 4 ? ' · <span style="color:var(--danger)">可疑邮件</span>' : ''}</div></div>
        <div class="reader-actions">
          <md-icon-button id="dlRaw" title="下载 EML"><svg class="ic"><use href="#i-att"/></svg></md-icon-button>
          <md-icon-button id="delMail" title="删除" style="color:var(--danger)"><svg class="ic"><use href="#i-del"/></svg></md-icon-button>
        </div>
      </div>
    </div>
    <div class="reader-body" id="readerBody"></div>`;
  const body = $('#readerBody');
  if (m.code) {
    body.innerHTML = `<div class="code-callout"><span>验证码</span><b>${esc(m.code)}</b><span>点击复制</span></div>`;
    body.querySelector('.code-callout').onclick = () => { navigator.clipboard?.writeText(m.code); toast('验证码已复制'); };
  }
  if (m.html_body) {
    const f = document.createElement('iframe');
    f.className = 'mail-frame'; f.sandbox = 'allow-same-origin';
    f.style.height = `calc(100% - ${m.code ? 74 : 0}px)`;
    body.appendChild(f);
    f.srcdoc = `<!DOCTYPE html><html><head><meta charset="utf-8"><base target="_blank">
      <style>body{font-family:system-ui,sans-serif;padding:20px;color:#222;background:#fff}</style></head>
      <body>${m.html_body}</body></html>`;
  } else {
    const d = document.createElement('div');
    d.className = 'plain'; d.textContent = m.text_body || '(空邮件)';
    body.appendChild(d);
  }
  $('#dlRaw').onclick = () => {
    const a = document.createElement('a');
    a.href = `/api/v1/mails/${m.id}/raw`;
    a.setAttribute('download', `${m.subject || 'mail'}-${m.id}.eml`);
    a.click();
  };
  $('#delMail').onclick = async () => {
    await api.req(`/mails/${m.id}`, { method: 'DELETE' });
    toast('已移入垃圾箱'); state.mail = null;
    await refreshFolders(); await loadMails(true); renderReader();
  };
}
let qTimer;
$('#q').addEventListener('input', (e) => {
  clearTimeout(qTimer);
  qTimer = setTimeout(() => { state.q = e.target.value.trim(); loadMails(); }, 350);
});
$$('#segFilter [data-f]').forEach((b) => b.onclick = () => {
  state.filter = b.dataset.f;
  $$('#segFilter [data-f]').forEach((x) => x.classList.toggle('on', x === b));
  loadMails(true);
});

/* ---------- 写信 ---------- */
$('#fabCompose').onclick = () => {
  if (!state.mb) return;
  $('#cpFrom').value = state.mb.address;
  $('#cpTo').value = ''; $('#cpSubject').value = ''; $('#cpText').value = ''; $('#cpErr').textContent = '';
  $('#dlgCompose').open = true;
  requestAnimationFrame(() => $('#dlgCompose').shadowRoot?.querySelector('dialog')?.style.setProperty('margin', 'auto'));
};
$('#cpCancel').onclick = () => ($('#dlgCompose').open = false);
$('#cpSend').onclick = async () => {
  try {
    await api.req(`/mailboxes/${state.mb.id}/compose`, {
      method: 'POST',
      body: JSON.stringify({ to: $('#cpTo').value.trim(), subject: $('#cpSubject').value, text: $('#cpText').value }),
    });
    $('#dlgCompose').open = false;
    toast('已发送（进入投递队列）');
    refreshFolders();
  } catch (e) { $('#cpErr').textContent = e.error || '发送失败'; }
};

/* ---------- 邮箱管理 ---------- */
async function loadMailboxes() {
  await refreshFolders();
  $('#mbCards').innerHTML = state.mailboxes.map((mb) => `
    <div class="mb-card"><h4><svg class="ic" style="color:var(--primary)"><use href="#i-mail"/></svg>
      <code>${esc(mb.address)}</code>${mb.is_active ? '' : '<span class="chip warn">已停用</span>'}</h4>
      <div class="badge-line">${state.folders.map((f) =>
        `<span class="chip">${esc(f.name)} ${f.total} 封 / 未读 ${f.unread}</span>`).join('')}</div>
    </div>`).join('');
}

/* ---------- 规则（转发/验证码） ---------- */
function ruleMbx(id) {
  const sel = $(id);
  sel.innerHTML = state.mailboxes.map((mb) =>
    `<md-select-option value="${mb.id}">${esc(mb.address)}</md-select-option>`).join('');
  sel.value = String(state.mailboxes[0]?.id || '');
}
async function loadRules(kind) {
  const sel = $(kind === 'forward' ? '#fwMbx' : '#vfMbx');
  ruleMbx(kind === 'forward' ? '#fwMbx' : '#vfMbx');
  const mbId = sel.value;
  if (!mbId) return;
  const r = await api.req(`/mailboxes/${mbId}/rules?kind=${kind}`);
  if (kind === 'forward') {
    $('#fwList').innerHTML = r.items.length ? r.items.map((x) => `
      <md-list-item><span slot="headline">${esc(x.target)}</span>
        <span slot="supporting-text">全部邮件转发至该地址</span>
        <md-icon-button slot="end" data-del="${x.id}" title="删除" style="color:var(--danger)">
          <svg class="ic"><use href="#i-del"/></svg></md-icon-button></md-list-item>`).join('')
      : '<p class="hint" style="padding:8px">暂无转发规则</p>';
    $('#fwList').querySelectorAll('[data-del]').forEach((b) => b.onclick = () => delRule(kind, mbId, b.dataset.del));
  } else {
    $('#vfList').innerHTML = r.items.length ? r.items.map((x) => `
      <md-list-item><span slot="headline">${esc(x.name)}</span>
        <code slot="supporting-text">${esc(x.pattern)}</code>
        <md-icon-button slot="end" data-del="${x.id}" title="删除" style="color:var(--danger)">
          <svg class="ic"><use href="#i-del"/></svg></md-icon-button></md-list-item>`).join('')
      : '<p class="hint" style="padding:8px">暂无验证码规则（命中时自动提取验证码）</p>';
    $('#vfList').querySelectorAll('[data-del]').forEach((b) => b.onclick = () => delRule(kind, mbId, b.dataset.del));
  }
}
async function delRule(kind, mbId, id) {
  await api.req(`/mailboxes/${mbId}/rules?kind=${kind}&id=${id}`, { method: 'DELETE' });
  toast('已删除'); loadRules(kind);
}
$('#fwAdd').onclick = async () => {
  const mbId = $('#fwMbx').value; if (!mbId) return;
  try {
    await api.req(`/mailboxes/${mbId}/rules?kind=forward`, { method: 'POST', body: JSON.stringify({ target: $('#fwTarget').value.trim() }) });
    $('#fwTarget').value = ''; toast('转发规则已添加'); loadRules('forward');
  } catch (e) { toast(e.error || '添加失败'); }
};
$('#vfAdd').onclick = async () => {
  const mbId = $('#vfMbx').value; if (!mbId) return;
  try {
    await api.req(`/mailboxes/${mbId}/rules?kind=verif`, {
      method: 'POST', body: JSON.stringify({ name: $('#vfName').value.trim(), pattern: $('#vfPattern').value.trim() }) });
    $('#vfName').value = ''; $('#vfPattern').value = ''; toast('验证码规则已添加'); loadRules('verif');
  } catch (e) { toast(e.error || '添加失败（检查正则语法）'); }
};

/* ---------- 账号设置 ---------- */
async function loadSettings() {
  await loadAppPasswords();
}
async function loadAppPasswords() {
  if (!state.mb) return;
  const r = await api.req(`/mailboxes/${state.mb.id}/app_passwords`);
  $('#apList').innerHTML = r.items.length ? r.items.map((x) => `
    <md-list-item><span slot="headline">${esc(x.label)}</span>
      <span slot="supporting-text">创建于 ${esc(x.created_at.slice(0, 10))}${x.last_used ? ' · 最近使用 ' + esc(x.last_used.slice(0, 16)) : ' · 从未使用'}</span>
      <md-icon-button slot="end" data-del="${x.id}" title="撤销" style="color:var(--danger)">
        <svg class="ic"><use href="#i-del"/></svg></md-icon-button></md-list-item>`).join('')
    : '<p class="hint" style="padding:8px">暂无 App 专用密码</p>';
  $('#apList').querySelectorAll('[data-del]').forEach((b) => b.onclick = async () => {
    await api.req(`/mailboxes/${state.mb.id}/app_passwords?pid=${b.dataset.del}`, { method: 'DELETE' });
    toast('已撤销'); loadAppPasswords();
  });
}
$('#pwSave').onclick = async () => {
  try {
    await api.req('/me/password', { method: 'POST', body: JSON.stringify({ old: $('#pwOld').value, new: $('#pwNew').value }) });
    $('#pwOld').value = ''; $('#pwNew').value = '';
    toast('密码已修改，SMTP / IMAP / POP3 已同步');
  } catch (e) { toast(e.error || '修改失败'); }
};
$('#apAdd').onclick = async () => {
  if (!state.mb) return;
  try {
    const r = await api.req(`/mailboxes/${state.mb.id}/app_passwords`, {
      method: 'POST', body: JSON.stringify({ label: $('#apLabel').value.trim() || '未命名' }) });
    $('#apLabel').value = '';
    $('#apwValue').textContent = r.password;
    $('#dlgAp').open = true;
    loadAppPasswords();
  } catch (e) { toast(e.error || '生成失败'); }
};
$('#apwOk').onclick = () => ($('#dlgAp').open = false);

/* ---------- 管理面板 ---------- */
$$('#admTabs [data-t]').forEach((b) => b.onclick = () => {
  state.admTab = b.dataset.t;
  $$('#admTabs [data-t]').forEach((x) => x.classList.toggle('on', x === b));
  ['ov', 'users', 'domains', 'queue', 'conf'].forEach((t) => $(`#adm${t[0].toUpperCase()}${t.slice(1)}`).hidden = t !== state.admTab);
  loadAdmTab();
});
async function loadAdmin() { loadAdmTab(); }
async function loadAdmTab() {
  const t = state.admTab;
  if (t === 'ov') {
    const st = await api.req('/admin/stats');
    $('#admOv').innerHTML = `
      <div class="stat-grid">
        <div class="stat-card"><span>用户</span><b>${st.users}</b><i>管理员可在用户页管理</i></div>
        <div class="stat-card"><span>邮箱</span><b>${st.mailboxes}</b><i>全部用户合计</i></div>
        <div class="stat-card"><span>邮件</span><b>${st.mails}</b><i>含垃圾箱</i></div>
        <div class="stat-card"><span>数据库</span><b>${fmtSize(st.db_bytes)}</b><i>单文件 SQLite</i></div>
      </div>
      <div class="panel slim" style="margin-top:14px"><h4>投递队列</h4>
        <table class="tbl"><tr><td>待发送</td><td>${st.queue.queued}</td></tr>
        <tr><td>已发送</td><td>${st.queue.sent}</td></tr>
        <tr><td>失败</td><td>${st.queue.failed}</td></tr></table></div>`;
  } else if (t === 'users') {
    const users = (await api.req('/admin/users')).items;
    $('#admUsers').innerHTML = `
      <div class="panel slim"><h4>新增用户</h4>
        <div class="rule-add">
          <md-outlined-text-field id="nuName" label="用户名（小写字母/数字/-/_）" style="max-width:240px"></md-outlined-text-field>
          <md-outlined-text-field id="nuPass" label="密码（至少 6 位）" type="password" style="max-width:200px"></md-outlined-text-field>
          <md-filled-button id="nuGo"><svg class="ic" slot="icon"><use href="#i-add"/></svg>创建</md-filled-button>
        </div>
        <p class="hint">创建后自动开通 用户名@默认域名 邮箱，协议密码与 Web 密码一致</p></div>
      <div class="panel slim"><table class="tbl">${users.map((u) => `<tr>
        <td>#${u.id} ${esc(u.username)}${u.role === 'admin' ? ' · 管理员' : ''}</td>
        <td>${esc(u.created_at.slice(0, 10))}<br>${u.mailboxes} 邮箱</td>
        <td><span style="color:${u.status === 'active' ? 'var(--ok)' : 'var(--danger)'}">${u.status === 'active' ? '启用' : '禁用'}</span></td>
        <td style="text-align:right">
          <md-text-button data-op="${u.status === 'active' ? 'disable' : 'enable'}" data-id="${u.id}">${u.status === 'active' ? '禁用' : '启用'}</md-text-button>
          <md-text-button data-op="reset" data-id="${u.id}">重置密码</md-text-button></td></tr>`).join('')}</table></div>`;
    $('#nuGo').onclick = async () => {
      try {
        const ru = await api.req('/admin/users', { method: 'POST', body: JSON.stringify({ username: $('#nuName').value.trim(), password: $('#nuPass').value }) });
        $('#nuName').value = ''; $('#nuPass').value = '';
        toast('用户已创建：' + (ru.address || '')); loadAdmTab();
      } catch (e) { toast(e.error || '创建失败'); }
    };
    $('#admUsers').querySelectorAll('[data-op]').forEach((b) => b.onclick = async () => {
      let pw = '';
      if (b.dataset.op === 'reset') { pw = prompt('输入新密码（至少 6 位）'); if (!pw) return; }
      await api.req(`/admin/users/${b.dataset.id}`, { method: 'PATCH', body: JSON.stringify({ op: b.dataset.op, password: pw }) });
      toast('已执行'); loadAdmTab();
    });
  } else if (t === 'domains') {
    const domains = (await api.req('/admin/domains')).items;
    $('#admDomains').innerHTML = `
      <div class="panel slim"><h4>新增域名</h4>
        <div class="rule-add">
          <md-outlined-text-field id="ndName" label="example.com" style="max-width:240px"></md-outlined-text-field>
          <md-filled-button id="ndGo"><svg class="ic" slot="icon"><use href="#i-add"/></svg>添加</md-filled-button>
        </div></div>
      <div class="panel slim">${domains.map((d) => `
        <h4><code style="color:var(--primary)">${esc(d.domain)}</code> · ${d.status}</h4>
        ${d.dkim_dns ? `<table class="tbl">
          <tr><td>DNS TXT 主机</td><td><code>${esc(d.dkim_dns.host)}</code></td></tr>
          <tr><td>DNS TXT 记录</td><td><code>${esc(d.dkim_dns.record)}</code></td></tr></table>`
          : '<p class="hint">DKIM 密钥生成中…</p>'}`).join('')}</div>
      <p class="hint">还需发布：MX → 本服务器 · SPF <code>v=spf1 mx ~all</code> · DMARC <code>v=DMARC1; p=quarantine</code></p>`;
    $('#ndGo').onclick = async () => {
      try {
        await api.req('/admin/domains', { method: 'POST', body: JSON.stringify({ domain: $('#ndName').value.trim() }) });
        $('#ndName').value = ''; toast('域名已添加'); loadAdmTab();
      } catch (e) { toast(e.error || '添加失败'); }
    };
  } else if (t === 'queue') {
    const q = (await api.req('/queue')).items;
    $('#admQueue').innerHTML = `<div class="panel slim"><table class="tbl">${q.length ? q.map((r) => `
      <tr><td>#${r.id} ${r.status === 'failed' ? `<span style="color:var(--danger)">${esc(r.last_error || '')}</span>` : r.status}</td>
      <td>${esc(r.from)} → ${esc(r.to)}</td><td>尝试 ${r.attempts} 次</td><td>${esc(r.created_at.slice(5, 16))}</td></tr>`).join('')
      : '<tr><td>队列为空</td></tr>'}</table></div>`;
  } else if (t === 'conf') {
    const st2 = await api.req('/admin/settings');
    $('#regToggle').selected = st2.registration_enabled;
    const ports = (await api.req('/admin/ports')).items;
    const names = { smtp_listen: 'SMTP 收信', smtp_submission: 'SMTP 提交(587)', smtp_tls: 'SMTPS(465)',
      imap_listen: 'IMAP', imap_tls: 'IMAPS(993)', pop3_listen: 'POP3', pop3_tls: 'POP3S(995)' };
    $('#portGrid').innerHTML = Object.keys(names).map((k) => `
      <md-outlined-text-field data-port="${k}" label="${names[k]}" value="${esc(ports[k] || '')}"
        placeholder=":25 / 留空关闭" style="width:100%"></md-outlined-text-field>`).join('');
  }
}
$('#regToggle').addEventListener('change', async (e) => {
  try {
    await api.req('/admin/settings', { method: 'PUT', body: JSON.stringify({ registration_enabled: e.target.selected }) });
    toast(e.target.selected ? '注册已开放' : '注册已关闭');
  } catch { e.target.selected = !e.target.selected; }
});
$('#portSave').onclick = async () => {
  const body = {};
  $$('#portGrid [data-port]').forEach((i) => body[i.dataset.port] = i.value.trim());
  try {
    const r = await api.req('/admin/ports', { method: 'PUT', body: JSON.stringify(body) });
    toast('端口已保存：' + (r.note || '重启后生效'));
  } catch (e) { toast(e.error || '保存失败'); }
};

/* ---------- md-dialog 居中修复（display:contents 使 margin:auto 失效） ---------- */
const _origOpen = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'open');
// 监听所有 md-dialog 的 open 变化太重；直接在 show 时打补丁
function patchDialogs() {
  document.querySelectorAll('md-dialog').forEach((d) => {
    const inner = d.shadowRoot?.querySelector('dialog');
    if (inner) inner.style.margin = 'auto';
  });
}
const mo = new MutationObserver(patchDialogs);
mo.observe(document.body, { childList: true, subtree: false, attributes: true, attributeFilter: ['open'] });

/* ---------- 入口 ---------- */
if (api.token) boot(); else showLogin();
