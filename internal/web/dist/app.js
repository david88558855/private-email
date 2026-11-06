/* Private Email · V5 工程版（按设计稿实施） */
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

const FOLDER_CN = { INBOX: '收件箱', Sent: '已发送', Drafts: '草稿箱', Trash: '垃圾箱' };
const folderCN = (n) => FOLDER_CN[n] || n;
// 邮件视图的页头标题：全部邮件 / 收件箱 / 已发送 …
const inboxTitle = () => (state.folder ? folderCN(state.folderName) : '全部邮件');
const state = { view: 'dashboard', folder: null, folderName: 'INBOX', mail: null, mails: [], filter: 'all',
  mailboxes: [], folders: [], mb: null, me: null, q: '', admTab: 'ov', adminConsole: false, loginMode: 'user',
  adminDomains: [], apMb: null, listLoading: false };

const VIEWS = {
  dashboard: { title: '仪表板', icon: 'i-dash', group: '工作台' },
  inbox: { title: '收件箱', icon: 'i-inbox', group: '工作台' },
  mailboxes: { title: '邮箱管理', icon: 'i-mail', group: '管理' },
  forward: { title: '转发规则', icon: 'i-fwd', group: '管理' },
  verif: { title: '验证码规则', icon: 'i-key', group: '管理' },
  settings: { title: '账号设置', icon: 'i-tune', group: '管理' },
  admin: { title: '后台管理', icon: 'i-shield', group: '管理', adminOnly: true },
};
const ADMIN_VIEWS = {
  ov: { title: '概览', icon: 'i-dash' }, users: { title: '用户', icon: 'i-users' },
  domains: { title: '域名', icon: 'i-globe' }, queue: { title: '投递队列', icon: 'i-mon' },
  conf: { title: '系统设置', icon: 'i-tune' },
};

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtSize = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + 'MB' : n > 1024 ? (n / 1024).toFixed(0) + 'KB' : n + 'B';
const fmtTime = (s) => { const d = new Date(s.includes('T') ? s : s.replace(' ', 'T') + 'Z');
  const now = new Date(); return d.toDateString() === now.toDateString() ?
    d.toTimeString().slice(0, 5) : `${d.getMonth() + 1}/${d.getDate()}`; };

let tT; function toast(s) { const t = $('#toast'); t.textContent = s; t.classList.add('on'); clearTimeout(tT); tT = setTimeout(() => t.classList.remove('on'), 2400); }
function openDlg(id) { $('#' + id).classList.add('on'); }
function closeDlg(id) { $('#' + id).classList.remove('on'); }
function toggleTheme() { const d = document.documentElement.dataset.theme === 'dark'; document.documentElement.dataset.theme = d ? '' : 'dark'; localStorage.setItem('pe_theme', d ? '' : 'dark'); }
// 首帧的主题由 index.html <head> 里的内联脚本设置，这里不再重复（避免二次切换）。

/* ---------- 导航 ---------- */
function renderNav() {
  const nav = $('#sideNav');
  let html = '';
  if (state.adminConsole) {
    for (const [k, v] of Object.entries(ADMIN_VIEWS)) {
      html += `<button class="nav-item ${state.view === 'admin' && state.admTab === k ? 'on' : ''}" onclick="admTab('${k}')">
        <svg><use href="#${v.icon}"/></svg>${v.title}</button>`;
    }
    html += `<div class="nav-label">切换</div>
      <button class="nav-item" onclick="backUser()"><svg><use href="#i-person"/></svg>用户视图</button>`;
    nav.innerHTML = html; return;
  }
  let group = '';
  for (const [id, v] of Object.entries(VIEWS)) {
    if (v.adminOnly && state.me?.role !== 'admin') continue;
    // 收件箱不再单列入口，邮件视图改由下面的文件夹导航进入
    if (id === 'inbox') { html += `<div class="side-folders" id="folderStrip"></div>`; continue; }
    if (v.group !== group) { group = v.group; html += `<div class="nav-label">${group}</div>`; }
    html += `<button class="nav-item ${state.view === id ? 'on' : ''}" onclick="showView('${id}')">
      <svg><use href="#${v.icon}"/></svg>${v.title}</button>`;
  }
  nav.innerHTML = html;
  renderFolderStrip();
}

// 首屏（刷新恢复当前页）不播视图进入动画：动画从 opacity:0 起步，
// 在界面已经出现之后再看内容淡入，很容易被读成「闪了一下再落到本页」。
// 之后用户主动切页仍保留 vin 动画。
let firstPaint = true;
// applyView 只做「切视图」的 DOM 工作（同步、无网络请求），
// 抽出来是为了让首屏能在任何 await 之前就把正确的视图摆好。
function applyView(v) {
  state.view = v;
  if (v === 'admin') {
    state.adminConsole = true;
    state.admTab = localStorage.getItem('pe_adm_tab') || 'ov'; // 刷新后回到上次的子页面
    applyAdmTab();
  }
  $$('.view').forEach((e) => e.classList.remove('on'));
  if (!firstPaint) $$('.view').forEach((e) => e.classList.remove('no-in'));
  const sec = $('#v-' + v);
  if (!sec) return;
  // no-in 必须在 .on 之前挂上，同一帧内不会有中间的重绘
  if (firstPaint) { sec.classList.add('no-in'); firstPaint = false; }
  sec.classList.add('on');
  $('#viewTitle').textContent = v === 'admin' ? '管理后台' : (v === 'inbox' ? inboxTitle() : VIEWS[v].title);
  document.body.classList.toggle('has-fab', v === 'inbox');
}
async function loadView(v) {
  const loaders = { dashboard: loadDashboard, inbox: loadInbox, mailboxes: loadMailboxes,
    forward: () => loadRules('forward'), verif: () => loadRules('verif'),
    settings: loadSettings, admin: loadAdmin };
  try { await (loaders[v] || (() => {}))(); } catch (e) { if (e.message !== 'unauthorized') toast(e.error || '加载失败'); }
}
async function showView(v) {
  localStorage.setItem('pe_view', v); // 刷新后回到同一页
  applyView(v);
  renderNav();
  await loadView(v);
}
const ADM_TABS = ['ov', 'users', 'domains', 'queue', 'conf'];
function applyAdmTab() { ADM_TABS.forEach((t) => { const el = $('#a-' + t); if (el) el.style.display = t === state.admTab ? '' : 'none'; }); }
function admTab(k) { state.admTab = k; localStorage.setItem('pe_adm_tab', k); applyAdmTab(); renderNav(); loadAdmin(); }
function backUser() { state.adminConsole = false; showView('dashboard'); }

/* ---------- 登录 ---------- */
function setMode(mode) {
  state.loginMode = mode;
  const reg = mode === 'register';
  $('#lgPass2Wrap').style.display = reg ? '' : 'none';
  $('#lgTitle').textContent = reg ? '创建账号' : '欢迎回来';
  $('#lgSub').textContent = reg ? '注册后即可使用完整功能' : '登录你的邮箱工作台';
  $('#lgBtn').textContent = reg ? '注 册' : '登 录';
  $('#lgBack').style.display = reg ? '' : 'none';
  $('#lgReg').style.display = (!reg && state.regOpen) ? 'inline' : 'none';
  $('#lgErr').textContent = '';
}
async function doLogin() {
  const u = $('#lgUser').value.trim(), p = $('#lgPass').value;
  $('#lgErr').textContent = '';
  if (!u || !p) { $('#lgErr').textContent = '请输入用户名和密码'; return; }
  try {
    if (state.loginMode === 'register') {
      if (p !== $('#lgPass2').value) { $('#lgErr').textContent = '两次输入的密码不一致'; return; }
      const r = await api.req('/auth/register', { method: 'POST', body: JSON.stringify({ username: u, password: p }) });
      api.token = r.token; localStorage.setItem('pe_token', r.token);
      toast('注册成功，已自动登录'); state.loginMode = 'user'; boot(); return;
    }
    const r = await api.req('/auth/login', { method: 'POST', body: JSON.stringify({ username: u, password: p }) });
    api.token = r.token; localStorage.setItem('pe_token', r.token);
    boot();
  } catch (e) { $('#lgErr').textContent = e.error || (state.loginMode === 'register' ? '注册失败' : '登录失败'); }
}
$('#lgPass').addEventListener('keydown', (e) => e.key === 'Enter' && doLogin());
$('#lgPass2').addEventListener('keydown', (e) => e.key === 'Enter' && doLogin());
function logout() { localStorage.removeItem('pe_token'); location.reload(); }

async function initLogin() {
  try { const s = await fetch('/api/v1/settings').then((r) => r.json());
    state.regOpen = s.registration_enabled;
    if (s.registration_enabled) $('#lgReg').style.display = 'inline';
  } catch {}
}

/* ---------- 启动 ---------- */
// 刷新不闪动的三段式：
//   1) primeShell()：脚本一开始（任何 await 之前）就按上次的视图把外壳摆好 —— 首帧即正确；
//   2) boot() 只负责补数据，不再「先显示默认页再切回来」；
//   3) 外壳从头到尾都在，没有「空白 → 满屏」的弹跳。
// 之前的两版分别踩了：预置 .on 导致先闪仪表板、以及等三个请求回来才显示外壳导致整页空白后突然出现。
function primeShell() {
  const saved = localStorage.getItem('pe_view') || '';
  const v = VIEWS[saved] ? saved : 'dashboard';
  const savedFolder = localStorage.getItem('pe_folder') || '';
  if (v === 'inbox' && savedFolder) state.folderName = savedFolder;
  applyView(v);
  // 收件箱的标题依赖「当前文件夹 id」，而 id 要等 /folders 回来才知道。
  // 这里先用上次的文件夹名把标题定死（'' = 全部邮件），
  // 否则首帧会先写「全部邮件」、数据回来再改成「收件箱」，页头明显跳一下。
  if (v === 'inbox') {
    $('#viewTitle').textContent = savedFolder ? folderCN(savedFolder) : '全部邮件';
  }
  $('#login').style.display = 'none';
  $('#app').classList.add('on');
}
async function boot() {
  try { state.me = await api.req('/me'); } catch { return showLogin(); }
  const initial = (state.me.username || '?')[0].toUpperCase();
  $('#sideName').textContent = state.me.username;
  $('#sideAvatar').textContent = initial;
  state.mailboxes = (await api.req('/mailboxes')).items;
  const savedMb = localStorage.getItem('pe_mb');
  state.mb = state.mailboxes.find((m) => String(m.id) === savedMb) || state.mailboxes[0] || null;
  if (state.mb) localStorage.setItem('pe_mb', state.mb.id);
  if (state.mb) await refreshFolders();
  $('#sideRole').textContent = state.me.role === 'admin' ? '管理员' : '用户工作台';
  $('#sideMail').textContent = state.mb?.address || '';
  // 刷新/重开页面回到上次所在页面与文件夹，不强制跳回仪表板
  const lastView = localStorage.getItem('pe_view') || '';
  const lastFolder = localStorage.getItem('pe_folder') || '';
  if (lastFolder && state.mb) {
    const lf = state.folders.find((x) => x.name === lastFolder);
    // folderName 必须一起恢复：它决定页头标题，只恢复 id 会出现「标题写收件箱、高亮在垃圾箱」
    if (lf) { state.folder = lf.id; state.folderName = lf.name; }
  }
  const want = VIEWS[lastView] && !(VIEWS[lastView].adminOnly && state.me.role !== 'admin')
    ? lastView : 'dashboard';
  renderNav();
  if (want === state.view) {
    // 视图已由 primeShell 摆好，这里只补数据：不重切类名，避免任何一次重排/动画
    if (want === 'inbox') $('#viewTitle').textContent = inboxTitle();
    await loadView(want);
  } else {
    // 角色不符（例如上次停在后台但账号已降级为普通用户）才需要真正切一次
    await showView(want);
  }
  setInterval(async () => {
    if (state.view === 'inbox' && !state.q && state.folder) { await refreshFolders(); await loadMails(true); }
  }, 8000);
  // 回到页面立即刷新收件箱
  window.addEventListener('focus', () => {
    if (state.view === 'inbox' && state.folder) { refreshFolders(); loadMails(true); }
  });
}
async function refreshFolders() { if (state.mb) state.folders = (await api.req(`/mailboxes/${state.mb.id}/folders`)).items; renderNav(); }
function showLogin() {
  $('#app').classList.remove('on');
  // 清掉 head 里设的首屏登录态标记，否则 CSS 会把外壳继续显示出来
  document.documentElement.removeAttribute('data-auth');
  $('#login').style.display = 'flex';
  initLogin();
}

/* ---------- 仪表板 ---------- */
async function loadDashboard() {
  const d = await api.req('/dashboard');
  $('#stMb').textContent = d.mailboxes;
  $('#stToday').textContent = d.today;
  $('#stUnread').textContent = d.unread;
  $('#stUnreadSub').textContent = d.unread ? '含验证码邮件' : '已全部处理';
  $('#stStore').textContent = fmtSize(d.storage_bytes);
  const h = new Date().getHours();
  $('#greet').textContent = (h < 6 ? '夜深了' : h < 12 ? '上午好' : h < 18 ? '下午好' : '晚上好') + '，' + state.me.username;
  $('#greetSub').textContent = `今天有 ${d.today} 封新邮件，${d.unread} 封未读`;
  const max = Math.max(...d.trend.map((t) => t.count), 1);
  $('#trendChart').innerHTML = d.trend.map((t) => `
    <div class="tcol"><div class="tbar ${t.count ? '' : 'flat'}" title="${t.count} 封" style="height:${Math.max(t.count / max * 100, 3)}%"></div>
      <span class="tday">${t.day.slice(5)}</span></div>`).join('');
  $('#recentList').innerHTML = d.recent.length ? d.recent.map((m) => `
    <div class="dm-item" onclick="showView('inbox')">
      <span class="dm-dot ${m.unread ? '' : 'read'}"></span>
      <div style="flex:1;min-width:0"><b>${esc(m.sender)}</b>
        ${m.code ? `<span class="snip">${esc(m.code)}</span>` : ''}<div class="hint" style="margin:0">${m.subject ? esc(m.subject) : '(无主题)'}</div></div>
      <span class="hint">${fmtTime(m.created_at)}</span>
    </div>`).join('') : '<p class="hint">暂无邮件</p>';
}

/* ---------- 收件箱 ---------- */
async function loadInbox() {
  // 邮箱切换下拉（切换后文件夹与列表全部跟随）
  const sel = $('#mbSwitch');
  if (sel) {
    if (!state.mailboxes.length) {
      sel.innerHTML = '<option value="">无邮箱 · 请先创建</option>';
      sel.disabled = true;
    } else {
      sel.disabled = false;
      // 地址或数量变化时重建选项，避免旧列表残留
      const sig = state.mailboxes.map((m) => m.id + ':' + m.address).join('|');
      if (sel.dataset.sig !== sig) {
        sel.dataset.sig = sig;
        sel.innerHTML = state.mailboxes.map((m) => `<option value="${m.id}">${esc(m.address)}</option>`).join('');
      }
      if (state.mb) sel.value = String(state.mb.id);
    }
    sel.onchange = async () => {
      state.mb = state.mailboxes.find((m) => m.id === +sel.value);
      if (!state.mb) return;
      localStorage.setItem('pe_mb', state.mb.id);
      state.folder = null; state.folderName = 'INBOX'; state.mail = null;
      $('#sideMail').textContent = state.mb.address;
      await refreshFolders();
      const inbox = state.folders.find((f) => f.name === 'INBOX');
      state.folder = inbox?.id || state.folders[0]?.id || null;
      await loadMails(); renderFolderStrip();
      $('#viewTitle').textContent = inboxTitle();
      toast('已切换：' + state.mb.address);
    };
  }
  await refreshFolders();
  // folder=null → 「全部邮件」聚合视图（默认）
  renderFolderStrip();
  await loadMails(true);
}
const FOLDER_ORDER = ['INBOX', 'Sent', 'Drafts', 'Trash'];
// 文件夹图标：与侧栏导航同一套 symbol，尺寸由 .side-folders svg 统一控制
const FOLDER_ICON = { INBOX: 'i-inbox', Sent: 'i-send', Drafts: 'i-draft', Trash: 'i-trash' };
const folderIcon = (n) => FOLDER_ICON[n] || 'i-mail';

// 文件夹导航：始终渲染 5 项，保持正常配色（不因无邮箱或未加载而置灰）
function renderFolderStrip() {
  const box = $('#folderStrip');
  if (!box) return; // 管理后台导航视图下没有该容器
  const total = state.folders.reduce((a, f) => a + (f.total || 0), 0);
  const inMail = state.view === 'inbox';
  let html = `<button class="all ${inMail && !state.folder ? 'on' : ''}" data-fid="all" data-name="">
    <svg><use href="#i-mail"/></svg>全部邮件 <span class="fbadge">${total}</span></button>`;
  for (const name of FOLDER_ORDER) {
    const f = state.folders.find((x) => x.name === name);
    const cnt = f ? (f.unread ? `<span class="fbadge">${f.unread}</span>` : `<span class="fcount">${f.total || ''}</span>`) : '';
    html += `<button class="${inMail && f && f.id === state.folder ? 'on' : ''}"
      data-fid="${f ? f.id : ''}" data-name="${name}"><svg><use href="#${folderIcon(name)}"/></svg>${folderCN(name)}${cnt}</button>`;
  }
  box.innerHTML = html;
  $$('#folderStrip [data-fid]').forEach((b) => b.onclick = () => pickFolder(b.dataset.fid, b.dataset.name));
}

// 文件夹点击：无邮箱时引导创建；数据没拉到就地补拉；id 过期按名字兜底
async function pickFolder(fid, name) {
  if (!state.mb) { toast('还没有邮箱，先去「邮箱管理」创建一个'); showView('mailboxes'); return; }
  if (!state.folders.length) await refreshFolders();
  let f = fid && fid !== 'all' ? state.folders.find((x) => x.id === +fid) : null;
  if (!f && name) f = state.folders.find((x) => x.name === name);
  if (!f && name) { toast('文件夹未就绪，请稍后重试'); return; }
  state.folder = f ? f.id : null;
  state.folderName = f ? f.name : 'INBOX';
  localStorage.setItem('pe_folder', f ? f.name : '');
  if (state.view === 'inbox') { $('#viewTitle').textContent = inboxTitle(); renderFolderStrip(); await loadMails(); }
  else await showView('inbox');
}
function setFilter(btn, f) { state.filter = f; $$('#segFilter button').forEach((b) => b.classList.toggle('on', b === btn)); renderList(); }
let qT; $('#q').addEventListener('input', (e) => { clearTimeout(qT); qT = setTimeout(() => { state.q = e.target.value.trim(); loadMails(); }, 350); });

async function loadMails(silent) {
  state.listLoading = true;
  try {
    await fetchMails();
  } finally {
    state.listLoading = false;
    renderList();
    if (!silent) renderReader();
  }
}
async function fetchMails() {
  if (!state.folder) {
    // 全部邮件：合并该邮箱所有文件夹
    const rs = await Promise.all(state.folders.map((f) =>
      api.req(`/folders/${f.id}/mails?limit=50`).catch(() => ({ items: [], total: 0 }))));
    let items = rs.flatMap((r) => r.items);
    items.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
    if (state.filter === 'unread') items = items.filter((m) => !m.flags.includes('\\Seen'));
    state.mails = items.slice(0, 50);
    $('#listMeta').textContent = `共 ${items.length} 封`;
    return;
  }
  const p = state.q ? `?q=${encodeURIComponent(state.q)}&limit=50` : '?limit=50';
  const r = await api.req(`/folders/${state.folder}/mails${p}`);
  state.mails = state.filter === 'unread' ? r.items.filter((m) => !m.flags.includes('\\Seen')) : r.items;
  $('#listMeta').textContent = `共 ${r.total} 封`;
}
function renderList() {
  const box = $('#mailList');
  if (!state.mails.length) {
    // 首次加载还没回来时不要先画「暂无邮件」再被列表顶掉：
    // 空白列表区 → 列表，看起来像布局跳动；留空更稳。
    box.innerHTML = state.listLoading ? '' : '<div class="empty"><svg><use href="#i-mail"/></svg>暂无邮件</div>';
    return;
  }
  box.innerHTML = state.mails.map((m) => `
    <div class="m-item ${state.mail?.id === m.id ? 'on' : ''} ${m.flags.includes('\\Seen') ? '' : 'unread'}" onclick="openMail(${m.id})">
      <div class="r1"><span class="from">${esc(m.sender)}</span><span class="time">${fmtTime(m.created_at)}</span></div>
      <div class="r2"><span class="subj">${m.subject ? esc(m.subject) : '(无主题)'}</span>
        <span class="r2meta">${m.code ? `<span class="snip">${esc(m.code)}</span>` : ''}${m.spam_score >= 4 ? '<span class="snip" style="color:var(--error)">可疑</span>' : ''}<span class="meta-size">${fmtSize(m.size)}</span></span></div>
    </div>`).join('');
}
async function openMail(id) {
  try {
    const m = await api.req(`/mails/${id}`);
    state.mail = m;
    // 服务端读取时已置已读，本地列表同步 flags，未读点立即消失（否则要等轮询）
    const i = state.mails.findIndex((x) => x.id === id);
    if (i >= 0) state.mails[i].flags = m.flags;
    renderList(); renderReader();
  } catch (e) { toast(e.error || '邮件加载失败'); }
}
function renderReader() {
  const box = $('#reader');
  if (!state.mail) { box.innerHTML = '<div class="empty"><svg><use href="#i-mail"/></svg>选择左侧邮件查看内容</div>'; return; }
  const m = state.mail;
  box.innerHTML = `
    <div class="hd">
      <h3>${m.subject ? esc(m.subject) : '(无主题)'}</h3>
      <div class="meta">
        <div class="avatar">${esc((m.sender || '?')[0].toUpperCase())}</div>
        <div class="who" style="flex:1;min-width:0"><b>${esc(m.sender)}</b>
          <span>→ ${esc(m.to)} · ${esc((m.created_at || '').replace('T', ' ').slice(0, 19))} · ${fmtSize(m.size)}</span></div>
        <div class="acts">
          <button class="iconbtn" title="下载 EML" onclick="downloadMail(${m.id})"><svg><use href="#i-att"/></svg></button>
          <button class="iconbtn" title="删除" style="color:var(--error)" onclick="delMail(${m.id})"><svg><use href="#i-del"/></svg></button>
        </div>
      </div>
    </div>
    <div class="body" id="mailBody"></div>`;
  const body = $('#mailBody');
  if (m.code) {
    body.innerHTML = `<div class="code-callout"><span>验证码</span><b>${esc(m.code)}</b><span>点击复制</span></div>`;
    body.querySelector('.code-callout').onclick = () => { navigator.clipboard?.writeText(m.code); toast('验证码已复制'); };
  }
  if (m.html_body) {
    const f = document.createElement('iframe');
    f.className = 'mail-frame'; f.sandbox = ''; // 全禁隔离
    body.appendChild(f);
    f.srcdoc = `<!DOCTYPE html><html><head><meta charset="utf-8"><base target="_blank">
      <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
      <style>body{font-family:-apple-system,'Segoe UI','PingFang SC',sans-serif;padding:20px;color:#222;background:#fff}</style></head>
      <body>${m.html_body}</body></html>`;
  } else {
    const d = document.createElement('div');
    d.className = 'plain'; d.textContent = m.text_body || '(空邮件)';
    body.appendChild(d);
  }
}
async function downloadMail(id) {
  // 直接 location.href 不会带 Authorization，接口必然 401；改成 fetch + blob
  try {
    const r = await fetch(`/api/v1/mails/${id}/raw`, { headers: { Authorization: 'Bearer ' + api.token } });
    if (!r.ok) throw new Error('download failed');
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `mail-${id}.eml`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
  } catch (e) { toast('下载失败'); }
}
async function delMail(id) {
  await api.req(`/mails/${id}`, { method: 'DELETE' });
  // 在垃圾箱里删是真删，提示不能还说"移入垃圾箱"
  toast(state.folderName === 'Trash' ? '已永久删除' : '已移入垃圾箱'); state.mail = null;
  await refreshFolders(); renderFolderStrip(); await loadMails(true); renderReader();
}

/* ---------- 写信 ---------- */
function openCompose() { if (!state.mb) { toast('还没有邮箱，请先在「邮箱管理」创建'); return; }
  $('#cpFrom').value = state.mb.address; $('#cpTo').value = ''; $('#cpSubject').value = ''; $('#cpText').value = ''; $('#cpErr').textContent = '';
  openDlg('composeDlg'); }
async function sendCompose() {
  try {
    await api.req(`/mailboxes/${state.mb.id}/compose`, { method: 'POST',
      body: JSON.stringify({ to: $('#cpTo').value.trim(), subject: $('#cpSubject').value, text: $('#cpText').value }) });
    closeDlg('composeDlg');
    toast('已发送 · 进入投递队列');
    // 立即刷新文件夹统计与当前列表（已发送/收件箱即时可见）
    await refreshFolders();
    renderFolderStrip();
    if (state.folder) await loadMails(true);
    renderNav();
  } catch (e) { $('#cpErr').textContent = e.error || '发送失败'; }
}

/* ---------- 邮箱管理 ---------- */
async function loadMailboxes() {
  state.mailboxes = (await api.req('/mailboxes')).items;
  const dr = await api.req('/domains');
  const domains = dr.items || [];
  const pendingCount = dr.pending_count || 0;
  // 从「没有邮箱」到「刚建好第一个」时自动接管，否则收件箱仍是空的
  if (!state.mb && state.mailboxes.length) {
    state.mb = state.mailboxes[0];
    $('#sideMail').textContent = state.mb.address;
    await refreshFolders();
  }
  if (domains.length) {
    $('#mbDomain').disabled = false;
    $('#mbDomain').innerHTML = domains.map((d) => `<option value="${d.id}">${esc(d.domain)}</option>`).join('');
  } else {
    $('#mbDomain').disabled = true;
    // 域名加了但没过验证，和「一个域名都没加」是两回事，提示必须分开，
    // 否则管理员明明添加过域名，用户却被告知"先添加域名"，排查方向直接跑偏。
    $('#mbDomain').innerHTML = pendingCount
      ? `<option value="">有 ${pendingCount} 个域名待管理员验证，暂不能创建邮箱</option>`
      : '<option value="">请先在后台添加域名</option>';
  }
  $('#mbCards').innerHTML = state.mailboxes.length ? state.mailboxes.map((mb, i) => `
    <div class="panel" style="margin-bottom:14px">
      <h4><svg style="color:var(--primary)"><use href="#i-mail"/></svg><span class="mb-addr">${esc(mb.address)}</span></h4>
      <div class="mb-acts">
        <span class="hint">${mb.is_active ? '收发正常' : '已暂停收发<span class="snip" style="color:var(--error)">已停用</span>'}</span>
        <button class="btn text" onclick="toggleMb(${mb.id}, ${mb.is_active ? 'false' : 'true'})">${mb.is_active ? '停用' : '启用'}</button>
        ${state.mb?.id === mb.id
          ? '<span class="btn text default-tag" title="当前默认邮箱">默认</span>'
          : `<button class="btn text" onclick="setDefaultMb(${mb.id})">设为默认</button>`}
      </div>
    </div>`).join('') : '<div class="empty" style="grid-column:1/-1;padding:48px 0"><svg><use href="#i-mail"/></svg>暂无邮箱 · 用上方表单创建第一个</div>';
}
async function createMailbox() {
  let prefix = $('#mbPrefix').value.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{1,31}$/.test(prefix)) {
    toast('前缀仅限小写字母/数字/-/_，2-32 位（大写已自动转小写）'); return;
  }
  try {
    const r = await api.req('/mailboxes', { method: 'POST',
      body: JSON.stringify({ prefix, domain_id: +$('#mbDomain').value || 0 }) });
    $('#mbPrefix').value = '';
    toast('已创建 ' + r.address + '，密码与登录一致'); loadMailboxes();
  } catch (e) { toast(e.error || '创建失败'); }
}
async function toggleMb(id, active) {
  await api.req(`/mailboxes/${id}`, { method: 'PATCH', body: JSON.stringify({ active }) });
  toast(active ? '已启用' : '已停用'); loadMailboxes();
}
async function setDefaultMb(id) {
  state.mb = state.mailboxes.find((x) => x.id === id);
  localStorage.setItem('pe_mb', state.mb.id);
  await refreshFolders(); $('#sideMail').textContent = state.mb.address;
  toast('默认邮箱：' + state.mb.address); loadMailboxes();
}

/* ---------- 规则 ---------- */
async function loadRules(kind) {
  const mbs = state.mailboxes;
  const sel = kind === 'forward' ? $('#fwMbx') : $('#vfMbx');
  const list = kind === 'forward' ? $('#fwList') : $('#vfList');
  if (!mbs.length) { if (list) list.innerHTML = '<p class="hint">还没有邮箱，请先在「邮箱管理」创建</p>'; return; }
  if (sel) {
    const sig = mbs.map((m) => m.id + ':' + m.address).join('|');
    if (sel.dataset.sig !== sig) {
      sel.dataset.sig = sig;
      sel.innerHTML = mbs.map((m) => `<option value="${m.id}">${esc(m.address)}</option>`).join('');
    }
  }
  const mbId = +(sel?.value || mbs[0].id);
  const items = (await api.req(`/mailboxes/${mbId}/rules?kind=${kind}`)).items;
  list.innerHTML = items.length ? items.map((r) => `
    <div class="rule-item">
      <div class="ic"><svg><use href="#${kind === 'forward' ? 'i-fwd' : 'i-key'}"/></svg></div>
      <div style="flex:1;min-width:0"><b>${esc(kind === 'forward' ? r.target : r.name)}</b><span>${esc(kind === 'forward' ? '收到邮件即转发至该地址' : r.pattern)}</span></div>
      <button class="del" onclick="delRule('${kind}', ${r.id})"><svg><use href="#i-del"/></svg></button>
    </div>`).join('') : '<p class="hint">暂无规则</p>';
}
async function addRule(kind) {
  const mbId = +(kind === 'forward' ? $('#fwMbx').value : $('#vfMbx').value) || state.mailboxes[0]?.id;
  try {
    const body = kind === 'forward' ? { target: $('#fwTarget').value.trim() } : { name: $('#vfName').value.trim() || '自定义规则', pattern: $('#vfPattern').value.trim() };
    await api.req(`/mailboxes/${mbId}/rules?kind=${kind}`, { method: 'POST', body: JSON.stringify(body) });
    if (kind === 'forward') $('#fwTarget').value = ''; else { $('#vfName').value = ''; $('#vfPattern').value = ''; }
    toast('规则已添加'); loadRules(kind);
  } catch (e) { toast(e.error || '添加失败（检查格式）'); }
}
async function delRule(kind, id) {
  const mbId = +(kind === 'forward' ? $('#fwMbx').value : $('#vfMbx').value) || state.mailboxes[0]?.id;
  await api.req(`/mailboxes/${mbId}/rules?kind=${kind}&id=${id}`, { method: 'DELETE' });
  toast('已删除'); loadRules(kind);
}
$('#fwMbx')?.addEventListener('change', () => loadRules('forward'));
$('#vfMbx')?.addEventListener('change', () => loadRules('verif'));

/* ---------- 账号设置 ---------- */
// 令牌明文只放内存：列表默认打码，点「显示」才渲染出来，避免肩窥/截图泄露。
let apwCache = {};
// 当前正在查看/生成令牌的邮箱（与收件箱的默认邮箱解耦，
// 避免「在默认邮箱下生成、却拿另一个地址配客户端」的误配）
function apMbId() {
  if (state.apMb && state.mailboxes.some((m) => m.id === state.apMb)) return state.apMb;
  return state.mb ? state.mb.id : null;
}
async function loadSettings() {
  // 没有邮箱时 state.mb 是 null，取 .id 会抛异常，页面只弹「加载失败」
  if (!state.mb) {
    $('#apMbx').innerHTML = '';
    $('#apList').innerHTML = '<p class="hint">还没有邮箱，请先在「邮箱管理」创建一个</p>';
    return;
  }
  // 归属邮箱选择器：令牌与邮箱一对一，必须让用户看清当前是哪个地址
  const sel = $('#apMbx');
  const sig = state.mailboxes.map((m) => m.id + ':' + m.address).join('|');
  if (sel && sel.dataset.sig !== sig) {
    sel.dataset.sig = sig;
    sel.innerHTML = state.mailboxes.map((m) => `<option value="${m.id}">${esc(m.address)}</option>`).join('');
  }
  const mbId = apMbId();
  if (sel) {
    sel.value = String(mbId);
    sel.onchange = () => { state.apMb = +sel.value; loadSettings(); };
  }
  const cur = state.mailboxes.find((m) => m.id === mbId);
  const items = (await api.req(`/mailboxes/${mbId}/app_passwords`)).items;
  apwCache = {};
  for (const a of items) if (a.password) apwCache[a.id] = a.password;
  $('#apList').innerHTML = items.length ? items.map((a) => `
    <div class="rule-item">
      <div class="ic"><svg><use href="#i-key"/></svg></div>
      <div style="flex:1;min-width:0"><b>${esc(a.label)}</b>
        <span>${esc(a.mailbox || (cur ? cur.address : ''))} · 创建于 ${esc(a.created_at.slice(0, 10))}${a.last_used ? ' · 最近使用 ' + esc(a.last_used.slice(0, 16)) : ' · 从未使用'}</span>
        ${a.password ? `<div class="apw-line">
          <code id="apwv-${a.id}">${'•'.repeat(a.password.length)}</code>
          <button class="btn text sm" id="apwt-${a.id}" onclick="toggleApw(${a.id})">显示</button>
          <button class="btn text sm" onclick="copyApwById(${a.id})">复制</button>
        </div>` : '<div class="apw-line"><span class="hint">旧记录不可回显，撤销后重新生成即可查看</span></div>'}
      </div>
      <button class="del" onclick="delApw(${a.id})"><svg><use href="#i-del"/></svg></button>
    </div>`).join('') : '<p class="hint">这个邮箱还没有 App 专用密码</p>';
}
function toggleApw(id) {
  const el = $('#apwv-' + id), btn = $('#apwt-' + id);
  if (!el || !apwCache[id]) return;
  const shown = el.dataset.shown === '1';
  el.textContent = shown ? '•'.repeat(apwCache[id].length) : apwCache[id];
  el.dataset.shown = shown ? '0' : '1';
  if (btn) btn.textContent = shown ? '显示' : '隐藏';
}
function copyText(v, okMsg) {
  if (!v) return;
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(v).then(() => toast(okMsg)).catch(() => toast('复制失败，请手动选择'));
  } else {
    // 非安全上下文（http + 局域网 IP）下没有 clipboard API，退回选区+CtrlC
    const t = document.createElement('textarea');
    t.value = v; t.style.position = 'fixed'; t.style.opacity = '0';
    document.body.appendChild(t); t.select();
    try { document.execCommand('copy'); toast(okMsg); } catch { toast('复制失败，请手动选择'); }
    t.remove();
  }
}
function copyApwById(id) { copyText(apwCache[id], '独立密码已复制'); }
async function savePassword() {
  try {
    await api.req('/me/password', { method: 'POST', body: JSON.stringify({ old: $('#pwOld').value, new: $('#pwNew').value }) });
    $('#pwOld').value = ''; $('#pwNew').value = '';
    toast('密码已修改 · 协议密码已同步');
  } catch (e) { toast(e.error || '修改失败'); }
}
async function genApw() {
  const mbId = apMbId();
  if (!mbId) { toast('还没有邮箱，请先在「邮箱管理」创建一个'); return; }
  try {
    const r = await api.req(`/mailboxes/${mbId}/app_passwords`, { method: 'POST', body: JSON.stringify({ label: $('#apLabel').value.trim() || '客户端' }) });
    $('#apLabel').value = '';
    const mb = state.mailboxes.find((m) => m.id === mbId);
    $('#apwValue').textContent = r.password;
    $('#apwFor').textContent = mb ? mb.address : '';
    openDlg('apwDlg'); loadSettings();
  } catch (e) { toast(e.error || '生成失败'); }
}
async function delApw(id) {
  await api.req(`/mailboxes/${apMbId()}/app_passwords?pid=${id}`, { method: 'DELETE' });
  toast('已撤销'); loadSettings();
}
function copyApw() {
  copyText($('#apwValue').textContent, '已复制并关闭');
  closeDlg('apwDlg');
}
$('#apwDlg')?.addEventListener('click', (e) => { if (e.target.id === 'apwDlg') closeDlg('apwDlg'); });

/* ---------- 管理后台 ---------- */
async function loadAdmin() {
  const t = state.admTab;
  if (t === 'ov') {
    const s = await api.req('/admin/stats');
    $('#aUsers').textContent = s.users; $('#aUsersSub').textContent = `${s.users - 1} 用户`;
    $('#aMbs').textContent = s.mailboxes;
    $('#aMbsSub').textContent = `队列 待${s.queue.queued} / 成${s.queue.sent} / 败${s.queue.failed}`;
    $('#aMails').textContent = s.mails; $('#aDb').textContent = fmtSize(s.db_bytes);
    const q = (await api.req('/queue')).items;
    $('#aQueueTbl').innerHTML = `<tr><th>状态</th><th>收件人</th><th>尝试</th><th>时间</th></tr>` + (q.length ? q.slice(0, 8).map((r) => `
      <tr><td><span class="q-status ${r.status === 'sent' ? 'ok' : r.status === 'failed' ? 'warn' : 'wait'}"><span class="dot"></span>${r.status === 'sent' ? '已送达' : r.status === 'failed' ? '失败' : '重试中'}</span></td>
      <td>${esc(r.to)}</td><td>${r.attempts}</td><td>${esc(r.created_at.slice(5, 16))}</td></tr>`).join('') : '<tr><td colspan=4 class="hint">队列为空</td></tr>');
    const ports = (await api.req('/admin/ports')).items;
    const ok = '<span class="q-status ok"><span class="dot"></span>运行中</span>';
    $('#aSysTbl').innerHTML = `
      <tr><td>SMTP ${esc(ports.smtp_listen || '关')} / ${esc(ports.smtp_tls || '关')}</td><td>${ok}</td></tr>
      <tr><td>IMAP ${esc(ports.imap_listen || '关')} / ${esc(ports.imap_tls || '关')}</td><td>${ok}</td></tr>
      <tr><td>POP3 ${esc(ports.pop3_listen || '关')} / ${esc(ports.pop3_tls || '关')}</td><td>${ok}</td></tr>
      <tr><td>Web ${location.port || 80}</td><td>${ok}</td></tr>`;
  } else if (t === 'users') {
    const us = (await api.req('/admin/users')).items;
    $('#aUsersTbl').innerHTML = `<tr><th>用户</th><th>邮箱数</th><th>状态</th><th>操作</th></tr>` + us.map((u) => `
      <tr><td>#${u.id} <b>${esc(u.username)}</b>${u.role === 'admin' ? ' <span class="snip">管理员</span>' : ''}<div class="hint">${esc(u.created_at.slice(0, 10))}</div></td>
      <td>${u.mailboxes}</td>
      <td><span class="q-status ${u.status === 'active' ? 'ok' : 'warn'}"><span class="dot"></span>${u.status === 'active' ? '启用' : '禁用'}</span></td>
      <td style="white-space:nowrap">
        <button class="btn text" style="height:32px;padding:0 10px" onclick="userOp(${u.id}, '${u.status === 'active' ? 'disable' : 'enable'}')">${u.status === 'active' ? '禁用' : '启用'}</button>
        <button class="btn text" style="height:32px;padding:0 10px" onclick="resetPw(${u.id})">重置密码</button>
      </td></tr>`).join('');
  } else if (t === 'domains') {
    const ds = (await api.req('/admin/domains')).items;
    state.adminDomains = ds;
    $('#aDomainsTbl').innerHTML = `<tr><th>域名</th><th>验证状态</th><th>DKIM 记录</th><th></th></tr>` + (ds.length ? ds.map((d) => `
      <tr><td><b>${esc(d.domain)}</b><div class="hint">${esc(d.created_at.slice(0, 10))}</div></td>
      <td>${d.status === 'verified'
        ? '<span class="q-status ok"><span class="dot"></span>已验证</span>'
        : `<span class="q-status warn"><span class="dot"></span>待验证</span>
           <div class="hint" style="margin-top:4px;word-break:break-all;line-height:1.5">TXT ${esc(d.verify_host || '')}<br>= ${esc(d.verify_value || '')}</div>
           <div style="display:flex;gap:4px;margin-top:6px">
             <button class="btn text" style="height:30px;padding:0 10px;color:var(--primary)" onclick="verifyDomain(${d.id})">检测 DNS</button>
             <button class="btn text" style="height:30px;padding:0 10px" onclick="forceVerify(${d.id})">跳过验证</button>
           </div>`}</td>
      <td>${d.dkim_dns ? `<div class="hint">${esc(d.dkim_dns.host)}</div><button class="btn text" style="height:30px;padding:0 10px;color:var(--primary)" onclick="showDkim(${d.id})">查看完整记录</button>` : '<button class="btn text" style="height:30px;padding:0 10px" onclick="loadAdmin()">未生成 · 重试</button>'}</td>
      <td><button class="btn text" style="color:var(--error);height:32px;padding:0 10px" onclick="delDomain(${d.id})">删除</button></td></tr>`).join('') : '<tr><td colspan=4 class="hint">暂无域名</td></tr>');
  } else if (t === 'queue') {
    const q = (await api.req('/queue')).items;
    $('#aQueueTbl2').innerHTML = `<tr><th>状态</th><th>发件人</th><th>收件人</th><th>尝试</th><th>时间</th><th>错误</th></tr>` + (q.length ? q.map((r) => `
      <tr><td><span class="q-status ${r.status === 'sent' ? 'ok' : r.status === 'failed' ? 'warn' : 'wait'}"><span class="dot"></span>${r.status === 'sent' ? '已送达' : r.status === 'failed' ? '失败' : '重试中'}</span></td>
      <td>${esc(r.from)}</td><td>${esc(r.to)}</td><td>${r.attempts}</td><td>${esc(r.created_at.slice(5, 16))}</td>
      <td class="hint" style="max-width:200px;word-break:break-all">${esc(r.last_error || '')}</td></tr>`).join('') : '<tr><td colspan=6 class="hint">队列为空</td></tr>');
  } else if (t === 'conf') {
    const s = await api.req('/admin/settings');
    $('#regToggle').classList.toggle('on', s.registration_enabled);
    const ports = (await api.req('/admin/ports')).items;
    $$('.port-item [data-port]').forEach((f) => {
      const v = ports[f.dataset.port] || '';
      f.value = v.startsWith(':') ? v.slice(1) : v; // 纯数字显示
    });
  }
}
async function toggleReg() {
  const on = !$('#regToggle').classList.contains('on');
  try {
    await api.req('/admin/settings', { method: 'PUT', body: JSON.stringify({ registration_enabled: on }) });
    $('#regToggle').classList.toggle('on', on);
    toast(on ? '注册已开放' : '注册已关闭');
  } catch (e) { toast(e.error || '失败'); }
}
async function savePorts() {
  const body = {};
  $$('.port-item [data-port]').forEach((f) => body[f.dataset.port] = f.value.trim()); // 纯数字，后端补冒号
  try {
    const r = await api.req('/admin/ports', { method: 'PUT', body: JSON.stringify(body) });
    toast('端口已保存：' + (r.note || '重启后生效'));
  } catch (e) { toast(e.error || '保存失败'); }
}
async function createUser() {
  try {
    const r = await api.req('/admin/users', { method: 'POST',
      body: JSON.stringify({ username: $('#nuName').value.trim(), password: $('#nuPass').value }) });
    $('#nuName').value = ''; $('#nuPass').value = '';
    toast('用户已创建：' + (r.address || '')); loadAdmin();
  } catch (e) { toast(e.error || '创建失败'); }
}
async function userOp(id, op) {
  let pwd = '';
  if (op === 'reset') {
    pwd = prompt('输入新密码（至少 6 位）');
    if (!pwd) return;
    if (pwd.length < 6) { toast('密码至少 6 位'); return; }
  }
  await api.req(`/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify({ op, password: pwd }) });
  toast('操作成功'); loadAdmin();
}
async function resetPw(id) { userOp(id, 'reset'); }
async function delDomain(id) {
  const d = (state.adminDomains || []).find((x) => x.id === id);
  if (!d) return;
  if (!confirm('确定删除域名 ' + d.domain + '？其下有邮箱时会被拒绝')) return;
  try {
    await api.req(`/admin/domains/${id}`, { method: 'DELETE' });
    toast('域名已删除'); loadAdmin();
  } catch (e) { toast(e.error || '删除失败'); }
}
async function verifyDomain(id) {
  try {
    await api.req(`/admin/domains/${id}/verify`, { method: 'POST', body: '{}' });
    toast('域名验证通过'); loadAdmin();
  } catch (e) {
    // DNS 查不到时别只弹一句"失败"就完了，直接把旁路给出来。
    // 内网/测试环境没有可管理的公网 DNS，硬等 TXT 生效等于永远卡住。
    const msg = (e.error || '验证失败') + '\n\n如果这个域名没有可管理的公网 DNS（内网、测试环境），可以跳过验证直接启用。要跳过吗？';
    if (confirm(msg)) await forceVerify(id);
  }
}
async function forceVerify(id) {
  if (!confirm('跳过 DNS 验证后，该域名立即视为已验证，可以创建邮箱并对外发信。\n\n确定继续？')) return;
  try {
    await api.req(`/admin/domains/${id}/verify`, { method: 'POST', body: JSON.stringify({ force: true }) });
    toast('已标记为已验证'); loadAdmin();
  } catch (e) { toast(e.error || '操作失败'); }
}
async function addDomain() {
  try {
    await api.req('/admin/domains', { method: 'POST', body: JSON.stringify({ domain: $('#ndName').value.trim() }) });
    $('#ndName').value = '';
    toast('域名已添加 · 待验证，列表中可直接复制 TXT 记录');
    loadAdmin();
  } catch (e) { toast(e.error || '添加失败'); }
}

/* ---------- 入口 ---------- */
// 有 token 就先把外壳按上次的视图摆好（同步、首帧即正确），再去补数据。
if (api.token) { primeShell(); boot(); } else showLogin();

/* ---------- DKIM 详情弹窗 ---------- */
async function showDkim(id) {
  const d = (state.adminDomains || []).find((x) => x.id === id);
  if (!d?.dkim_dns) { toast('DKIM 记录生成中'); return; }
  $('#dkimDlgTitle').textContent = 'DKIM 记录 · ' + d.domain;
  $('#dkimHost').value = 'TXT  ' + d.dkim_dns.host;
  $('#dkimValue').value = d.dkim_dns.record;
  openDlg('dkimDlg');
}
function copyDkim() {
  navigator.clipboard?.writeText($('#dkimValue').value);
  toast('DKIM 完整记录值已复制');
}
