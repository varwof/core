/* pki Manager — Web UI */
(function() {
'use strict';

const API = '/api/v1';
let TOKEN = '';
let USER = {};

const $ = id => document.getElementById(id);
const qs = (sel, ctx) => (ctx||document).querySelector(sel);
const qa = (sel, ctx) => (ctx||document).querySelectorAll(sel);

function escape(s) { var d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

function __(key) {
  var parts = key.split('.');
  var v = window.__LOCALE__;
  for (var i = 0; v && i < parts.length; i++) v = v[parts[i]];
  if (v == null || typeof v !== 'string') v = key;
  var args = Array.prototype.slice.call(arguments, 1);
  if (args.length) {
    v = v.replace(/%[sd]/g, function() { return String(args.shift()); });
  }
  return v;
}

function initUI() {
  var ids = {
    pageTitle: __('ui.app_title'),
    loginTitle: __('ui.app_title'),
    loginSubtitle: __('ui.login_subtitle'),
    loginUsername: function() { this.placeholder = __('ui.login_username'); },
    loginPassword: function() { this.placeholder = __('ui.login_password'); },
    loginBtn: __('ui.login_btn'),
    sidebarLogo: 'pki',
    navDashboard: __('ui.nav_dashboard'),
    navCerts: __('ui.nav_certs'),
    navIssue: __('ui.nav_issue'),
    navCas: __('ui.nav_cas'),
    navTopology: __('ui.nav_topology'),
    navRa: __('ui.nav_ra'),
    navReports: __('ui.nav_reports'),
    navAdmin: __('ui.nav_admin'),
    logoutBtn: function() { this.title = __('ui.logout_title'); },
    pageDashboardTitle: __('ui.page_dashboard'),
    pageCertsTitle: __('ui.page_certs'),
    pageIssueTitle: __('ui.page_issue'),
    pageCasTitle: __('ui.page_cas'),
    pageTopologyTitle: __('ui.page_topology'),
    pageRaTitle: __('ui.page_ra'),
    pageReportsTitle: __('ui.page_reports'),
    reportsDesc: __('ui.reports_desc'),
    pageAdminTitle: __('ui.page_admin'),
    expiryTitle: __('ui.expiry_distribution'),
    certSearch: function() { this.placeholder = __('ui.cert_search_placeholder'); },
    certStatusAll: __('ui.cert_status_all'),
    certStatusValid: __('ui.cert_status_valid'),
    certStatusRevoked: __('ui.cert_status_revoked'),
    refreshCerts: __('ui.cert_refresh'),
    issueCALabel: __('ui.issue_ca_label'),
    issueCNLabel: __('ui.issue_cn_label'),
    issueSANLabel: __('ui.issue_san_label'),
    issueSAN: function() { this.placeholder = __('ui.issue_san_placeholder'); },
    issueValidityLabel: __('ui.issue_validity_label'),
    issueKeyTypeLabel: __('ui.issue_key_type_label'),
    issueProfileLabel: __('ui.issue_profile_label'),
    issueBtn: __('ui.issue_btn'),
    adminTabUsers: __('ui.admin_users'),
    adminTabTokens: __('ui.admin_tokens'),
    adminTabAudit: __('ui.admin_audit'),
    adminTabConfig: __('ui.admin_config'),
    adminTabConfig: __('ui.admin_config'),
    raTabPending: __('ui.ra_pending'),
    raTabHistory: __('ui.ra_history'),
    refreshRA: __('ui.ra_refresh'),
    reportsSoc2: __('ui.reports_soc2'),
    reportsPci: __('ui.reports_pci'),
    reportsGenerate: __('ui.reports_generate'),
  };
  for (var id in ids) {
    var el = $(id);
    if (!el) continue;
    var val = ids[id];
    if (typeof val === 'function') { val.call(el); }
    else if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') { el.placeholder = val; }
    else { el.textContent = val; }
  }
}

async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' }};
  if (TOKEN) opts.headers['X-Auth-Token'] = TOKEN;
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(API + path, opts);
  if (r.status === 401 && path !== '/users/login') { logout(); return null; }
  const text = await r.text();
  try { return JSON.parse(text); } catch(e) { return text; }
}

function toast(msg, type) {
  const t = $('toast'); t.textContent = msg; t.className = 'toast visible ' + (type||'');
  setTimeout(() => t.className = 'toast hidden', 3000);
}

// ─── Login ───
async function login() {
  const resp = await api('POST', '/users/login', {
    username: $('loginUsername').value,
    password: $('loginPassword').value
  });
  if (resp && resp.token) {
    TOKEN = resp.token; USER = resp;
    $('loginPage').classList.add('hidden');
    $('app').classList.remove('hidden');
    $('userDisplay').textContent = __('ui.user_display', USER.username, USER.role);
    loadDashboard();
  } else {
    $('loginError').textContent = __('ui.login_error');
  }
}

function logout() {
  api('POST', '/users/logout');
  TOKEN = ''; USER = {};
  $('app').classList.add('hidden');
  $('loginPage').classList.remove('hidden');
  $('loginUsername').value = '';
  $('loginPassword').value = '';
}

// ─── Navigation ───
qa('.nav-btn').forEach(btn => {
  btn.onclick = function() {
    qa('.nav-btn').forEach(b => b.classList.remove('active'));
    qa('.page').forEach(p => p.classList.remove('active'));
    this.classList.add('active');
    const page = $('page-' + this.dataset.page);
    if (page) {
      page.classList.add('active');
      switch(this.dataset.page) {
        case 'dashboard': if (!dashboardEventSource) startDashboardSSE(); break;
        case 'certs': loadCerts(); break;
        case 'issue': loadIssueForm(); break;
        case 'cas': loadCAs(); break;
        case 'topology': loadTopology(); break;
        case 'ra': loadRA('pending'); break;
        case 'reports': loadReports(); break;
        case 'admin': loadAdmin('users'); break;
      }
    }
  };
});

// ─── Dashboard ───
let dashboardEventSource = null;

function startDashboardSSE() {
  if (dashboardEventSource) dashboardEventSource.close();
  dashboardEventSource = new EventSource(API + '/dashboard/events');
  dashboardEventSource.onmessage = function(e) {
    try { renderDashboard(JSON.parse(e.data)); } catch(_) {}
  };
  dashboardEventSource.onerror = function() {
    // fallback: poll every 30s
    setTimeout(function() {
      loadDashboard();
    }, 30000);
  };
}

function renderDashboard(d) {
  if (!d) return;
  const s = d.summary;
  $('statsGrid').innerHTML = `
    <div class="stat-card"><h3>${__('ui.stat_total_certs')}</h3><p class="value">${s.total_certs}</p></div>
    <div class="stat-card"><h3>${__('ui.stat_valid')}</h3><p class="value">${s.valid}</p></div>
    <div class="stat-card"><h3>${__('ui.stat_revoked')}</h3><p class="value danger">${s.revoked}</p></div>
    <div class="stat-card"><h3>${__('ui.stat_expiring_30d')}</h3><p class="value warn">${s.expiring_30d}</p></div>
    <div class="stat-card"><h3>${__('ui.stat_ca_count')}</h3><p class="value">${s.total_cas}</p></div>
    <div class="stat-card"><h3>${__('ui.stat_revoke_rate')}</h3><p class="value">${(s.revoked_ratio*100).toFixed(1)}%</p></div>`;
  const ne = d.nearest_expiry;
  if (ne) {
    var daysLabel, daysCls;
    if (ne.days_left <= 0) { daysLabel = __('ui.stat_nearest_expired'); daysCls = 'danger'; }
    else if (ne.days_left <= 30) { daysLabel = __('ui.stat_nearest_days', ne.days_left); daysCls = 'danger'; }
    else if (ne.days_left <= 60) { daysLabel = __('ui.stat_nearest_days', ne.days_left); daysCls = 'warn'; }
    else { daysLabel = __('ui.stat_nearest_days', ne.days_left); daysCls = 'ok'; }
    $('nearestExpiry').innerHTML =
      '<div class="stat-card nearest-card"><h3>' + __('ui.stat_nearest_expiry') + '</h3>' +
      '<p class="value ' + daysCls + '">' + daysLabel + '</p>' +
      '<p class="nearest-cn">' + escape(ne.common_name) + '</p>' +
      '<p class="nearest-meta">' + escape(ne.ca_name) + ' · ' + ne.not_after.slice(0,10) + '</p></div>';
  } else {
    $('nearestExpiry').innerHTML =
      '<div class="stat-card nearest-card"><h3>' + __('ui.stat_nearest_expiry') + '</h3>' +
      '<p class="nearest-cn">' + __('ui.stat_nearest_none') + '</p></div>';
  }
  const e = d.expiry;
  const max = Math.max(e.within_30d, e.within_60d, e.within_90d, e.within_180d, e.within_365d, e.over_365d, 1);
  $('expiryBars').innerHTML = [
    {k:'within_30d', cls:'danger'},
    {k:'within_60d', cls:'warn'},
    {k:'within_90d', cls:'warn2'},
    {k:'within_180d', cls:'ok2'},
    {k:'within_365d', cls:'ok'},
    {k:'over_365d', cls:'ok'},
  ].map(function(item) {
    var v = e[item.k];
    return '<div class="bar-row"><span class="bar-label">' + item.k.replace('within_','').replace('_','-') + '</span><div class="bar-track"><div class="bar-fill ' + item.cls + '" style="width:' + (v/max*100).toFixed(0) + '%"></div></div><span class="bar-val">' + v + '</span></div>';
  }).join('');
}

async function loadDashboard() {
  const d = await api('GET', '/dashboard');
  renderDashboard(d);
}

// ─── Certificates ───
async function loadCerts() {
  const params = new URLSearchParams();
  const search = $('certSearch').value;
  const status = $('certStatus').value;
  if (status) params.set('status', status);
  if (search) params.set('cn', search);
  const certs = await api('GET', '/certs?' + params.toString());
  if (!certs) return;
  $('certsList').innerHTML = '<table class="data-table"><thead><tr><th>' + __('ui.cert_table_serial') + '</th><th>' + __('ui.cert_table_cn') + '</th><th>' + __('ui.cert_table_ca') + '</th><th>' + __('ui.cert_table_status') + '</th><th>' + __('ui.cert_table_expires') + '</th><th>' + __('ui.cert_table_action') + '</th></tr></thead><tbody>' +
    certs.map(c => `<tr><td title="${escape(c.serial_number)}">${escape(c.serial_number).slice(0,16)}…</td><td>${escape(c.common_name)}</td><td>${escape(c.ca_name)}</td><td>${c.status}</td><td>${c.not_after.slice(0,10)}</td><td><button onclick="showCert('${c.ca_name}','${c.serial_number}')">${__('ui.cert_view')}</button></td></tr>`
    ).join('') + '</tbody></table>';
}

async function showCert(ca, serial) {
  const c = await api('GET', '/cert/' + ca + '/' + serial);
  if (!c) { toast(__('ui.cert_not_exist'), 'error'); return; }
  const m = $('modal');
  qs('.modal-content', m).innerHTML = `<span class="modal-close" onclick="closeModal()">&times;</span>
    <h3>${__('ui.cert_detail_title')}</h3><pre>${escape(JSON.stringify(c,null,2))}</pre>
    <button onclick="revokeCert('${ca}','${serial}')">${__('ui.cert_revoke_btn')}</button>`;
  m.classList.remove('hidden');
  $('overlay').classList.remove('hidden');
}
window.showCert = showCert;
window.closeModal = function() { $('modal').classList.add('hidden'); $('overlay').classList.add('hidden'); };

async function revokeCert(ca, serial) {
  if (!confirm(__('ui.cert_revoke_confirm'))) return;
  const r = await api('POST', `/cert/${ca}/${serial}/revoke`, { reason: 'unspecified' });
  toast(r ? __('ui.cert_revoke_success') : __('ui.cert_revoke_fail'), r ? 'success' : 'error');
  closeModal(); loadCerts();
}
window.revokeCert = revokeCert;

// ─── Issue Certificate ───
async function loadIssueForm() {
  const cas = await api('GET', '/cas');
  if (cas) $('issueCA').innerHTML = cas.map(c => `<option value="${c.name}">${c.name}</option>`).join('');
}

$('issueForm').onsubmit = async function(e) {
  e.preventDefault();
  const body = {
    ca: $('issueCA').value,
    cn: $('issueCN').value,
    san: $('issueSAN').value,
    validity: parseInt($('issueValidity').value) || 365,
    key_type: $('issueKeyType').value,
    profile: $('issueProfile').value,
  };
  const r = await api('POST', '/certs', body);
  if (r && r.serial_number) {
    $('issueResult').classList.remove('hidden');
    $('issueResult').textContent = __('ui.issue_result_prefix', r.serial_number, r.cert_pem, r.key_pem);
    toast(__('ui.issue_success'), 'success');
  } else {
    toast(__('ui.issue_fail'), 'error');
  }
};

// ─── CAs ───
async function loadCAs() {
  const cas = await api('GET', '/cas');
  if (!cas) return;
  $('casList').innerHTML = cas.map(c => `<div class="ca-card"><h3>${__('ui.ca_card_title', c.name)}</h3><table><tr><td>${__('ui.ca_subject')}</td><td>${escape(c.subject)}</td></tr><tr><td>${__('ui.ca_algorithm')}</td><td>${escape(c.key_algorithm)}</td></tr><tr><td>${__('ui.ca_expires')}</td><td>${c.not_after}</td></tr><tr><td>${__('ui.ca_fingerprint')}</td><td style="font-family:monospace">${escape(c.fingerprint)}</td></tr></table></div>`).join('');
}

// ─── Topology ───
async function loadTopology() {
  const cas = await api('GET', '/cas/tree');
  if (!cas) return;
  $('topoSvg').innerHTML = cas.nodes ? renderTree(cas) : `<text x="20" y="30">${__('ui.topology_loading')}</text>`;
}

function renderTree(data) {
  let y = 40;
  return data.nodes.map(n => {
    const el = `<g transform="translate(20,${y})"><rect x="0" y="-12" width="200" height="24" rx="4" fill="var(--card-bg)" stroke="var(--border)"/><text x="10" y="4" font-size="13">${escape(n.name)}</text></g>`;
    y += 50;
    return el;
  }).join('');
}

// ─── Admin ───
qa('.admin-tab').forEach(tab => {
  tab.onclick = function() {
    qa('.admin-tab').forEach(t => t.classList.remove('active'));
    qa('.admin-content').forEach(c => c.classList.add('hidden'));
    this.classList.add('active');
    loadAdmin(this.dataset.tab);
  };
});

async function loadAdmin(tab) {
  const c = $('adminContent');
  if (tab === 'users') {
    const users = await api('GET', '/users');
    c.innerHTML = `<button id="newUserBtn" class="btn-sm">${__('ui.admin_new_user')}</button>
      <div id="newUserForm" class="hidden"><input id="nuUser" placeholder="${__('ui.admin_user_placeholder')}"><input id="nuPass" type="password" placeholder="${__('ui.admin_pass_placeholder')}"><select id="nuRole"><option value="operator">${__('ui.admin_role_operator')}</option><option value="admin">${__('ui.admin_role_admin')}</option><option value="auditor">${__('ui.admin_role_auditor')}</option></select><button id="createUserBtn">${__('ui.admin_create_btn')}</button></div>
      <table class="data-table"><thead><tr><th>${__('ui.admin_user_table_user')}</th><th>${__('ui.admin_user_table_role')}</th><th>${__('ui.admin_user_table_created')}</th></tr></thead><tbody>${
        (users||[]).map(u => `<tr><td>${escape(u.username)}</td><td>${escape(u.role)}</td><td>${u.created_at}</td></tr>`).join('')}</tbody></table>`;
    $('newUserBtn').onclick = () => $('newUserForm').classList.toggle('hidden');
    $('createUserBtn').onclick = async () => {
      await api('POST', '/users', { username: $('nuUser').value, password: $('nuPass').value, role: $('nuRole').value });
      toast(__('ui.admin_user_created')); loadAdmin('users');
    };
  } else if (tab === 'tokens') {
    const tokens = await api('GET', '/tokens?user_id=0');
    c.innerHTML = `<table class="data-table"><thead><tr><th>${__('ui.admin_token_table_token')}</th><th>${__('ui.admin_token_table_desc')}</th><th>${__('ui.admin_token_table_created')}</th></tr></thead><tbody>${
      (tokens||[]).map(t => `<tr><td style="font-family:monospace">${escape(t.token).slice(0,32)}…</td><td>${escape(t.description)}</td><td>${t.created_at}</td></tr>`).join('')}</tbody></table>`;
  } else if (tab === 'audit') {
    const entries = await api('GET', '/audit?limit=20');
    c.innerHTML = `<table class="data-table"><thead><tr><th>${__('ui.admin_audit_table_time')}</th><th>${__('ui.admin_audit_table_user')}</th><th>${__('ui.admin_audit_table_action')}</th><th>${__('ui.admin_audit_table_detail')}</th></tr></thead><tbody>${
      (entries||[]).map(e => `<tr><td>${e.timestamp}</td><td>${escape(e.username)}</td><td>${escape(e.action)}</td><td>${escape(e.detail||'')}</td></tr>`).join('')}</tbody></table>`;
  } else if (tab === 'config') {
    const resp = await api('GET', '/admin/config');
    if (!resp) { c.innerHTML = '<p>Error loading config</p>'; return; }
    const cfgStr = JSON.stringify(resp.config, null, 2);
    c.innerHTML = '<p style="margin-bottom:8px;color:var(--text2)">Config path: ' + escape(resp.config_path||'unknown') + ' | Hot reload: ' + (resp.hot_reload ? 'Yes' : 'No') + '</p>' +
      '<textarea id="configEditor" style="width:100%;height:400px;font-family:monospace;font-size:12px;background:var(--card-bg);color:var(--text1);border:1px solid var(--border);border-radius:6px;padding:8px;resize:vertical">' + escape(cfgStr) + '</textarea>' +
      '<div style="margin-top:8px"><button onclick="saveConfig()">' + __('ui.admin_config_save') + '</button><span id="configSaveStatus" style="margin-left:8px;color:var(--text2)"></span></div>';
  }
}
window.saveConfig = async function() {
  var editor = document.getElementById('configEditor');
  var status = document.getElementById('configSaveStatus');
  if (!editor || !status) return;
  try {
    var cfg = JSON.parse(editor.value);
    var r = await api('PUT', '/admin/config', { config: cfg });
    if (r && r.status === 'ok') {
      status.textContent = __('ui.admin_config_saved');
      status.style.color = 'var(--success)';
    } else {
      status.textContent = __('ui.admin_config_save_fail');
      status.style.color = 'var(--danger)';
    }
  } catch(e) {
    status.textContent = 'Invalid JSON: ' + e.message;
    status.style.color = 'var(--danger)';
  }
};


// ─── RA Tabs ───
qa('.ra-tab').forEach(tab => {
  tab.onclick = function() {
    qa('.ra-tab').forEach(t => t.classList.remove('active'));
    qa('.ra-content').forEach(c => c.classList.add('hidden'));
    this.classList.add('active');
    loadRA(this.dataset.tab);
  };
});

async function loadRA(tab) {
  const c = $('raContent');
  const data = await api('GET', '/ra');
  if (!data) { c.innerHTML = '<p>Error loading requests</p>'; return; }
  const items = Array.isArray(data) ? data : (data.requests || []);
  const isPending = tab === 'pending';
  const filtered = isPending ? items.filter(r => r.status === 'pending') : items.filter(r => r.status !== 'pending');
  c.innerHTML = '<table class="data-table"><thead><tr>' +
    `<th>${__('ui.ra_table_id')}</th><th>${__('ui.ra_table_cn')}</th><th>${__('ui.ra_table_ca')}</th><th>${__('ui.ra_table_profile')}</th><th>${__('ui.ra_table_requester')}</th><th>${__('ui.ra_table_status')}</th><th>${__('ui.ra_table_date')}</th>` +
    (isPending ? `<th>${__('ui.ra_table_action')}</th>` : '') +
    '</tr></thead><tbody>' +
    filtered.map(r => `<tr>
      <td>${r.id}</td>
      <td>${escape(r.common_name)}</td>
      <td>${escape(r.ca_name)}</td>
      <td>${escape(r.profile)}</td>
      <td>${escape(r.requester)}</td>
      <td>${r.status}</td>
      <td>${r.requested_at}</td>
      ${isPending ? `<td>
        <button style="background:var(--success)" onclick="doRA(${r.id},'approve')">${__('ui.ra_approve')}</button>
        <button style="background:var(--danger)" onclick="doRA(${r.id},'reject')">${__('ui.ra_reject')}</button>
      </td>` : ''}
    </tr>`).join('') +
    '</tbody></table>' +
    (filtered.length === 0 ? '<p style="text-align:center;color:var(--text2);padding:20px;">No requests found</p>' : '');
}

async function doRA(id, action) {
  const comment = prompt(__('ui.ra_comment_placeholder') + ':');
  const r = await api('POST', `/ra/${id}/${action}`, { comment: comment || '' });
  if (r) {
    toast(action === 'approve' ? __('ui.ra_approve_success') : __('ui.ra_reject_success'), 'success');
    loadRA('pending');
  } else {
    toast(action === 'approve' ? __('ui.ra_approve_fail') : __('ui.ra_reject_fail'), 'error');
  }
}
window.doRA = doRA;

$('refreshRA').onclick = () => loadRA('pending');

// ─── Reports ───
async function loadReports() {
  const g = $('reportsGrid');
  g.innerHTML = [
    { title: __('ui.reports_soc2'), desc: 'SOC 2 Type II self-assessment — certificate inventory, CA hierarchy, CRL/OCSP status, key strength analysis.', url: '/api/v1/reports/compliance?soc2' },
    { title: __('ui.reports_pci'), desc: 'PCI DSS v4.0 self-assessment — certificate validity, key strength, revocation checks, expiring certs.', url: '/api/v1/reports/compliance?pci' },
  ].map(r => `<div class="stat-card" style="cursor:pointer" onclick="window.open('${r.url}','_blank')">
    <h3>${r.title}</h3>
    <p style="font-size:13px;color:var(--text2);margin:8px 0 12px">${r.desc}</p>
    <button class="btn-sm">${__('ui.reports_generate')}</button>
  </div>`).join('');
}

// ─── Init ───
initUI();

// Session is carried by an HttpOnly cookie (login) or by the client's mTLS
// certificate; probe /session to detect the current user and, when present,
// the certificate identity bound to the session (Web user detection).
async function tryRestoreSession() {
  const resp = await api('GET', '/session');
  if (resp && resp.authenticated && resp.username) {
    USER = resp;
    $('loginPage').classList.add('hidden');
    $('app').classList.remove('hidden');
    $('userDisplay').textContent = __('ui.user_display', USER.username, USER.role);
    if (resp.cert_identity) {
      const ci = resp.cert_identity;
      const certNote = __('ui.cert_identity', ci.cn || ci.serial) +
        (ci.principal_uid ? ' · ' + ci.principal_uid : '') +
        (ci.spki_hash ? ' · ' + ci.spki_hash.slice(0, 16) : '');
      $('userDisplay').title = certNote;
    }
    startDashboardSSE();
  }
}
tryRestoreSession();

$('loginBtn').onclick = login;
$('loginPassword').onkeydown = e => { if (e.key === 'Enter') login(); };
$('logoutBtn').onclick = logout;
$('refreshCerts').onclick = loadCerts;
$('certSearch').oninput = loadCerts;
$('certStatus').onchange = loadCerts;
$('overlay').onclick = () => { $('modal').classList.add('hidden'); $('overlay').classList.add('hidden'); };

// Dark mode
const dark = window.matchMedia('(prefers-color-scheme: dark)');
if (dark.matches) document.documentElement.setAttribute('data-theme', 'dark');
dark.addEventListener('change', e => document.documentElement.setAttribute('data-theme', e.matches ? 'dark' : 'light'));

})();
