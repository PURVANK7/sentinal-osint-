/* SENTINEL v2 · app.js */

const S = { token: null, user: null, stats: { total:0, ips:0, threats:0, clean:0 }, activity: [] };

// ── INIT ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initMatrix();
  initClock();
  checkOAuthCallback();
  checkAuth();
  setupTabs();
  setupNav();
  setupLogout();
  setupPasswordStrength();
  document.getElementById('sidebar-toggle').onclick = () => document.getElementById('sidebar').classList.toggle('open');
});

function checkOAuthCallback() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token');
  const user = params.get('user');
  if (token && user) {
    try {
      S.token = token;
      S.user = JSON.parse(decodeURIComponent(user));
      sessionStorage.setItem('s_token', token);
      sessionStorage.setItem('s_user', JSON.stringify(S.user));
      window.history.replaceState({}, '', '/');
      showDashboard();
    } catch(e) { console.error('OAuth callback error', e); }
  }
  const error = params.get('error');
  if (error) {
    window.history.replaceState({}, '', '/');
    showToast('Social login failed. Try again.', 'error');
  }
}

function checkAuth() {
  const token = sessionStorage.getItem('s_token');
  const user = JSON.parse(sessionStorage.getItem('s_user') || 'null');
  if (token && user) { S.token = token; S.user = user; showDashboard(); }
}

// ── AUTH TABS ──────────────────────────────────────────
function setupTabs() {
  document.querySelectorAll('.auth-tab').forEach(tab => {
    tab.onclick = () => {
      document.querySelectorAll('.auth-tab,.auth-form').forEach(el => el.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    };
  });
}

// ── LOGIN ─────────────────────────────────────────────
async function doLogin() {
  const un = document.getElementById('login-username').value.trim();
  const pw = document.getElementById('login-password').value;
  const errEl = document.getElementById('login-error');
  const btn = document.getElementById('login-btn');
  errEl.classList.add('hidden');
  if (!un || !pw) { errEl.textContent = 'Username and password required'; errEl.classList.remove('hidden'); return; }
  setBtnLoading(btn, true);
  try {
    const res = await fetch('/api/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:un, password:pw}) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    S.token = data.token; S.user = data.user;
    sessionStorage.setItem('s_token', data.token);
    sessionStorage.setItem('s_user', JSON.stringify(data.user));
    showDashboard();
  } catch(e) { errEl.textContent = '⚠ ' + e.message; errEl.classList.remove('hidden'); }
  finally { setBtnLoading(btn, false); }
}

// ── REGISTER ──────────────────────────────────────────
async function doRegister() {
  const name = document.getElementById('reg-name').value.trim();
  const username = document.getElementById('reg-username').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const phone = document.getElementById('reg-phone').value.trim();
  const password = document.getElementById('reg-password').value;
  const errEl = document.getElementById('reg-error');
  const btn = document.getElementById('reg-btn');
  errEl.classList.add('hidden');
  if (!username || !email || !password) { errEl.textContent = 'Username, email and password are required'; errEl.classList.remove('hidden'); return; }
  setBtnLoading(btn, true);
  try {
    const res = await fetch('/api/auth/register', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name, username, email, phone, password}) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    S.token = data.token; S.user = data.user;
    sessionStorage.setItem('s_token', data.token);
    sessionStorage.setItem('s_user', JSON.stringify(data.user));
    showDashboard();
    showToast('Account created successfully!');
  } catch(e) { errEl.textContent = '⚠ ' + e.message; errEl.classList.remove('hidden'); }
  finally { setBtnLoading(btn, false); }
}

function setBtnLoading(btn, loading) {
  btn.querySelector('span').style.display = loading ? 'none' : '';
  btn.querySelector('.btn-spinner').style.display = loading ? 'block' : 'none';
  btn.disabled = loading;
}

function fillLogin(u, p) {
  document.getElementById('login-username').value = u;
  document.getElementById('login-password').value = p;
}

function togglePw(id) {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
}

function setupPasswordStrength() {
  const pw = document.getElementById('reg-password');
  const bar = document.getElementById('pw-strength');
  if (!pw) return;
  pw.addEventListener('input', () => {
    const v = pw.value;
    let score = 0;
    if (v.length >= 8) score++;
    if (/[A-Z]/.test(v)) score++;
    if (/[0-9]/.test(v)) score++;
    if (/[^A-Za-z0-9]/.test(v)) score++;
    const colors = ['#ff2b4e','#ffaa00','#ffaa00','#00ff88'];
    bar.style.width = (score * 25) + '%';
    bar.style.background = colors[score - 1] || 'transparent';
  });
}

// ── SHOW DASHBOARD ───────────────────────────────────
function showDashboard() {
  document.getElementById('auth-view').classList.remove('active');
  document.getElementById('dashboard-view').classList.add('active');
  const u = S.user;
  document.getElementById('user-display-name').textContent = u.name || u.username;
  document.getElementById('user-av').textContent = (u.name || u.username)[0].toUpperCase();
  const tag = document.getElementById('user-team-tag');
  tag.textContent = u.role === 'admin' ? 'ADMIN · ALL ACCESS' : (u.team || 'USER').toUpperCase() + ' TEAM';
  tag.className = 'team-tag ' + (u.role === 'admin' ? 'both' : (u.team || 'blue'));
  if (u.role === 'admin') {
    document.getElementById('admin-nav').style.display = 'block';
  }
  loadRecentActivity();
}

function setupLogout() {
  document.getElementById('logout-btn').onclick = () => {
    sessionStorage.clear();
    S.token = null; S.user = null;
    document.getElementById('dashboard-view').classList.remove('active');
    document.getElementById('auth-view').classList.add('active');
  };
}

// ── NAVIGATION ──────────────────────────────────────
function setupNav() {
  document.querySelectorAll('[data-panel]').forEach(el => {
    el.addEventListener('click', e => { e.preventDefault(); switchPanel(el.dataset.panel); });
  });
}

const panelTitles = {
  'panel-dashboard':'Dashboard','panel-ip':'IP Lookup','panel-whois':'WHOIS Lookup',
  'panel-dns':'DNS Records','panel-subdomain':'Subdomain Enumeration','panel-email':'Email OSINT',
  'panel-username':'Username Recon','panel-threat':'Threat Intelligence','panel-port':'Port Scanner',
  'panel-ssl':'SSL Analyzer','panel-network':'Network Intelligence','panel-darkweb':'Dark Web Monitor',
  'panel-activity':'Activity Log','panel-admin':'Admin Panel','panel-users':'User Management'
};

function switchPanel(id) {
  document.querySelectorAll('.panel,.nav-item').forEach(el => el.classList.remove('active'));
  document.getElementById(id)?.classList.add('active');
  document.querySelector(`[data-panel="${id}"]`)?.classList.add('active');
  document.getElementById('topbar-title').textContent = panelTitles[id] || 'Dashboard';
  if (id === 'panel-activity') loadActivityPanel();
  if (id === 'panel-admin') loadAdminPanel();
  if (id === 'panel-users') loadUsersPanel();
  if (window.innerWidth <= 768) document.getElementById('sidebar').classList.remove('open');
}

// ── TOOL RUNNER ─────────────────────────────────────
const TOOLS = {
  ip:        { input:'ip-input',        result:'ip-result',        endpoint:'/api/osint/ip-lookup',  body:v=>({ip:v}) },
  whois:     { input:'whois-input',     result:'whois-result',     endpoint:'/api/osint/whois',      body:v=>({domain:v}) },
  dns:       { input:'dns-input',       result:'dns-result',       endpoint:'/api/osint/dns',        body:v=>({domain:v}) },
  subdomain: { input:'subdomain-input', result:'subdomain-result', endpoint:'/api/osint/subdomains', body:v=>({domain:v}) },
  email:     { input:'email-input',     result:'email-result',     endpoint:'/api/osint/email',      body:v=>({email:v}) },
  username:  { input:'username-input',  result:'username-result',  endpoint:'/api/osint/username',   body:v=>({username:v}) },
  threat:    { input:'threat-input',    result:'threat-result',    endpoint:'/api/osint/threat-intel', body:v=>({indicator:v, type:document.getElementById('threat-type').value}) },
  port:      { input:'port-input',      result:'port-result',      endpoint:'/api/osint/port-scan',  body:v=>({ip:v}) },
  darkweb:   { input:'darkweb-input',   result:'darkweb-result',   endpoint:'/api/osint/darkweb',    body:v=>({query:v, type:document.getElementById('darkweb-type').value}) },
  ssl:       { input:'ssl-input',       result:'ssl-result',       endpoint:'/api/osint/ssl',        body:v=>({domain:v}) },
  network:   { input:'network-input',   result:'network-result',   endpoint:'/api/osint/network',    body:v=>({query:v, type:document.getElementById('network-type').value}) }
};

async function runTool(tool) {
  const c = TOOLS[tool]; if (!c) return;
  const inputEl = document.getElementById(c.input);
  const value = inputEl.value.trim();
  if (!value) { inputEl.focus(); return; }
  const resultEl = document.getElementById(c.result);
  const btn = document.getElementById(tool + '-btn');
  resultEl.classList.remove('hidden');
  resultEl.innerHTML = `<div class="loading-row"><div class="spin"></div><span>SCANNING ${value.toUpperCase()}...</span></div>`;
  if (btn) btn.disabled = true;
  try {
    const res = await fetch(c.endpoint, {
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+S.token},
      body:JSON.stringify(c.body(value))
    });
    if (res.status === 401 || res.status === 403) { sessionStorage.clear(); location.reload(); return; }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Scan failed');
    S.stats.total++; updateStats();
    resultEl.innerHTML = renderResult(tool, data, value);
    addActivity(tool, value, data);
  } catch(e) {
    resultEl.innerHTML = `<div class="res-hdr"><span class="res-title">ERROR</span><span class="badge badge-red">FAILED</span></div><div class="res-body"><div class="ic-val red" style="font-family:var(--mono);font-size:13px">${e.message}</div></div>`;
  } finally { if (btn) btn.disabled = false; }
}

// ── RESULT RENDERERS ────────────────────────────────
function renderResult(tool, data, target) {
  const map = { ip:renderIP, whois:renderWHOIS, dns:renderDNS, subdomain:renderSubdomains, email:renderEmail, username:renderUsername, threat:renderThreat, port:renderPort, darkweb:renderDarkWeb, ssl:renderSSL, network:renderNetwork };
  return (map[tool] || (() => `<div class="res-body"><pre style="font-family:var(--mono);font-size:11px;color:var(--t2)">${JSON.stringify(data,null,2)}</pre></div>`))(data);
}

function infoCard(label, value, cls='') {
  return `<div class="info-card"><div class="ic-label">${label}</div><div class="ic-val ${cls}">${value}</div></div>`;
}

function resHeader(title, badge='', badgeClass='', data=null) {
  const exportBtn = data ? `<button class="copy-btn" onclick="exportJSON('${btoa(JSON.stringify(data))}','${title.replace(/[^a-z0-9]/gi,'_')}')">⬇ EXPORT</button>` : '';
  const badgeHTML = badge ? `<span class="badge ${badgeClass}">${badge}</span>` : '';
  return `<div class="res-hdr"><span class="res-title">${title}</span><div class="res-actions">${exportBtn}${badgeHTML}</div></div>`;
}

function renderIP(d) {
  const risk = d.riskLevel || 'LOW';
  const bc = risk==='HIGH'?'badge-red':risk==='MEDIUM'?'badge-amber':'badge-green';
  if (risk==='HIGH') { S.stats.threats++; } else { S.stats.clean++; }
  S.stats.ips++; updateStats();
  const abuseHTML = d.abuse && !d.abuse.note ? `
    <div class="sec-title">ABUSE INTELLIGENCE</div>
    <div class="info-grid">
      ${infoCard('ABUSE SCORE', d.abuse.abuseScore+'%', d.abuse.abuseScore>50?'red':d.abuse.abuseScore>10?'amber':'green')}
      ${infoCard('TOTAL REPORTS', d.abuse.totalReports)}
      ${infoCard('IS TOR NODE', d.abuse.isTor?'YES':'NO', d.abuse.isTor?'red':'green')}
      ${infoCard('LAST REPORTED', d.abuse.lastReported||'Never')}
    </div>` : d.abuse?.note ? `<div class="info-card" style="margin-top:12px">${infoCard('ABUSEIPDB','⚠ '+d.abuse.note,'amber')}</div>` : '';
  return resHeader('IP ANALYSIS · '+d.ip, 'RISK: '+risk, bc, d) + `<div class="res-body">
    <div class="sec-title">GEOLOCATION</div>
    <div class="info-grid">
      ${infoCard('IP ADDRESS',d.ip,'cyber')}
      ${infoCard('COUNTRY',d.geo.country+' ('+d.geo.countryCode+')')}
      ${infoCard('CITY / REGION',d.geo.city+', '+d.geo.region)}
      ${infoCard('COORDINATES',d.geo.lat+', '+d.geo.lon)}
      ${infoCard('TIMEZONE',d.geo.timezone)}
      ${infoCard('ISP',d.geo.isp)}
      ${infoCard('ASN',d.geo.asn)}
      ${infoCard('ORG',d.geo.org)}
      ${infoCard('IS PROXY',d.geo.isProxy?'⚠ YES':'✓ NO',d.geo.isProxy?'red':'green')}
      ${infoCard('IS HOSTING',d.geo.isHosting?'YES':'NO',d.geo.isHosting?'amber':'green')}
      ${infoCard('IS MOBILE',d.geo.isMobile?'YES':'NO')}
    </div>
    ${abuseHTML}
  </div>`;
}

function renderWHOIS(d) {
  const ents = (d.entities||[]).map(e => infoCard(e.role.toUpperCase(), e.name + (e.email?'<br><span style="color:var(--blue)">'+e.email+'</span>':''))).join('');
  const ns = (d.nameservers||[]).map(n => `<div class="rec-item"><span class="rec-type">NS</span><span class="rec-val">${n}</span></div>`).join('');
  return resHeader('WHOIS · '+d.domain,'','',d)+`<div class="res-body">
    <div class="info-grid">
      ${infoCard('DOMAIN',d.domain,'blue')}${infoCard('STATUS',d.status||'Unknown')}
      ${infoCard('REGISTERED',d.registered||'Unknown')}${infoCard('EXPIRES',d.expires||'Unknown')}
      ${infoCard('LAST UPDATED',d.updated||'Unknown')}${infoCard('HANDLE',d.handle||'Unknown')}
    </div>
    <div class="sec-title">NAME SERVERS</div>
    <div class="rec-list">${ns||'<div style="color:var(--t3);font-family:var(--mono);font-size:12px;padding:8px">None found</div>'}</div>
    <div class="sec-title">ENTITIES</div>
    <div class="info-grid">${ents||'<div style="color:var(--t3);font-family:var(--mono);font-size:12px;padding:8px">Privacy protected</div>'}</div>
  </div>`;
}

function renderDNS(d) {
  const types = ['A','AAAA','MX','NS','TXT','CNAME','SOA'];
  const sections = types.map(t => {
    const recs = d.records[t]||[];
    if (!recs.length) return '';
    return `<div class="sec-title">${t} RECORDS (${recs.length})</div><div class="rec-list">${recs.map(r=>`<div class="rec-item"><span class="rec-type">${t}</span><span class="rec-val">${r}</span></div>`).join('')}</div>`;
  }).join('');
  return resHeader('DNS RECORDS · '+d.domain,'','',d)+`<div class="res-body">${sections||'<div style="color:var(--t3);font-size:12px;padding:8px;font-family:var(--mono)">No records found</div>'}</div>`;
}

function renderSubdomains(d) {
  const items = (d.subdomains||[]).map(s=>`<div class="sub-item">${s}</div>`).join('');
  return resHeader('SUBDOMAINS · '+d.domain, d.count+' FOUND', d.count>10?'badge-amber':'badge-blue', d)+`<div class="res-body">
    <div class="info-grid">
      ${infoCard('TOTAL DISCOVERED',d.count,'blue')}
      ${infoCard('SOURCE',d.source)}
      ${infoCard('SCANNED AT',new Date(d.timestamp).toLocaleString())}
    </div>
    ${d.count>0?`<div class="sec-title">DISCOVERED SUBDOMAINS</div><div class="sub-grid">${items}</div>`:'<div style="color:var(--green);font-family:var(--mono);font-size:12px;padding:12px">✓ No subdomains found in certificate transparency logs.</div>'}
  </div>`;
}

function renderEmail(d) {
  let bHTML = '';
  if (d.breachNote) bHTML = infoCard('BREACH CHECK','⚠ '+d.breachNote,'amber');
  else if (!d.breaches) bHTML = infoCard('BREACH CHECK','Add HIBP_KEY for breach data','amber');
  else if (d.breaches.length===0) bHTML = infoCard('BREACHES','✓ NOT FOUND IN ANY BREACH','green');
  else bHTML = d.breaches.map(b=>infoCard('⚠ BREACH: '+b.name,b.domain+' · '+b.breachDate,'red')).join('');
  const breached = d.breaches && d.breaches.length > 0;
  return resHeader('EMAIL OSINT · '+d.email, breached?d.breaches.length+' BREACHES':'CLEAN', breached?'badge-red':'badge-green', d)+`<div class="res-body">
    <div class="info-grid">
      ${infoCard('EMAIL',d.email,'blue')}
      ${infoCard('DOMAIN',d.domain)}
      ${infoCard('DOMAIN VALID',d.domainValid?'✓ VALID (MX FOUND)':'✗ NO MX RECORDS',d.domainValid?'green':'red')}
    </div>
    <div class="sec-title">MX RECORDS</div>
    <div class="rec-list">${(d.mxRecords||[]).map(r=>`<div class="rec-item"><span class="rec-type">MX</span><span class="rec-val">${r}</span></div>`).join('')||'<div style="color:var(--t3);font-family:var(--mono);font-size:12px;padding:8px">No MX records</div>'}</div>
    <div class="sec-title">BREACH DATABASE</div>
    <div class="info-grid">${bHTML}</div>
  </div>`;
}

function renderUsername(d) {
  const found = d.results.filter(r=>r.found);
  const notFound = d.results.filter(r=>!r.found);
  const mkItem = r => `<a class="plat-item ${r.found?'found':'not-found'}" ${r.found?`href="${r.url}" target="_blank" rel="noopener"`:'href="#"'}>
    <span>${r.found?'✅':'❌'}</span><span class="plat-name">${r.platform}</span>
    ${r.found?`<span class="plat-link">OPEN ↗</span>`:''}
  </a>`;
  return resHeader('USERNAME RECON · @'+d.username, found.length+'/'+d.total+' FOUND', found.length>0?'badge-amber':'badge-green', d)+`<div class="res-body">
    <div class="info-grid">
      ${infoCard('USERNAME','@'+d.username,'blue')}
      ${infoCard('PLATFORMS CHECKED',d.total)}
      ${infoCard('ACCOUNTS FOUND',found.length,found.length>0?'amber':'green')}
    </div>
    ${found.length>0?`<div class="sec-title">✅ FOUND (${found.length})</div><div class="plat-grid">${found.map(mkItem).join('')}</div>`:''}
    <div class="sec-title">❌ NOT FOUND (${notFound.length})</div>
    <div class="plat-grid">${notFound.map(mkItem).join('')}</div>
  </div>`;
}

function renderThreat(d) {
  const isM = d.overallRisk==='MALICIOUS';
  if (isM) { S.stats.threats++; } else { S.stats.clean++; }
  updateStats();
  const srcHTML = (d.sources||[]).map(s=>`<div class="info-card">
    <div class="ic-label">${s.source}</div>
    ${s.note?`<div class="ic-val amber">${s.note}</div>`:
    s.malicious===true||s.malicious>0?`<div class="ic-val red">⚠ MALICIOUS · ${s.pulseCount||s.malicious} hits</div>`:
    `<div class="ic-val green">✓ CLEAN</div>`}
    ${s.tags&&s.tags.length?`<div style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-top:4px">${s.tags.join(', ')}</div>`:''}
  </div>`).join('');
  return resHeader('THREAT INTEL · '+d.indicator, d.overallRisk, isM?'badge-red':'badge-green', d)+`<div class="res-body">
    <div class="info-grid">
      ${infoCard('INDICATOR',d.indicator,'blue')}
      ${infoCard('TYPE',d.type.toUpperCase())}
      ${infoCard('VERDICT',d.overallRisk,isM?'red':'green')}
    </div>
    <div class="sec-title">INTELLIGENCE SOURCES</div>
    <div class="info-grid">${srcHTML}</div>
  </div>`;
}

function renderPort(d) {
  if (!d.shodan) return resHeader('PORT SCAN · '+d.ip)+`<div class="res-body">${infoCard('STATUS','⚠ '+d.note,'amber')}<div style="margin-top:12px;font-family:var(--mono);font-size:11px;color:var(--t3)">${d.warning}</div></div>`;
  const s = d.shodan;
  const ports = (s.ports||[]).map(p=>`<span style="background:var(--bg2);border:1px solid var(--border);padding:4px 10px;border-radius:var(--r);font-family:var(--mono);font-size:12px;color:var(--cyber)">${p}</span>`).join(' ');
  return resHeader('PORT SCAN · '+d.ip, s.ports.length+' OPEN', s.vulns.length>0?'badge-red':'badge-green', d)+`<div class="res-body">
    <div class="info-grid">
      ${infoCard('OS',s.os||'Unknown')}${infoCard('HOSTNAMES',s.hostnames.join(', ')||'None')}
      ${infoCard('OPEN PORTS',s.ports.length,'blue')}${infoCard('CVEs',s.vulns.length>0?s.vulns.length+' FOUND':'NONE',s.vulns.length>0?'red':'green')}
    </div>
    <div class="sec-title">OPEN PORTS</div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px">${ports}</div>
    ${s.vulns.length?`<div class="sec-title">CVE VULNERABILITIES</div><div style="display:flex;flex-wrap:wrap;gap:6px">${s.vulns.map(v=>`<span style="background:var(--red-d);border:1px solid rgba(255,43,78,.3);padding:3px 10px;border-radius:2px;font-family:var(--mono);font-size:11px;color:var(--red)">${v}</span>`).join('')}</div>`:''}
  </div>`;
}

function renderDarkWeb(d) {
  const rHTML = (d.mockResults||[]).map(r=>`<div class="info-card" style="border-left:3px solid ${r.risk==='CRITICAL'?'var(--red)':'var(--amber)'}">
    <div class="ic-label">${r.risk} · ${r.source} · ${r.date}</div>
    <div class="ic-val">${r.snippet}</div>
  </div>`).join('');
  return resHeader('DARK WEB MONITOR · '+d.query,'DEMO DATA','badge-amber')+`<div class="res-body">
    <div class="info-card" style="margin-bottom:14px;border-left:3px solid var(--amber)">
      <div class="ic-label">⚠ NOTICE</div><div class="ic-val amber" style="font-size:11px">${d.disclaimer}</div>
    </div>
    <div class="info-grid">${rHTML}</div>
    <div style="margin-top:14px;font-family:var(--mono);font-size:10px;color:var(--t3)">
      Real monitoring: Flare.io · Recorded Future · DarkOwl · Intel471
    </div>
  </div>`;
}

function renderSSL(d) {
  if (d.error) return resHeader('SSL · '+d.domain,'ERROR','badge-red')+`<div class="res-body">${infoCard('ERROR',d.error,'red')}<div style="font-family:var(--mono);font-size:11px;color:var(--t3);margin-top:8px">${d.note||''}</div></div>`;
  const c = d.cert||{};
  const expired = d.expired;
  return resHeader('SSL ANALYZER · '+d.domain, expired?'EXPIRED':'VALID', expired?'badge-red':'badge-green', d)+`<div class="res-body">
    <div class="info-grid">
      ${infoCard('DOMAIN',d.domain,'blue')}
      ${infoCard('VALID',expired?'❌ EXPIRED':'✅ VALID',expired?'red':'green')}
      ${infoCard('ISSUER',c.issuer||'Unknown')}
      ${infoCard('SUBJECT',c.subject||'Unknown')}
      ${infoCard('VALID FROM',c.validFrom||'Unknown')}
      ${infoCard('VALID TO',c.validTo||'Unknown',expired?'red':'green')}
      ${infoCard('DAYS REMAINING',c.daysRemaining||'Unknown',expired?'red':c.daysRemaining<30?'amber':'green')}
      ${infoCard('PROTOCOL',c.protocol||'Unknown')}
      ${infoCard('KEY BITS',c.keyBits||'Unknown')}
    </div>
    ${c.sans&&c.sans.length?`<div class="sec-title">SUBJECT ALT NAMES (${c.sans.length})</div><div class="sub-grid">${c.sans.map(s=>`<div class="sub-item">${s}</div>`).join('')}</div>`:''}
  </div>`;
}

function renderNetwork(d) {
  if (d.error) return resHeader('NETWORK · '+d.query,'ERROR','badge-red')+`<div class="res-body">${infoCard('ERROR',d.error,'red')}</div>`;
  return resHeader('NETWORK INTEL · '+d.query,'','',d)+`<div class="res-body">
    <div class="info-grid">
      ${infoCard('QUERY',d.query,'blue')}
      ${infoCard('TYPE',d.type?.toUpperCase()||'Unknown')}
      ${d.asn?infoCard('ASN',d.asn):''}
      ${d.name?infoCard('NAME',d.name):''}
      ${d.country?infoCard('COUNTRY',d.country):''}
      ${d.description?infoCard('DESCRIPTION',d.description):''}
      ${d.org?infoCard('ORGANIZATION',d.org):''}
      ${d.prefixes?infoCard('IP PREFIXES',d.prefixes.length+' blocks'):''}
    </div>
    ${d.prefixes&&d.prefixes.length?`<div class="sec-title">IP PREFIXES</div><div class="sub-grid">${d.prefixes.slice(0,50).map(p=>`<div class="sub-item">${p.prefix||p}</div>`).join('')}</div>`:''}
    ${d.note?`<div style="font-family:var(--mono);font-size:11px;color:var(--t3);margin-top:12px">${d.note}</div>`:''}
  </div>`;
}

// ── ACTIVITY ─────────────────────────────────────────
const toolLabels = { ip:'IP Lookup', whois:'WHOIS', dns:'DNS', subdomain:'Subdomain', email:'Email OSINT', username:'Username Recon', threat:'Threat Intel', port:'Port Scan', darkweb:'Dark Web', ssl:'SSL Analyzer', network:'Network Intel' };

function addActivity(tool, target, data) {
  S.activity.unshift({ tool:toolLabels[tool]||tool, target, team:S.user?.team||'blue', time:new Date() });
  if (S.activity.length > 50) S.activity.pop();
  renderRecentActivity();
  fetch('/api/osint/log', { method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+S.token}, body:JSON.stringify({tool, target, action:'scan'}) }).catch(()=>{});
}

function renderRecentActivity() {
  const el = document.getElementById('recent-list');
  if (!el) return;
  if (!S.activity.length) { el.innerHTML = '<div class="empty-state">No scans yet</div>'; return; }
  el.innerHTML = S.activity.slice(0,15).map(a=>`
    <div class="recent-item">
      <div class="ri-dot ${a.team}"></div>
      <div class="ri-text"><strong>${a.tool}</strong> · ${a.target}</div>
      <div class="ri-time">${timeAgo(a.time)}</div>
    </div>`).join('');
}

function loadRecentActivity() { renderRecentActivity(); }

async function loadActivityPanel() {
  const el = document.getElementById('activity-table-wrap');
  el.innerHTML = '<div class="empty-state">Loading...</div>';
  try {
    const res = await fetch('/api/osint/activity', { headers:{'Authorization':'Bearer '+S.token} });
    const data = await res.json();
    if (!data.length) { el.innerHTML = '<div class="empty-state">No activity yet</div>'; return; }
    el.innerHTML = `<table>
      <thead><tr><th>USER</th><th>TEAM</th><th>TOOL</th><th>TARGET</th><th>TIME</th></tr></thead>
      <tbody>${data.map(a=>`<tr>
        <td style="color:var(--t0)">${a.user||'—'}</td>
        <td><span class="team-pill ${a.team||'blue'}">${(a.team||'—').toUpperCase()}</span></td>
        <td>${a.tool||a.action||'—'}</td>
        <td style="color:var(--cyber);font-family:var(--mono)">${a.target||'—'}</td>
        <td style="font-family:var(--mono);font-size:11px">${new Date(a.timestamp).toLocaleString()}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch(e) { el.innerHTML = '<div class="empty-state">Failed to load</div>'; }
}

async function loadAdminPanel() {
  try {
    const res = await fetch('/api/admin/stats', { headers:{'Authorization':'Bearer '+S.token} });
    if (!res.ok) return;
    const d = await res.json();
    document.getElementById('a-total').textContent = d.totalUsers;
    document.getElementById('a-active').textContent = d.activeUsers;
    document.getElementById('a-red').textContent = d.redTeamUsers;
    document.getElementById('a-blue').textContent = d.blueTeamUsers;
    const el = document.getElementById('admin-activity');
    if (!d.recentActivity.length) { el.innerHTML = '<div class="empty-state">No activity</div>'; return; }
    el.innerHTML = d.recentActivity.map(a=>`
      <div class="recent-item">
        <div class="ri-dot ${a.team||'blue'}"></div>
        <div class="ri-text"><strong>${a.user}</strong> · ${a.tool||a.action} · ${a.target||''}</div>
        <div class="ri-time">${new Date(a.timestamp).toLocaleTimeString()}</div>
      </div>`).join('');
  } catch(e) {}
}

async function loadUsersPanel() {
  const el = document.getElementById('users-table-wrap');
  el.innerHTML = '<div class="empty-state">Loading...</div>';
  try {
    const res = await fetch('/api/admin/users', { headers:{'Authorization':'Bearer '+S.token} });
    if (!res.ok) { el.innerHTML = '<div class="empty-state">Access denied</div>'; return; }
    const users = await res.json();
    el.innerHTML = `<table>
      <thead><tr><th>NAME</th><th>USERNAME</th><th>EMAIL</th><th>PHONE</th><th>ROLE</th><th>TEAM</th><th>PROVIDER</th><th>JOINED</th><th>STATUS</th><th>ACTIONS</th></tr></thead>
      <tbody>${users.map(u=>`<tr>
        <td style="color:var(--t0)">${u.name}</td>
        <td style="font-family:var(--mono)">${u.username}</td>
        <td style="font-family:var(--mono);font-size:11px">${u.email}</td>
        <td style="font-family:var(--mono);font-size:11px">${u.phone||'—'}</td>
        <td><span class="role-pill ${u.role}">${u.role.toUpperCase()}</span></td>
        <td><span class="team-pill ${u.team}">${u.team.toUpperCase()}</span></td>
        <td style="font-family:var(--mono);font-size:11px">${u.provider||'local'}</td>
        <td style="font-family:var(--mono);font-size:11px">${new Date(u.createdAt).toLocaleDateString()}</td>
        <td style="color:${u.active?'var(--green)':'var(--red)'};font-family:var(--mono);font-size:11px">${u.active?'ACTIVE':'DISABLED'}</td>
        <td>${u.role!=='admin'?`<button class="action-btn del" onclick="deleteUser('${u.id}')">DELETE</button>`:'—'}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch(e) { el.innerHTML = '<div class="empty-state">Failed to load</div>'; }
}

async function deleteUser(id) {
  if (!confirm('Delete this user?')) return;
  try {
    const res = await fetch('/api/auth/users/'+id, { method:'DELETE', headers:{'Authorization':'Bearer '+S.token} });
    if (res.ok) { showToast('User deleted'); loadUsersPanel(); }
  } catch(e) {}
}

// ── STATS ─────────────────────────────────────────────
function updateStats() {
  document.getElementById('s-total').textContent = S.stats.total;
  document.getElementById('s-ips').textContent = S.stats.ips;
  document.getElementById('s-threats').textContent = S.stats.threats;
  document.getElementById('s-clean').textContent = S.stats.clean;
}

// ── UTILS ──────────────────────────────────────────────
function timeAgo(d) {
  const s = Math.floor((new Date()-d)/1000);
  if (s<60) return s+'s ago'; if (s<3600) return Math.floor(s/60)+'m ago'; return Math.floor(s/3600)+'h ago';
}

function exportJSON(encoded, name) {
  try {
    const data = JSON.parse(atob(encoded));
    const blob = new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
    const a = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=name+'.json'; a.click();
    showToast('Exported: '+name+'.json');
  } catch(e) { showToast('Export failed','error'); }
}

function showToast(msg, type='success') {
  const t = document.createElement('div');
  t.style.cssText = `position:fixed;bottom:24px;right:24px;background:var(--bg2);border:1px solid ${type==='error'?'rgba(255,43,78,.4)':'rgba(0,255,231,.3)'};color:${type==='error'?'var(--red)':'var(--cyber)'};font-family:var(--mono);font-size:12px;padding:10px 18px;border-radius:4px;z-index:9999;letter-spacing:1px;animation:fadeUp .2s ease`;
  t.textContent = (type==='error'?'✗ ':'✓ ')+msg;
  document.body.appendChild(t); setTimeout(()=>t.remove(),3000);
}

function initClock() {
  const el = document.getElementById('topbar-clock');
  if (!el) return;
  setInterval(()=>{ el.textContent = new Date().toLocaleTimeString('en-US',{hour12:false})+' UTC'; },1000);
}

function initMatrix() {
  const canvas = document.getElementById('matrix-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const resize = () => { canvas.width=innerWidth; canvas.height=innerHeight; };
  resize(); window.addEventListener('resize',resize);
  const chars = 'アイウエオ0123456789ABCDEF@#$'; const fs = 14;
  let cols = Math.floor(canvas.width/fs);
  const drops = Array(cols).fill(1);
  setInterval(()=>{
    cols = Math.floor(canvas.width/fs);
    ctx.fillStyle='rgba(6,8,16,.05)'; ctx.fillRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle='#00b4ff'; ctx.font=fs+'px monospace';
    for (let i=0;i<drops.length;i++){
      ctx.fillText(chars[Math.floor(Math.random()*chars.length)],i*fs,drops[i]*fs);
      if (drops[i]*fs>canvas.height&&Math.random()>.975) drops[i]=0;
      drops[i]++;
    }
  },50);
}
