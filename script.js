/**
 * CyberScan – script.js
 * Handles: auth, section navigation, scan orchestration, results rendering
 */

// ── State ─────────────────────────────────────────────────────────
let currentSection = 'login';
let scanResults    = null;

// ── Section Map ───────────────────────────────────────────────────
const SECTIONS = {
  login:     'sec-login',
  reg:       'sec-reg',
  dashboard: 'sec-dashboard',
  scanning:  'sec-scanning',
  results:   'sec-results',
  logs:      'sec-logs',
  risk:      'sec-risk',
};

// ── Section Navigation ─────────────────────────────────────────────
function showSection(name) {
  const el = document.getElementById(SECTIONS[name]);
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth' });
  currentSection = name;
}

// ── On Load ────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  // Check if already logged in
  try {
    const res  = await fetch('/api/session');
    const data = await res.json();
    if (data.logged_in) setLoggedIn(data.name);
  } catch (_) {}
});

// ── Auth Helpers ───────────────────────────────────────────────────
function setLoggedIn(name) {
  document.getElementById('nav-user').textContent  = `◉  ${name}`;
  document.getElementById('nav-user').classList.remove('hidden');
  document.getElementById('nav-logout').classList.remove('hidden');
}

function setLoggedOut() {
  document.getElementById('nav-user').classList.add('hidden');
  document.getElementById('nav-logout').classList.add('hidden');
}

// ── Login ──────────────────────────────────────────────────────────
async function doLogin() {
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl    = document.getElementById('login-error');

  errEl.classList.add('hidden');
  if (!email || !password) { showError(errEl, 'Please fill in all fields.'); return; }

  try {
    const res  = await postJSON('/api/login', { email, password });
    const data = await res.json();

    if (data.success) {
      setLoggedIn(data.name);
      showSection('dashboard');
    } else {
      showError(errEl, data.message || 'Login failed.');
    }
  } catch (e) {
    showError(errEl, 'Connection error. Please try again.');
  }
}

// ── Register ───────────────────────────────────────────────────────
async function doRegister() {
  const name     = document.getElementById('reg-name').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const msgEl    = document.getElementById('reg-msg');

  msgEl.className = 'hidden';
  if (!name || !email || !password) { showMsg(msgEl, 'error', 'All fields are required.'); return; }
  if (password.length < 6) { showMsg(msgEl, 'error', 'Password must be at least 6 characters.'); return; }

  try {
    const res  = await postJSON('/api/register', { name, email, password });
    const data = await res.json();

    if (data.success) {
      showMsg(msgEl, 'success', 'Account created! Please sign in.');
      setTimeout(() => showSection('login'), 1500);
    } else {
      showMsg(msgEl, 'error', data.message || 'Registration failed.');
    }
  } catch (e) {
    showMsg(msgEl, 'error', 'Connection error. Please try again.');
  }
}

// ── Logout ─────────────────────────────────────────────────────────
async function logout() {
  await fetch('/api/logout', { method: 'POST' });
  setLoggedOut();
  showSection('login');
}

// ── IP Preset ─────────────────────────────────────────────────────
function setIP(ip) {
  document.getElementById('ip-input').value = ip;
  document.getElementById('ip-input').focus();
}

// ── Scan Orchestration ─────────────────────────────────────────────
async function startScan() {
  const ip    = document.getElementById('ip-input').value.trim();
  const errEl = document.getElementById('scan-error');
  errEl.classList.add('hidden');

  if (!ip) { showError(errEl, 'Please enter a target IP address.'); return; }
  if (!isValidIP(ip)) { showError(errEl, 'Please enter a valid IP address.'); return; }

  // Go to scanning section
  showSection('scanning');
  animateScan();

  try {
    const res  = await postJSON('/api/scan', { ip });
    const data = await res.json();

    if (data.success) {
      scanResults = data;
      renderResults(data);
      renderLogs(data.logs);
      renderRisk(data.analysis.risk, data.analysis, data.logs);
      // Wait a moment then show results
      setTimeout(() => showSection('results'), 500);
    } else {
      showSection('dashboard');
      showError(errEl, data.message || 'Scan failed.');
    }
  } catch (e) {
    showSection('dashboard');
    showError(errEl, 'Scan failed. Is the Flask server running?');
  }
}

// ── Scan Animation ────────────────────────────────────────────────
function animateScan() {
  const steps = [
    'Initializing scan engine...',
    'Sending SYN probes to target...',
    'Enumerating open ports...',
    'Detecting service versions...',
    'Mapping CVE database...',
    'Matching MITRE ATT&CK techniques...',
    'Generating attack paths...',
    'Analyzing log patterns...',
    'Computing risk score...',
    'Finalizing report...',
  ];

  const bar   = document.getElementById('scan-bar');
  const text  = document.getElementById('scan-status-text');
  const log   = document.getElementById('scan-log');
  log.innerHTML = '';
  let idx = 0;

  const interval = setInterval(() => {
    if (idx >= steps.length) { clearInterval(interval); return; }
    const pct  = Math.round(((idx + 1) / steps.length) * 100);
    bar.style.width = pct + '%';
    text.textContent = steps[idx];
    const line = document.createElement('div');
    line.className = 'scan-log-line';
    line.textContent = `[${String(idx + 1).padStart(2, '0')}] ${steps[idx]}`;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
    idx++;
  }, 600);
}

// ── Render Results ─────────────────────────────────────────────────
function renderResults(data) {
  const grid  = document.getElementById('results-grid');
  const label = document.getElementById('results-ip-label');
  label.textContent = `Target: ${data.ip}  ·  ${data.timestamp}`;
  grid.innerHTML = '';

  const { scan, analysis } = data;

  // Card 1 – Open Ports
  grid.appendChild(makeCard({
    icon: '🔌', iconClass: 'blue',
    title: 'Open Ports',
    body: scan.open_ports.length
      ? `<div style="display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.5rem">
           ${scan.open_ports.map(p => `<span class="port-chip">${p}</span>`).join('')}
         </div>`
      : '<span style="color:var(--success)">No open ports detected</span>',
    delay: 0
  }));

  // Card 2 – Services
  const svcRows = scan.services.map(s =>
    `<div style="display:flex;justify-content:space-between;padding:.35rem 0;border-bottom:1px solid var(--border);font-size:.83rem">
       <span class="mono" style="color:var(--primary)">${s.port}</span>
       <span>${s.product || s.service}</span>
       <span style="color:var(--muted)">${s.version || '—'}</span>
     </div>`
  ).join('');
  grid.appendChild(makeCard({ icon: '⚙️', iconClass: 'purple', title: 'Services Detected', body: svcRows || 'None', delay: 1 }));

  // Card 3 – Vulnerabilities
  const vulnRows = analysis.vulnerabilities.map(v =>
    `<div class="vuln-item">
       <span class="sev-badge sev-${v.severity}">${v.severity}</span>
       <div>
         <div style="font-size:.85rem;font-weight:600">${v.cve}</div>
         <div style="font-size:.8rem;color:var(--muted)">${v.desc}</div>
       </div>
     </div>`
  ).join('');
  grid.appendChild(makeCard({ icon: '🛡️', iconClass: 'red', title: 'Vulnerabilities', body: vulnRows || '<span style="color:var(--success)">No known CVEs mapped</span>', delay: 2 }));

  // Card 4 – MITRE ATT&CK
  const mitreRows = analysis.mitre_techniques.map(t =>
    `<div style="padding:.4rem 0;border-bottom:1px solid var(--border)">
       <span class="mitre-tag">${t.id}</span>
       <span style="font-size:.82rem;margin-left:.4rem">${t.name}</span>
       <div style="font-size:.75rem;color:var(--muted);margin-top:.2rem;padding-left:.2rem">${t.tactic}</div>
     </div>`
  ).join('');
  grid.appendChild(makeCard({ icon: '🎯', iconClass: 'orange', title: 'MITRE ATT&CK', body: mitreRows || 'No techniques identified', delay: 3 }));

  // Card 5 – Attack Path (wide)
  const pathRows = analysis.attack_path.map(s =>
    `<div class="attack-step">
       <span class="step-num">${s.step}</span>
       <div>
         <div class="step-phase">${s.phase}</div>
         <div class="step-action">${s.action}</div>
         <div class="step-tech">${s.technique}</div>
       </div>
     </div>`
  ).join('');
  const pathCard = makeCard({ icon: '⚡', iconClass: 'cyan', title: 'Simulated Attack Path', body: pathRows || 'No attack path generated', delay: 4 });
  pathCard.style.gridColumn = 'span 2';
  grid.appendChild(pathCard);

  // Card 6 – Risk Badge
  const risk = analysis.risk;
  const riskCard = makeCard({
    icon: riskIcon(risk.level), iconClass: riskIconClass(risk.level),
    title: 'Risk Level',
    body: `<div style="font-family:'Space Mono',monospace;font-size:2rem;font-weight:700;color:${riskColor(risk.level)}">${risk.level}</div>
           <div style="font-size:.85rem;color:var(--muted);margin-top:.5rem">Risk Score: ${risk.score}/100</div>`,
    delay: 5
  });
  grid.appendChild(riskCard);
}

// ── Render Logs ────────────────────────────────────────────────────
function renderLogs(logs) {
  const body = document.getElementById('logs-body');
  const { summary, events } = logs;

  body.innerHTML = `
    <div class="logs-summary">
      <div class="log-stat-card">
        <div class="log-stat-n n-red">${summary.critical_events}</div>
        <div class="log-stat-l">Critical Events</div>
      </div>
      <div class="log-stat-card">
        <div class="log-stat-n n-orange">${summary.warning_events}</div>
        <div class="log-stat-l">Warnings</div>
      </div>
      <div class="log-stat-card">
        <div class="log-stat-n n-green">${summary.normal_events}</div>
        <div class="log-stat-l">Normal Events</div>
      </div>
      <div class="log-stat-card">
        <div class="log-stat-n n-red">${summary.failed_logins}</div>
        <div class="log-stat-l">Failed Logins</div>
      </div>
      <div class="log-stat-card">
        <div class="log-stat-n" style="color:var(--primary)">${summary.suspicious_ips.length}</div>
        <div class="log-stat-l">Suspicious IPs</div>
      </div>
    </div>
    <div class="log-stream" id="log-stream"></div>
  `;

  const stream = document.getElementById('log-stream');
  events.forEach((ev, i) => {
    const parts  = ev.line.split(' ');
    const ts     = parts.slice(0,2).join(' ');
    const sev    = ev.severity.toUpperCase();
    const txt    = parts.slice(3).join(' ');
    const line   = document.createElement('div');
    line.className = `log-line ${ev.severity}`;
    line.style.animationDelay = `${i * 0.03}s`;
    line.innerHTML = `<span class="log-ts">${ts || '—'}</span><span class="log-sev">${sev}</span><span class="log-txt">${txt || ev.line}</span>`;
    stream.appendChild(line);
  });
}

// ── Render Risk ────────────────────────────────────────────────────
function renderRisk(risk, analysis, logs) {
  const wrap = document.getElementById('risk-wrap');
  const lvl  = (risk.level || 'Low').toLowerCase();

  const tips = buildTips(analysis, logs);

  wrap.innerHTML = `
    <div class="badge">Final Assessment</div>
    <h2 style="font-family:'Space Mono',monospace;font-size:2rem;margin:.5rem 0">Risk Assessment</h2>
    <p style="color:var(--muted);margin-bottom:1.5rem">Based on surface scan, CVE mapping & log analysis</p>
    <div class="risk-meter ${lvl}">
      <div class="risk-level-text">${risk.level}</div>
      <div class="risk-score">Score: ${risk.score}/100</div>
    </div>
    <p class="risk-desc">${risk.description || ''}</p>
    <div class="risk-bar-wrap">
      <div class="risk-bar-label">Risk Score</div>
      <div class="risk-bar-track"><div class="risk-bar-fill ${lvl}" id="risk-fill"></div></div>
    </div>
    <div class="risk-tips">
      <h4>🔐 Remediation Recommendations</h4>
      ${tips.map(t => `<div class="tip"><span class="tip-icon">→</span><span>${t}</span></div>`).join('')}
    </div>
    <div class="risk-actions">
      <button class="btn-ghost" onclick="showSection('logs')">← Log Analysis</button>
      <button class="btn-primary" onclick="showSection('dashboard')">Run Another Scan</button>
    </div>
  `;

  // Animate bar
  setTimeout(() => {
    const fill = document.getElementById('risk-fill');
    if (fill) fill.style.width = risk.score + '%';
  }, 400);
}

function buildTips(analysis, logs) {
  const tips = [];
  const ports = (analysis.vulnerabilities || []).map(v => v.port);

  if (ports.includes(23)) tips.push('Disable Telnet immediately — use SSH with key-based auth instead.');
  if (ports.includes(445) || ports.includes(139)) tips.push('Patch SMB (MS17-010/EternalBlue). Restrict port 445 at the firewall.');
  if (ports.includes(3389)) tips.push('Enable Network Level Authentication on RDP. Consider VPN-only access.');
  if (ports.includes(3306)) tips.push('Restrict MySQL to localhost only. Rotate database credentials.');
  if (ports.includes(21)) tips.push('Disable anonymous FTP. Switch to SFTP/FTPS.');
  if (ports.includes(80) || ports.includes(8080)) tips.push('Update web server software. Enable WAF and disable directory listing.');
  if (logs.summary.failed_logins > 3) tips.push('Implement account lockout policy after 5 failed login attempts.');
  if (logs.summary.suspicious_ips.length > 0) tips.push(`Block suspicious IPs: ${logs.summary.suspicious_ips.join(', ')}`);
  if (tips.length === 0) tips.push('Continue monitoring. Regularly update all services and apply security patches.');

  return tips;
}

// ── Card Builder ───────────────────────────────────────────────────
function makeCard({ icon, iconClass, title, body, delay }) {
  const card = document.createElement('div');
  card.className = 'result-card';
  card.style.animationDelay = `${delay * 0.1}s`;
  card.innerHTML = `
    <div class="card-icon ${iconClass}">${icon}</div>
    <div class="card-title">${title}</div>
    <div class="card-body">${body}</div>
  `;
  return card;
}

// ── Utility ────────────────────────────────────────────────────────
function postJSON(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
}

function showError(el, msg) {
  el.textContent = msg;
  el.className = 'msg-error';
}

function showMsg(el, type, msg) {
  el.textContent = msg;
  el.className   = type === 'error' ? 'msg-error' : 'msg-success';
}

function isValidIP(ip) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6  = /^[0-9a-fA-F:]+$/;
  return ipv4.test(ip) || ipv6.test(ip) || ip === 'localhost';
}

function riskColor(level) {
  return { Critical: '#dc2626', High: '#d97706', Medium: '#ca8a04', Low: '#059669' }[level] || '#059669';
}

function riskIcon(level) {
  return { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🟢' }[level] || '🟢';
}

function riskIconClass(level) {
  return { Critical: 'red', High: 'orange', Medium: 'orange', Low: 'green' }[level] || 'green';
}

// ── Keyboard shortcut: Enter in login/reg/scan forms ──────────────
document.addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  if (currentSection === 'login')     doLogin();
  else if (currentSection === 'reg')  doRegister();
  else if (currentSection === 'dashboard') startScan();
});
