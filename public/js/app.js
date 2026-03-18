'use strict';

// ─── State ────────────────────────────────────────────────────
let ws = null;
let findings = [];
let openPorts = [];
let scanTarget = '';
let filteredFindings = [];
let activeFilter = 'all';
const counts = { critical:0, high:0, medium:0, low:0, info:0 };

// ─── Clock ────────────────────────────────────────────────────
function tickClock() {
  const n = new Date();
  document.getElementById('clock').textContent =
    [n.getHours(),n.getMinutes(),n.getSeconds()].map(v=>String(v).padStart(2,'0')).join(':');
}
setInterval(tickClock, 1000); tickClock();

// ─── Particles ───────────────────────────────────────────────
(function() {
  const canvas = document.getElementById('particles');
  const ctx = canvas.getContext('2d');
  let pts = [];
  function resize() { canvas.width=innerWidth; canvas.height=innerHeight; }
  function spawn(n) {
    for (let i=0;i<n;i++) pts.push({
      x:Math.random()*innerWidth, y:Math.random()*innerHeight,
      vx:(Math.random()-.5)*.25, vy:(Math.random()-.5)*.25,
      r:Math.random()*1.5+.3, a:Math.random()*.35+.05,
      h:Math.random()<.7?195:155
    });
  }
  function draw() {
    requestAnimationFrame(draw);
    ctx.clearRect(0,0,canvas.width,canvas.height);
    for(const p of pts){
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<0)p.x=canvas.width; if(p.x>canvas.width)p.x=0;
      if(p.y<0)p.y=canvas.height; if(p.y>canvas.height)p.y=0;
      ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle=`hsla(${p.h},100%,60%,${p.a})`;ctx.fill();
    }
  }
  window.addEventListener('resize',resize);
  resize(); spawn(50); draw();
})();

// ─── WebSocket connection ─────────────────────────────────────
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}`);

  ws.onopen = () => {
    setWSStatus(true);
    document.getElementById('scanBtn').disabled = false;
  };

  ws.onclose = () => {
    setWSStatus(false);
    document.getElementById('scanBtn').disabled = true;
    setTimeout(connectWS, 3000); // auto-reconnect
  };

  ws.onerror = () => setWSStatus(false);

  ws.onmessage = (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    handleMessage(msg);
  };
}

function setWSStatus(online) {
  const el = document.getElementById('wsStatus');
  el.className = 'ws-status ' + (online ? 'connected' : 'disconnected');
  el.querySelector('.ws-label').textContent = online ? 'ONLINE' : 'OFFLINE';
}

// ─── Message handler ──────────────────────────────────────────
function handleMessage(msg) {
  switch (msg.type) {
    case 'log':      addLog(msg.msg, msg.level);      break;
    case 'progress': updateProgress(msg.pct, msg.label); break;
    case 'finding':  addFinding(msg);                  break;
    case 'done':     onScanDone(msg);                  break;
  }
}

// ─── Terminal log ─────────────────────────────────────────────
function addLog(msg, level = 'info') {
  const t = document.getElementById('terminal');
  if (!t) return;
  const d = document.createElement('div');
  d.className = 'tline ' + level;
  d.textContent = msg;
  t.appendChild(d);
  while (t.children.length > 600) t.removeChild(t.firstChild);
  t.scrollTop = t.scrollHeight;
}

// ─── Progress ────────────────────────────────────────────────
function updateProgress(pct, label) {
  document.getElementById('progFill').style.width  = pct + '%';
  document.getElementById('progLabel').textContent = label;
  document.getElementById('progPct').textContent   = pct + '%';
}

// ─── Add finding ──────────────────────────────────────────────
function addFinding(f) {
  findings.push(f);
  counts[f.severity] = (counts[f.severity] || 0) + 1;
  updateStats();
  renderVulnList();
}

function updateStats() {
  animCount('s-critical', counts.critical);
  animCount('s-high',     counts.high);
  animCount('s-medium',   counts.medium);
  animCount('s-low',      counts.low);
  animCount('s-info',     counts.info);
  animCount('s-ports',    openPorts.length);
}

function animCount(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ─── Scan complete ────────────────────────────────────────────
function onScanDone(msg) {
  openPorts = msg.open_ports || [];
  updateStats();
  animCount('s-ports', openPorts.length);
  renderPortsTable();
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('stopBtn').disabled = true;
  addLog(`Scan complete in ${msg.elapsed}s — ${msg.total_findings} findings, ${openPorts.length} open ports`, 'ok');
}

// ─── Vuln list ────────────────────────────────────────────────
function renderVulnList() {
  const list = document.getElementById('vulnList');
  if (!list) return;

  let items = findings.filter(f => activeFilter === 'all' || f.severity === activeFilter);
  items.sort((a,b) => severityOrder(a.severity) - severityOrder(b.severity));
  filteredFindings = items;

  list.innerHTML = items.length ? items.map((f,i) => `
    <div class="vcard sev-${f.severity}${i===0?' active':''}" onclick="showDetail(this,${i})">
      <div class="vcard-top">
        <div class="vcard-name">${esc(f.name)}</div>
        <div class="badge ${f.severity}">${f.severity.toUpperCase()}</div>
      </div>
      <div class="vcard-desc">${esc(String(f.detail||'').slice(0,110))}...</div>
      <div class="vcard-meta">
        ${f.cvss > 0 ? `<span>⚡ CVSS ${f.cvss}</span>` : ''}
        <span>📁 ${esc(f.category)}</span>
        <span>🔗 ${esc(String(f.endpoint).slice(0,40))}</span>
      </div>
    </div>
  `).join('') : `<div style="padding:40px;text-align:center;color:var(--green);font-family:var(--mono);font-size:13px">✓ No findings for this filter</div>`;

  // Auto-show first finding in detail
  if (items.length > 0) showDetail(null, 0, true);
}

function showDetail(el, idx, silent = false) {
  if (!silent) {
    document.querySelectorAll('.vcard').forEach(c => c.classList.remove('active'));
    if (el) el.classList.add('active');
    else {
      const cards = document.querySelectorAll('.vcard');
      if (cards[idx]) cards[idx].classList.add('active');
    }
  }

  const f = filteredFindings[idx];
  if (!f) return;

  const cvssColor = f.cvss >= 9 ? 'var(--crit)' : f.cvss >= 7 ? 'var(--danger)' : f.cvss >= 4 ? 'var(--warn)' : 'var(--low)';

  document.getElementById('detailPane').innerHTML = `
    <div class="d-head">// FINDING DETAIL</div>
    <div class="d-block">
      <label>NAME</label>
      <p style="font-weight:700;font-size:15px">${esc(f.name)}</p>
    </div>
    ${f.cvss > 0 ? `
    <div class="d-block">
      <label>CVSS SCORE</label>
      <div class="cvss-row">
        <div class="cvss-track"><div class="cvss-fill" style="width:${f.cvss*10}%;background:${cvssColor}"></div></div>
        <div class="cvss-num" style="color:${cvssColor}">${f.cvss}</div>
      </div>
    </div>` : ''}
    <div class="d-block">
      <label>SEVERITY</label>
      <span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>
    </div>
    <div class="d-block">
      <label>CATEGORY</label>
      <p>${esc(f.category)}</p>
    </div>
    <div class="d-block">
      <label>ENDPOINT</label>
      <p style="font-family:var(--mono);font-size:12px;color:var(--accent);word-break:break-all">${esc(f.endpoint)}</p>
    </div>
    <div class="d-block">
      <label>DETAIL / EVIDENCE</label>
      <div class="code-block">${esc(f.detail)}</div>
    </div>
    <div class="d-block">
      <label>REMEDIATION</label>
      <ul class="remedy-list"><li>${esc(f.remediation)}</li></ul>
    </div>
  `;
}

// ─── Ports table ──────────────────────────────────────────────
const RISKY = new Set([23,3306,5432,6379,27017,9200,11211,1433,1521,5900,5984,28017]);

function renderPortsTable() {
  const section = document.getElementById('portsSection');
  const table   = document.getElementById('portsTable');
  if (!openPorts.length) { section.style.display='none'; return; }
  section.style.display = 'block';
  table.innerHTML = `
    <tr><th>PORT</th><th>SERVICE</th><th>BANNER</th><th>RISK</th></tr>
    ${openPorts.map(p => `
      <tr>
        <td class="port-num">${p.port}</td>
        <td class="port-svc ${RISKY.has(p.port)?'port-risky':''}">${esc(p.service)}</td>
        <td style="font-size:11px;color:var(--dim)">${esc(p.banner||'—').slice(0,80)}</td>
        <td>${RISKY.has(p.port) ? '<span style="color:var(--danger);font-family:var(--mono);font-size:10px">⚠ RISKY</span>' : '<span style="color:var(--dim);font-family:var(--mono);font-size:10px">NORMAL</span>'}</td>
      </tr>
    `).join('')}
  `;
}

// ─── Start scan ───────────────────────────────────────────────
function startScan() {
  const target = document.getElementById('targetInput').value.trim();
  if (!target) {
    const w = document.getElementById('targetWrap');
    w.style.borderColor='var(--danger)'; w.style.boxShadow='0 0 16px rgba(255,59,92,.3)';
    setTimeout(()=>{ w.style.borderColor=''; w.style.boxShadow=''; }, 1200);
    return;
  }
  if (!ws || ws.readyState !== 1) { alert('WebSocket not connected. Please wait...'); return; }

  scanTarget = target;
  findings = [];
  openPorts = [];
  filteredFindings = [];
  counts.critical = counts.high = counts.medium = counts.low = counts.info = 0;

  // Reset UI
  document.getElementById('emptyState').style.display    = 'none';
  document.getElementById('progressCard').style.display  = 'block';
  document.getElementById('statsRow').style.display      = 'grid';
  document.getElementById('resultsSection').style.display = 'block';
  document.getElementById('portsSection').style.display  = 'none';
  document.getElementById('terminal').innerHTML = '';
  document.getElementById('vulnList').innerHTML = '';
  document.getElementById('detailPane').innerHTML = '<div class="detail-empty"><div style="font-size:48px;opacity:.2;margin-bottom:12px">🔍</div><p>Scan in progress...</p></div>';
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('stopBtn').disabled = false;
  updateProgress(0, 'Initialising...');
  updateStats();

  const modules = [...document.querySelectorAll('.mod-chip.active')].map(c => c.dataset.mod);
  ws.send(JSON.stringify({ type:'scan', target, modules }));
}

function stopScan() {
  if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type:'cancel' }));
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('stopBtn').disabled = true;
}

// ─── Presets ──────────────────────────────────────────────────
const PRESETS = {
  full:    ['dns','ports','http','headers','ssl','paths','banners'],
  quick:   ['ports','headers','ssl'],
  web:     ['http','headers','ssl','paths'],
  network: ['dns','ports','banners'],
};

function setPreset(name) {
  const active = new Set(PRESETS[name] || PRESETS.full);
  document.querySelectorAll('.mod-chip').forEach(c => {
    c.classList.toggle('active', active.has(c.dataset.mod));
  });
}

// ─── Filter ───────────────────────────────────────────────────
document.querySelectorAll('.fchip').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.fchip').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.f;
    renderVulnList();
  });
});

// ─── Stat box click to filter ─────────────────────────────────
document.querySelectorAll('.stat-box').forEach(box => {
  box.addEventListener('click', () => {
    const cls = box.classList[1]; // critical / high / medium / low / info / ports
    if (['critical','high','medium','low','info'].includes(cls)) {
      document.querySelectorAll('.fchip').forEach(c=>c.classList.remove('active'));
      document.querySelector(`.fchip[data-f="${cls}"]`)?.classList.add('active');
      activeFilter = cls;
      renderVulnList();
    }
  });
});

// ─── Export ───────────────────────────────────────────────────
document.getElementById('exportBtn')?.addEventListener('click', () => {
  document.getElementById('modalBg').style.display = 'flex';
});

function closeModal() {
  document.getElementById('modalBg').style.display = 'none';
}

function exportReport(fmt) {
  closeModal();
  const now    = new Date().toLocaleString();
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => counts[f.severity]++);

  if (fmt === 'txt') {
    const lines = [
      '═'.repeat(70),
      '  REALVULNSCAN — LIVE SECURITY SCAN REPORT',
      '═'.repeat(70),
      `  Target    : ${scanTarget}`,
      `  Date      : ${now}`,
      `  Findings  : ${findings.length}`,
      '─'.repeat(70),
      `  Critical: ${counts.critical}  High: ${counts.high}  Medium: ${counts.medium}  Low: ${counts.low}  Info: ${counts.info}`,
      '─'.repeat(70),
      `  Open Ports: ${openPorts.map(p=>p.port+'/'+p.service).join(', ') || 'None'}`,
      '═'.repeat(70),
      '',
      ...findings.map((f,i) => [
        `[${String(i+1).padStart(2,'0')}] ${f.name}`,
        `     Severity : ${f.severity.toUpperCase()}`,
        `     CVSS     : ${f.cvss}`,
        `     Category : ${f.category}`,
        `     Endpoint : ${f.endpoint}`,
        `     Detail   : ${f.detail}`,
        `     Fix      : ${f.remediation}`,
        '',
      ].join('\n')),
      '═'.repeat(70),
    ];
    download(lines.join('\n'), 'vulnscan-report.txt', 'text/plain');
  }

  if (fmt === 'json') {
    download(JSON.stringify({ target:scanTarget, date:now, findings, openPorts }, null, 2), 'vulnscan-report.json', 'application/json');
  }

  if (fmt === 'csv') {
    const rows = [['ID','Name','Severity','CVSS','Category','Endpoint','Detail']];
    findings.forEach((f,i) => rows.push([i+1, `"${f.name}"`, f.severity, f.cvss, f.category, `"${f.endpoint}"`, `"${String(f.detail).replace(/"/g,'""')}"`]));
    download(rows.map(r=>r.join(',')).join('\n'), 'vulnscan-report.csv', 'text/csv');
  }

  if (fmt === 'html') {
    const scColor = c => c>=9?'#ff1744':c>=7?'#ff3b5c':c>=4?'#ffb700':'#64ffda';
    const body = findings.map((f,i) => `
      <div style="border-left:4px solid ${scColor(f.cvss)};padding:14px 20px;margin-bottom:16px;background:#0a1520">
        <div style="display:flex;justify-content:space-between;margin-bottom:8px">
          <strong style="color:#c8dce8">${i+1}. ${f.name}</strong>
          <span style="font-size:11px;font-family:monospace;color:${scColor(f.cvss)};border:1px solid;padding:2px 8px">${f.severity.toUpperCase()}</span>
        </div>
        <p style="font-size:12px;color:#5f8fa8;margin-bottom:8px">${f.detail}</p>
        <p style="font-size:12px;color:#64ffda"><strong>Fix:</strong> ${f.remediation}</p>
      </div>`).join('');
    download(`<!DOCTYPE html><html><head><title>VulnScan Report</title>
      <style>body{background:#050a0e;color:#c8dce8;font-family:sans-serif;padding:40px}h1{color:#00e5ff;font-size:22px;margin-bottom:4px}.meta{font-family:monospace;font-size:12px;color:#5f8fa8;margin-bottom:24px}</style>
      </head><body><h1>REALVULNSCAN REPORT</h1><div class="meta">Target: ${scanTarget} | Date: ${now} | Findings: ${findings.length}</div>${body}</body></html>`,
      'vulnscan-report.html', 'text/html');
  }
}

function download(content, filename, mime) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], {type:mime}));
  a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
}

// ─── Utilities ────────────────────────────────────────────────
function severityOrder(s) { return {critical:0,high:1,medium:2,low:3,info:4}[s]??5; }
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── Keyboard ────────────────────────────────────────────────
document.getElementById('targetInput')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});
document.getElementById('scanBtn')?.addEventListener('click', startScan);
document.getElementById('stopBtn')?.addEventListener('click', stopScan);

// ─── Module chips ─────────────────────────────────────────────
document.querySelectorAll('.mod-chip').forEach(c => {
  c.addEventListener('click', () => c.classList.toggle('active'));
});

// ─── Boot ─────────────────────────────────────────────────────
connectWS();
