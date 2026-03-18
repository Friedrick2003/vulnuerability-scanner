'use strict';

const express   = require('express');
const http      = require('http');
const https     = require('https');
const net       = require('net');
const tls       = require('tls');
const dns       = require('dns').promises;
const { WebSocketServer } = require('ws');
const path      = require('path');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// ─── WebSocket handler ──────────────────────────────────────────
wss.on('connection', (ws) => {
  let cancelled = false;

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'cancel') { cancelled = true; return; }
    if (msg.type === 'scan')   { cancelled = false; runScan(msg, ws, () => cancelled); }
  });

  ws.on('close', () => { cancelled = true; });
});

// ─── Send helpers ───────────────────────────────────────────────
function send(ws, type, data) {
  if (ws.readyState === 1) ws.send(JSON.stringify({ type, ...data }));
}
function log(ws, msg, level = 'info') { send(ws, 'log', { msg, level }); }
function finding(ws, f)               { send(ws, 'finding', f); }
function progress(ws, pct, label)     { send(ws, 'progress', { pct, label }); }
function done(ws, stats)              { send(ws, 'done', stats); }

// ─── Utility ────────────────────────────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function ts() {
  return new Date().toTimeString().slice(0, 8);
}

// ─── Main scan orchestrator ─────────────────────────────────────
async function runScan(msg, ws, isCancelled) {
  const { target, modules } = msg;

  log(ws, `[${ts()}] ╔══════════════════════════════════════════`, 'system');
  log(ws, `[${ts()}] ║  RealVulnScan — Live Network Scanner`, 'system');
  log(ws, `[${ts()}] ╚══════════════════════════════════════════`, 'system');
  log(ws, `[${ts()}] Target  : ${target}`, 'dim');
  log(ws, `[${ts()}] Modules : ${modules.join(', ')}`, 'dim');
  log(ws, `[${ts()}] ───────────────────────────────────────────`, 'dim');

  const stats = { open_ports: [], findings: [], start: Date.now() };
  const total = modules.length;
  let done_count = 0;

  for (const mod of modules) {
    if (isCancelled()) break;
    progress(ws, Math.round((done_count / total) * 100), `Running: ${mod}`);

    try {
      switch (mod) {
        case 'dns':     await scanDNS(target, ws, stats, isCancelled);     break;
        case 'ports':   await scanPorts(target, ws, stats, isCancelled);   break;
        case 'http':    await scanHTTP(target, ws, stats, isCancelled);    break;
        case 'headers': await scanHeaders(target, ws, stats, isCancelled); break;
        case 'ssl':     await scanSSL(target, ws, stats, isCancelled);     break;
        case 'paths':   await scanPaths(target, ws, stats, isCancelled);   break;
        case 'banners': await scanBanners(target, ws, stats, isCancelled); break;
      }
    } catch (err) {
      log(ws, `[${ts()}] ⚠ Module ${mod} error: ${err.message}`, 'warn');
    }

    done_count++;
  }

  const elapsed = ((Date.now() - stats.start) / 1000).toFixed(1);
  log(ws, `[${ts()}] ═══════════════════════════════════════════`, 'dim');
  log(ws, `[${ts()}] SCAN COMPLETE in ${elapsed}s — ${stats.findings.length} findings`, 'system');

  progress(ws, 100, 'Complete');
  send(ws, 'done', {
    elapsed,
    total_findings: stats.findings.length,
    open_ports: stats.open_ports,
  });
}

// ══════════════════════════════════════════════════════════════
//  MODULE 1 — DNS RECONNAISSANCE
// ══════════════════════════════════════════════════════════════
async function scanDNS(target, ws, stats, isCancelled) {
  log(ws, `[${ts()}] ▶ DNS Reconnaissance`, 'module');
  const host = extractHost(target);

  // Resolve A records
  try {
    const addrs = await dns.resolve4(host);
    log(ws, `[${ts()}]   A records: ${addrs.join(', ')}`, 'ok');
    finding(ws, {
      id: 'DNS-001', name: 'DNS A Records', severity: 'info',
      cvss: 0, category: 'Reconnaissance', endpoint: host,
      detail: `Resolved to: ${addrs.join(', ')}`,
      remediation: 'Informational — verify these IPs match expected infrastructure.',
    });
  } catch (e) {
    log(ws, `[${ts()}]   A record lookup failed: ${e.code}`, 'warn');
  }

  // Reverse DNS
  try {
    const ip = extractHost(target);
    const hostnames = await dns.reverse(ip);
    log(ws, `[${ts()}]   Reverse DNS: ${hostnames.join(', ')}`, 'ok');
    finding(ws, {
      id: 'DNS-002', name: 'Reverse DNS Entry', severity: 'info',
      cvss: 0, category: 'Reconnaissance', endpoint: ip,
      detail: `PTR record: ${hostnames.join(', ')}`,
      remediation: 'Ensure PTR records do not expose internal naming conventions.',
    });
  } catch { /* no PTR record — normal */ }

  // MX records (if domain)
  if (!/^\d/.test(host)) {
    try {
      const mx = await dns.resolveMx(host);
      if (mx.length > 0) {
        log(ws, `[${ts()}]   MX records: ${mx.map(r=>r.exchange).join(', ')}`, 'ok');
      }
    } catch { /* no MX */ }

    // TXT records — check for SPF
    try {
      const txt = await dns.resolveTxt(host);
      const spf = txt.flat().find(r => r.includes('v=spf'));
      if (!spf) {
        log(ws, `[${ts()}]   ⚠ No SPF record found`, 'warn');
        finding(ws, {
          id: 'DNS-003', name: 'Missing SPF Record', severity: 'medium',
          cvss: 5.3, category: 'Email Security', endpoint: host,
          detail: 'No SPF TXT record found. Domain is vulnerable to email spoofing.',
          remediation: 'Add an SPF TXT record: v=spf1 include:your-mail-provider.com ~all',
        });
      } else {
        log(ws, `[${ts()}]   SPF record present: ${spf}`, 'ok');
      }
    } catch { /* no TXT */ }
  }

  log(ws, `[${ts()}] ✓ DNS Reconnaissance complete`, 'ok');
}

// ══════════════════════════════════════════════════════════════
//  MODULE 2 — PORT SCANNING
// ══════════════════════════════════════════════════════════════
const TOP_PORTS = [
  21, 22, 23, 25, 53, 80, 81, 110, 111, 119, 135, 139, 143,
  389, 443, 445, 465, 587, 631, 993, 995, 1080, 1433, 1521,
  2049, 2181, 3000, 3306, 3389, 4000, 4443, 4848, 5000, 5432,
  5900, 5984, 6379, 6443, 7001, 7443, 8000, 8080, 8081, 8443,
  8888, 9000, 9090, 9200, 9300, 9443, 11211, 27017, 27018,
  28017, 50070, 61616,
];

const SERVICE_NAMES = {
  21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
  80:'HTTP', 110:'POP3', 143:'IMAP', 389:'LDAP', 443:'HTTPS',
  445:'SMB', 1433:'MSSQL', 1521:'Oracle', 2181:'ZooKeeper',
  3306:'MySQL', 3389:'RDP', 4848:'GlassFish Admin',
  5432:'PostgreSQL', 5900:'VNC', 5984:'CouchDB', 6379:'Redis',
  7001:'WebLogic', 8080:'HTTP-Alt', 8443:'HTTPS-Alt',
  9200:'Elasticsearch', 11211:'Memcached', 27017:'MongoDB',
  28017:'MongoDB HTTP', 50070:'Hadoop NameNode',
};

const RISKY_PORTS = new Set([
  23, 1433, 1521, 3306, 3389, 5432, 5900, 5984,
  6379, 9200, 11211, 27017, 28017, 50070,
]);

async function probePort(host, port, timeout = 2000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let banner = '';
    sock.setTimeout(timeout);
    sock.on('connect', () => {
      sock.setTimeout(500);
      // Try to grab banner
    });
    sock.on('data', (d) => {
      banner += d.toString('utf8', 0, 256).replace(/[\r\n]/g,' ').trim();
      sock.destroy();
    });
    sock.on('timeout', () => { sock.destroy(); resolve({ open: sock.connecting ? false : true, banner }); });
    sock.on('error',   () => resolve({ open: false, banner: '' }));
    sock.on('close',   () => resolve({ open: true,  banner }));
    sock.connect(port, host);
  });
}

async function scanPorts(target, ws, stats, isCancelled) {
  log(ws, `[${ts()}] ▶ Port Scanner (${TOP_PORTS.length} ports)`, 'module');
  const host = extractHost(target);
  const CONCURRENCY = 30;

  const chunks = [];
  for (let i = 0; i < TOP_PORTS.length; i += CONCURRENCY) {
    chunks.push(TOP_PORTS.slice(i, i + CONCURRENCY));
  }

  for (const chunk of chunks) {
    if (isCancelled()) break;
    const results = await Promise.all(chunk.map(p => probePort(host, p)));
    results.forEach((r, i) => {
      const port = chunk[i];
      if (r.open) {
        const svc  = SERVICE_NAMES[port] || 'unknown';
        const risky = RISKY_PORTS.has(port);
        stats.open_ports.push({ port, service: svc, banner: r.banner });

        log(ws, `[${ts()}]   OPEN  ${String(port).padStart(5)} / ${svc}${r.banner ? '  ← ' + r.banner.slice(0,60) : ''}`,
            risky ? 'warn' : 'ok');

        if (risky) {
          finding(ws, {
            id:   `PORT-${port}`,
            name: `${svc} Exposed on Port ${port}`,
            severity: [3306,5432,6379,27017,9200,11211,1433,1521].includes(port) ? 'critical' : 'high',
            cvss: [3306,5432,6379,27017,9200,11211].includes(port) ? 9.1 : 7.5,
            category: 'Network Exposure',
            endpoint: `${host}:${port}`,
            detail: `${svc} is directly accessible from the network on port ${port}.${r.banner ? ' Banner: ' + r.banner.slice(0,120) : ''}`,
            remediation: `Restrict port ${port} with firewall rules. Bind ${svc} to localhost or internal interface only.`,
          });
        }

        if (port === 23) {
          finding(ws, {
            id: 'PORT-023-TELNET',
            name: 'Telnet Service Running (Plaintext)',
            severity: 'critical', cvss: 9.8,
            category: 'Insecure Protocol',
            endpoint: `${host}:23`,
            detail: 'Telnet transmits all data including credentials in plaintext. Trivially intercepted.',
            remediation: 'Disable Telnet immediately. Use SSH instead.',
          });
        }
      }
    });
  }

  log(ws, `[${ts()}] ✓ Port scan complete — ${stats.open_ports.length} open port(s)`, 'ok');
}

// ══════════════════════════════════════════════════════════════
//  MODULE 3 — HTTP/HTTPS CONNECTIVITY
// ══════════════════════════════════════════════════════════════
async function scanHTTP(target, ws, stats, isCancelled) {
  log(ws, `[${ts()}] ▶ HTTP/HTTPS Probe`, 'module');
  const host = extractHost(target);

  const schemes = ['http', 'https'];
  const ports   = [80, 443, 8080, 8443, 8888, 3000];

  for (const scheme of schemes) {
    for (const port of ports) {
      if (isCancelled()) return;
      const url = `${scheme}://${host}:${port}/`;
      try {
        const res = await httpGet(url, 5000);
        log(ws, `[${ts()}]   ${scheme.toUpperCase()}:${port} → ${res.statusCode} (${res.body.length} bytes)`, 'ok');

        stats.http_urls = stats.http_urls || [];
        stats.http_urls.push({ url, status: res.statusCode });

        if (scheme === 'http' && (port === 80 || port === 8080)) {
          // Check if HTTPS version exists
          const httpsUrl = url.replace('http://', 'https://').replace(':80', ':443').replace(':8080',':8443');
          try {
            await httpGet(httpsUrl, 3000);
            // HTTPS exists — check if HTTP redirects
            if (res.statusCode !== 301 && res.statusCode !== 302) {
              finding(ws, {
                id: 'HTTP-001',
                name: 'HTTP Not Redirecting to HTTPS',
                severity: 'medium', cvss: 5.9,
                category: 'Transport Security',
                endpoint: url,
                detail: 'The server serves content over plaintext HTTP without redirecting to HTTPS, allowing traffic interception.',
                remediation: 'Add a permanent 301 redirect from HTTP to HTTPS. Enable HSTS header.',
              });
            }
          } catch { /* no HTTPS */ }
        }

        // Check for directory listing
        if (res.body.includes('Index of /') || res.body.includes('Directory listing')) {
          finding(ws, {
            id: 'HTTP-002',
            name: 'Directory Listing Enabled',
            severity: 'medium', cvss: 5.3,
            category: 'Information Disclosure',
            endpoint: url,
            detail: 'Web server returns directory listings, exposing file and folder structure.',
            remediation: 'Disable directory listing: add "Options -Indexes" (Apache) or "autoindex off" (nginx).',
          });
        }

        break; // Found a working port for this scheme, continue
      } catch { /* port closed or refused */ }
    }
  }

  log(ws, `[${ts()}] ✓ HTTP probe complete`, 'ok');
}

// ══════════════════════════════════════════════════════════════
//  MODULE 4 — HTTP SECURITY HEADERS
// ══════════════════════════════════════════════════════════════
async function scanHeaders(target, ws, stats, isCancelled) {
  log(ws, `[${ts()}] ▶ HTTP Security Header Analysis`, 'module');
  const host = extractHost(target);

  let res;
  const tryUrls = [
    `https://${host}/`, `http://${host}/`,
    `https://${host}:8443/`, `http://${host}:8080/`,
  ];

  for (const url of tryUrls) {
    if (isCancelled()) return;
    try {
      res = await httpGet(url, 5000);
      log(ws, `[${ts()}]   Connected to ${url}`, 'ok');
      break;
    } catch { /* try next */ }
  }

  if (!res) {
    log(ws, `[${ts()}]   Could not reach any HTTP endpoint`, 'warn');
    return;
  }

  const h = res.headers;

  // Server header
  if (h['server']) {
    log(ws, `[${ts()}]   Server: ${h['server']}`, 'warn');
    finding(ws, {
      id: 'HDR-001', name: 'Server Version Disclosure',
      severity: 'low', cvss: 3.1,
      category: 'Information Disclosure',
      endpoint: tryUrls[0],
      detail: `Server header reveals: "${h['server']}"`,
      remediation: 'Remove or genericise the Server header in your web server config.',
    });
  }

  // X-Powered-By
  if (h['x-powered-by']) {
    log(ws, `[${ts()}]   X-Powered-By: ${h['x-powered-by']}`, 'warn');
    finding(ws, {
      id: 'HDR-002', name: 'X-Powered-By Header Disclosed',
      severity: 'low', cvss: 3.1,
      category: 'Information Disclosure',
      endpoint: tryUrls[0],
      detail: `X-Powered-By: ${h['x-powered-by']}`,
      remediation: 'Remove X-Powered-By header (PHP: expose_php=Off, Express: app.disable("x-powered-by")).',
    });
  }

  // Strict-Transport-Security
  if (!h['strict-transport-security']) {
    log(ws, `[${ts()}]   ⚠ Missing: Strict-Transport-Security`, 'warn');
    finding(ws, {
      id: 'HDR-003', name: 'Missing HSTS Header',
      severity: 'medium', cvss: 5.9,
      category: 'Transport Security',
      endpoint: tryUrls[0],
      detail: 'No Strict-Transport-Security header. Browsers can be downgraded to HTTP.',
      remediation: 'Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
    });
  } else {
    log(ws, `[${ts()}]   HSTS: ${h['strict-transport-security']}`, 'ok');
  }

  // Content-Security-Policy
  if (!h['content-security-policy']) {
    log(ws, `[${ts()}]   ⚠ Missing: Content-Security-Policy`, 'warn');
    finding(ws, {
      id: 'HDR-004', name: 'Missing Content-Security-Policy',
      severity: 'medium', cvss: 5.1,
      category: 'Injection',
      endpoint: tryUrls[0],
      detail: 'No CSP header found. XSS attacks have higher impact without CSP.',
      remediation: "Add: Content-Security-Policy: default-src 'self'",
    });
  } else {
    log(ws, `[${ts()}]   CSP present`, 'ok');
  }

  // X-Frame-Options
  if (!h['x-frame-options'] && !h['content-security-policy']?.includes('frame-ancestors')) {
    log(ws, `[${ts()}]   ⚠ Missing: X-Frame-Options`, 'warn');
    finding(ws, {
      id: 'HDR-005', name: 'Missing X-Frame-Options (Clickjacking)',
      severity: 'low', cvss: 3.7,
      category: 'UI Redressing',
      endpoint: tryUrls[0],
      detail: 'Page can be embedded in iframes by any site, enabling clickjacking attacks.',
      remediation: 'Add: X-Frame-Options: DENY',
    });
  }

  // X-Content-Type-Options
  if (!h['x-content-type-options']) {
    log(ws, `[${ts()}]   ⚠ Missing: X-Content-Type-Options`, 'warn');
    finding(ws, {
      id: 'HDR-006', name: 'Missing X-Content-Type-Options',
      severity: 'low', cvss: 3.1,
      category: 'Configuration',
      endpoint: tryUrls[0],
      detail: 'Browser MIME sniffing is enabled. Can be used to misinterpret responses.',
      remediation: 'Add: X-Content-Type-Options: nosniff',
    });
  }

  // Referrer-Policy
  if (!h['referrer-policy']) {
    log(ws, `[${ts()}]   ⚠ Missing: Referrer-Policy`, 'dim');
  }

  // Permissions-Policy
  if (!h['permissions-policy']) {
    log(ws, `[${ts()}]   ⚠ Missing: Permissions-Policy`, 'dim');
  }

  // Cookie security
  const setCookie = h['set-cookie'];
  if (setCookie) {
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
    cookies.forEach(c => {
      const name = c.split('=')[0].trim();
      if (!c.toLowerCase().includes('httponly')) {
        log(ws, `[${ts()}]   ⚠ Cookie "${name}" missing HttpOnly`, 'warn');
        finding(ws, {
          id: `HDR-COOKIE-${name}`, name: `Cookie Missing HttpOnly: ${name}`,
          severity: 'medium', cvss: 5.4,
          category: 'Session Management',
          endpoint: tryUrls[0],
          detail: `Cookie "${name}" is accessible via JavaScript (no HttpOnly flag).`,
          remediation: `Add HttpOnly flag to the "${name}" cookie: Set-Cookie: ${name}=...; HttpOnly`,
        });
      }
      if (!c.toLowerCase().includes('secure')) {
        log(ws, `[${ts()}]   ⚠ Cookie "${name}" missing Secure flag`, 'warn');
        finding(ws, {
          id: `HDR-COOKIE-SECURE-${name}`, name: `Cookie Missing Secure Flag: ${name}`,
          severity: 'medium', cvss: 5.4,
          category: 'Session Management',
          endpoint: tryUrls[0],
          detail: `Cookie "${name}" will be sent over HTTP connections.`,
          remediation: `Add Secure flag: Set-Cookie: ${name}=...; Secure`,
        });
      }
    });
  }

  // CORS
  if (h['access-control-allow-origin'] === '*') {
    log(ws, `[${ts()}]   ⚠ CORS: Access-Control-Allow-Origin: *`, 'warn');
    finding(ws, {
      id: 'HDR-CORS', name: 'Permissive CORS Policy (Wildcard)',
      severity: 'high', cvss: 7.5,
      category: 'Access Control',
      endpoint: tryUrls[0],
      detail: 'Access-Control-Allow-Origin: * allows any website to read API responses.',
      remediation: 'Restrict CORS to specific trusted origins. Never use wildcard with credentials.',
    });
  }

  log(ws, `[${ts()}] ✓ Header analysis complete`, 'ok');
}

// ══════════════════════════════════════════════════════════════
//  MODULE 5 — SSL/TLS ANALYSIS
// ══════════════════════════════════════════════════════════════
async function scanSSL(target, ws, stats, isCancelled) {
  log(ws, `[${ts()}] ▶ SSL/TLS Certificate Analysis`, 'module');
  const host = extractHost(target);
  const sslPorts = [443, 8443, 4443];

  for (const port of sslPorts) {
    if (isCancelled()) return;
    try {
      const info = await tlsCheck(host, port);
      log(ws, `[${ts()}]   Connected TLS ${info.protocol} on port ${port}`, 'ok');

      // Protocol version
      if (['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'].includes(info.protocol)) {
        finding(ws, {
          id: 'SSL-001', name: `Deprecated ${info.protocol} Supported`,
          severity: 'high', cvss: 7.4,
          category: 'Cryptography',
          endpoint: `${host}:${port}`,
          detail: `Server accepted a connection using deprecated ${info.protocol} which is vulnerable to POODLE/BEAST attacks.`,
          remediation: 'Disable TLS 1.0 and 1.1. Enforce TLS 1.2 minimum, prefer TLS 1.3.',
        });
      } else {
        log(ws, `[${ts()}]   Protocol: ${info.protocol} ✓`, 'ok');
      }

      // Certificate expiry
      const cert = info.cert;
      if (cert) {
        const expiry = new Date(cert.valid_to);
        const now    = new Date();
        const daysLeft = Math.floor((expiry - now) / 86400000);

        log(ws, `[${ts()}]   Certificate: ${cert.subject?.CN || 'Unknown'} — expires ${cert.valid_to}`, 'ok');
        log(ws, `[${ts()}]   Days until expiry: ${daysLeft}`, daysLeft < 30 ? 'warn' : 'ok');

        if (daysLeft < 0) {
          finding(ws, {
            id: 'SSL-002', name: 'SSL Certificate Expired',
            severity: 'critical', cvss: 9.1,
            category: 'Cryptography',
            endpoint: `${host}:${port}`,
            detail: `Certificate expired ${Math.abs(daysLeft)} days ago on ${cert.valid_to}.`,
            remediation: 'Renew the SSL certificate immediately.',
          });
        } else if (daysLeft < 30) {
          finding(ws, {
            id: 'SSL-003', name: 'SSL Certificate Expiring Soon',
            severity: 'medium', cvss: 5.3,
            category: 'Cryptography',
            endpoint: `${host}:${port}`,
            detail: `Certificate expires in ${daysLeft} days on ${cert.valid_to}.`,
            remediation: 'Renew the SSL certificate before it expires.',
          });
        }

        // Self-signed check
        const issuer  = cert.issuer?.O || cert.issuer?.CN || '';
        const subject = cert.subject?.O || cert.subject?.CN || '';
        if (issuer === subject || issuer.includes('self') || !cert.issuer?.O) {
          log(ws, `[${ts()}]   ⚠ Certificate appears self-signed`, 'warn');
          finding(ws, {
            id: 'SSL-004', name: 'Self-Signed Certificate',
            severity: 'medium', cvss: 5.9,
            category: 'Cryptography',
            endpoint: `${host}:${port}`,
            detail: `Certificate issued by: "${cert.issuer?.CN}" — not trusted by public CAs.`,
            remediation: "Obtain a certificate from a trusted CA (Let's Encrypt is free).",
          });
        }
      }

      break; // One SSL port is enough
    } catch { /* port not open or no TLS */ }
  }

  log(ws, `[${ts()}] ✓ SSL analysis complete`, 'ok');
}

// ══════════════════════════════════════════════════════════════
//  MODULE 6 — SENSITIVE PATH DISCOVERY
// ══════════════════════════════════════════════════════════════
const SENSITIVE_PATHS = [
  // Source control
  { path: '/.git/HEAD',        name: 'Git Repository Exposed',       sev: 'critical', cvss: 9.1,  cat: 'Information Disclosure' },
  { path: '/.git/config',      name: 'Git Config Exposed',           sev: 'high',     cvss: 7.5,  cat: 'Information Disclosure' },
  { path: '/.svn/entries',     name: 'SVN Repository Exposed',       sev: 'high',     cvss: 7.5,  cat: 'Information Disclosure' },
  { path: '/.env',             name: '.env File Exposed',            sev: 'critical', cvss: 9.8,  cat: 'Information Disclosure' },
  { path: '/.env.local',       name: '.env.local File Exposed',      sev: 'critical', cvss: 9.8,  cat: 'Information Disclosure' },
  { path: '/.env.production',  name: '.env.production Exposed',      sev: 'critical', cvss: 9.8,  cat: 'Information Disclosure' },
  // Admin panels
  { path: '/admin',            name: 'Admin Panel Accessible',       sev: 'high',     cvss: 7.3,  cat: 'Access Control' },
  { path: '/admin/login',      name: 'Admin Login Page Accessible',  sev: 'medium',   cvss: 5.3,  cat: 'Access Control' },
  { path: '/wp-admin/',        name: 'WordPress Admin Exposed',      sev: 'medium',   cvss: 5.3,  cat: 'Access Control' },
  { path: '/wp-login.php',     name: 'WordPress Login Exposed',      sev: 'low',      cvss: 3.7,  cat: 'Access Control' },
  { path: '/administrator/',   name: 'Joomla Admin Exposed',         sev: 'medium',   cvss: 5.3,  cat: 'Access Control' },
  { path: '/phpmyadmin/',      name: 'phpMyAdmin Exposed',           sev: 'critical', cvss: 9.8,  cat: 'Access Control' },
  { path: '/pma/',             name: 'phpMyAdmin (pma) Exposed',     sev: 'critical', cvss: 9.8,  cat: 'Access Control' },
  { path: '/manager/html',     name: 'Tomcat Manager Exposed',       sev: 'critical', cvss: 9.8,  cat: 'Access Control' },
  { path: '/actuator',         name: 'Spring Actuator Exposed',      sev: 'high',     cvss: 7.5,  cat: 'Access Control' },
  { path: '/actuator/env',     name: 'Spring Actuator /env Exposed', sev: 'critical', cvss: 9.1,  cat: 'Information Disclosure' },
  { path: '/console',          name: 'Debug Console Exposed',        sev: 'critical', cvss: 9.8,  cat: 'Access Control' },
  // Config / backup files
  { path: '/config.php',       name: 'config.php Accessible',        sev: 'high',     cvss: 7.5,  cat: 'Information Disclosure' },
  { path: '/config.php.bak',   name: 'config.php Backup Exposed',    sev: 'high',     cvss: 7.5,  cat: 'Information Disclosure' },
  { path: '/database.sql',     name: 'SQL Dump Exposed',             sev: 'critical', cvss: 9.8,  cat: 'Information Disclosure' },
  { path: '/db.sql',           name: 'SQL Dump Exposed',             sev: 'critical', cvss: 9.8,  cat: 'Information Disclosure' },
  { path: '/backup.zip',       name: 'Backup Archive Exposed',       sev: 'high',     cvss: 7.5,  cat: 'Information Disclosure' },
  { path: '/web.config',       name: 'web.config Accessible',        sev: 'high',     cvss: 7.5,  cat: 'Information Disclosure' },
  { path: '/composer.json',    name: 'composer.json Exposed',        sev: 'low',      cvss: 3.1,  cat: 'Information Disclosure' },
  { path: '/package.json',     name: 'package.json Exposed',         sev: 'low',      cvss: 3.1,  cat: 'Information Disclosure' },
  { path: '/Dockerfile',       name: 'Dockerfile Exposed',           sev: 'medium',   cvss: 5.3,  cat: 'Information Disclosure' },
  // API / debug
  { path: '/api',              name: 'API Root Accessible',          sev: 'info',     cvss: 0,    cat: 'Reconnaissance' },
  { path: '/swagger-ui.html',  name: 'Swagger UI Exposed',           sev: 'medium',   cvss: 5.3,  cat: 'Information Disclosure' },
  { path: '/swagger.json',     name: 'Swagger/OpenAPI Spec Exposed', sev: 'medium',   cvss: 5.3,  cat: 'Information Disclosure' },
  { path: '/graphql',          name: 'GraphQL Endpoint Exposed',     sev: 'medium',   cvss: 5.3,  cat: 'Information Disclosure' },
  { path: '/.well-known/security.txt', name: 'security.txt Missing', sev: 'info', cvss: 0,       cat: 'Reconnaissance' },
  { path: '/robots.txt',       name: 'robots.txt Accessible',        sev: 'info',     cvss: 0,    cat: 'Reconnaissance' },
  { path: '/sitemap.xml',      name: 'sitemap.xml Accessible',       sev: 'info',     cvss: 0,    cat: 'Reconnaissance' },
  { path: '/server-status',    name: 'Apache server-status Exposed', sev: 'high',     cvss: 7.5,  cat: 'Information Disclosure' },
  { path: '/server-info',      name: 'Apache server-info Exposed',   sev: 'high',     cvss: 7.5,  cat: 'Information Disclosure' },
  { path: '/nginx_status',     name: 'Nginx status Exposed',         sev: 'medium',   cvss: 5.3,  cat: 'Information Disclosure' },
  { path: '/.DS_Store',        name: '.DS_Store File Exposed',        sev: 'medium',   cvss: 5.3,  cat: 'Information Disclosure' },
];

async function scanPaths(target, ws, stats, isCancelled) {
  log(ws, `[${ts()}] ▶ Sensitive Path Discovery (${SENSITIVE_PATHS.length} paths)`, 'module');
  const host = extractHost(target);

  const baseUrls = [];
  for (const scheme of ['https','http']) {
    for (const port of [443,80,8443,8080]) {
      baseUrls.push(`${scheme}://${host}:${port}`);
    }
  }

  // Find a working base URL
  let base = null;
  for (const u of baseUrls) {
    if (isCancelled()) return;
    try {
      await httpGet(u + '/', 4000);
      base = u;
      log(ws, `[${ts()}]   Base URL: ${u}`, 'ok');
      break;
    } catch { /* try next */ }
  }

  if (!base) {
    log(ws, `[${ts()}]   No HTTP server found — skipping path scan`, 'warn');
    return;
  }

  const CONCURRENCY = 8;
  for (let i = 0; i < SENSITIVE_PATHS.length; i += CONCURRENCY) {
    if (isCancelled()) break;
    const batch = SENSITIVE_PATHS.slice(i, i + CONCURRENCY);
    await Promise.all(batch.map(async (p) => {
      if (isCancelled()) return;
      try {
        const res = await httpGet(base + p.path, 4000);
        if (res.statusCode >= 200 && res.statusCode < 300) {
          log(ws, `[${ts()}]   [${res.statusCode}] ${p.path} — ${p.name}`,
              ['critical','high'].includes(p.sev) ? 'warn' : 'dim');
          if (p.sev !== 'info') {
            finding(ws, {
              id:   `PATH-${p.path.replace(/[^a-z0-9]/gi,'-')}`,
              name: p.name,
              severity: p.sev,
              cvss: p.cvss,
              category: p.cat,
              endpoint: base + p.path,
              detail:   `Path "${p.path}" returned HTTP ${res.statusCode}. ${res.body.slice(0,200)}`,
              remediation: `Restrict access to "${p.path}" or remove the file/endpoint from the web root.`,
            });
          }
        }
      } catch { /* 404 or unreachable — good */ }
    }));
    await sleep(50);
  }

  log(ws, `[${ts()}] ✓ Path discovery complete`, 'ok');
}

// ══════════════════════════════════════════════════════════════
//  MODULE 7 — BANNER GRABBING
// ══════════════════════════════════════════════════════════════
async function scanBanners(target, ws, stats, isCancelled) {
  log(ws, `[${ts()}] ▶ Service Banner Analysis`, 'module');
  const host = extractHost(target);

  for (const { port, service } of (stats.open_ports || [])) {
    if (isCancelled()) break;
    try {
      const info = await grabBanner(host, port);
      if (info) {
        log(ws, `[${ts()}]   ${service}:${port} → ${info.slice(0,80)}`, 'dim');
        // Check for outdated versions
        checkBannerVulns(ws, port, service, info);
      }
    } catch { /* skip */ }
  }

  log(ws, `[${ts()}] ✓ Banner analysis complete`, 'ok');
}

function checkBannerVulns(ws, port, service, banner) {
  const b = banner.toLowerCase();
  const checks = [
    { match: /apache\/2\.[0-3]/,        name: 'Outdated Apache Version',      sev: 'medium', cvss: 5.9 },
    { match: /nginx\/1\.[0-9]\./,       name: 'Potentially Outdated Nginx',   sev: 'low',    cvss: 3.1 },
    { match: /openssh_(5|6|7\.[0-5])/i, name: 'Outdated OpenSSH Version',     sev: 'medium', cvss: 5.9 },
    { match: /vsftpd 2\.[0-2]/,         name: 'Outdated vsftpd Version',      sev: 'high',   cvss: 7.5 },
    { match: /proftpd 1\.[23]/,         name: 'Outdated ProFTPD Version',     sev: 'high',   cvss: 7.5 },
    { match: /microsoft-iis\/[0-7]\./i, name: 'Outdated IIS Version',         sev: 'high',   cvss: 7.5 },
    { match: /mysql\s+5\.[0-5]/i,       name: 'Outdated MySQL Version',       sev: 'medium', cvss: 5.9 },
    { match: /anonymous/i,              name: 'Anonymous FTP Login Possible', sev: 'high',   cvss: 7.5 },
  ];
  for (const c of checks) {
    if (c.match.test(banner)) {
      finding(ws, {
        id: `BNR-${port}-${service}`,
        name: c.name,
        severity: c.sev, cvss: c.cvss,
        category: 'Outdated Software',
        endpoint: `${service}:${port}`,
        detail: `Banner: "${banner.slice(0,150)}"`,
        remediation: `Update ${service} to the latest stable version and remove version information from banners.`,
      });
    }
  }
}

// ══════════════════════════════════════════════════════════════
//  HTTP & TLS HELPERS
// ══════════════════════════════════════════════════════════════
function httpGet(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const mod  = url.startsWith('https') ? https : http;
    const opts = {
      headers: { 'User-Agent': 'RealVulnScan/1.0 Security Scanner' },
      timeout,
      rejectUnauthorized: false, // allow self-signed certs
    };
    const req = mod.get(url, opts, (res) => {
      let body = '';
      res.setTimeout(timeout);
      res.on('data', d => { body += d; if (body.length > 50000) res.destroy(); });
      res.on('end',  () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error',   reject);
  });
}

function tlsCheck(host, port) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port, rejectUnauthorized: false, timeout: 5000 }, () => {
      const proto = sock.getProtocol();
      const cert  = sock.getPeerCertificate();
      sock.destroy();
      resolve({ protocol: proto, cert });
    });
    sock.on('error',   reject);
    sock.on('timeout', () => { sock.destroy(); reject(new Error('timeout')); });
    sock.setTimeout(5000);
  });
}

function grabBanner(host, port) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let data = '';
    sock.setTimeout(2500);
    sock.connect(port, host, () => {
      // Send a generic probe for common protocols
      if ([80,8080,8000].includes(port)) sock.write('HEAD / HTTP/1.0\r\n\r\n');
      if (port === 21)  sock.write('');   // FTP sends banner automatically
      if (port === 22)  sock.write('');   // SSH sends banner automatically
      if (port === 25)  sock.write('EHLO vulnscan\r\n');
    });
    sock.on('data', d => { data += d.toString('utf8',0,512); sock.destroy(); });
    sock.on('timeout', () => { sock.destroy(); resolve(data.trim() || null); });
    sock.on('error',   () => resolve(null));
    sock.on('close',   () => resolve(data.trim() || null));
  });
}

function extractHost(target) {
  try { return new URL(target).hostname; } catch { return target.trim(); }
}

// ─── Start server ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║   RealVulnScan — Security Scanner         ║`);
  console.log(`  ╚══════════════════════════════════════════╝`);
  console.log(`\n  ✓ Server running at: http://localhost:${PORT}`);
  console.log(`  ✓ Open that URL in your browser to scan\n`);
  console.log(`  ⚠  For authorised testing only!\n`);
});
