/* ═══════════════════════════════════════════════
   INTELFUSE X — CORE APPLICATION SCRIPT
   AI-Powered Cyber Intelligence Platform
═══════════════════════════════════════════════ */

'use strict';

// ══════════ GLOBAL STATE ══════════
const STATE = {
  currentPage: 'dashboard',
  activeCaseId: 'CASE-2026-0017',
  graphNodes: [],
  graphEdges: [],
  selectedNode: null,
  graphScale: 1,
  graphOffsetX: 0,
  graphOffsetY: 0,
  isDraggingGraph: false,
  dragStart: { x: 0, y: 0 },
  aiMessages: [],
  aiTyping: false,
  sidebarCollapsed: false,
};

// ══════════ KATANA DATA ══════════
const KATANA_DATA = {
  target: 'https://example.com',
  crawledUrls: 247,
  jsFiles: 38,
  forms: 19,
  apiEndpoints: 61,
  parameters: 134,
  duration: '4m 12s',
  depth: 5,
  stats: [
    { label: 'URLs Crawled', value: 247, color: 'cyan' },
    { label: 'JS Files', value: 38, color: 'purple' },
    { label: 'API Endpoints', value: 61, color: 'amber' },
    { label: 'HTML Forms', value: 19, color: 'red' },
    { label: 'Parameters', value: 134, color: 'green' },
    { label: 'Unique Domains', value: 14, color: 'cyan' },
  ],
  endpoints: [
    { url: 'https://api.example.com/v1/login', method: 'POST', params: ['username','password'], type: 'Auth', risk: 'CRITICAL', finding: 'SQLi vector via username param' },
    { url: 'https://admin.example.com/dashboard', method: 'GET', params: ['session_id'], type: 'Admin', risk: 'CRITICAL', finding: 'Unauthenticated access possible' },
    { url: 'https://api.example.com/v1/users', method: 'GET', params: ['id','role'], type: 'API', risk: 'HIGH', finding: 'IDOR — user role enumerable' },
    { url: 'https://api.example.com/v1/export', method: 'POST', params: ['format','data'], type: 'API', risk: 'HIGH', finding: 'Arbitrary file export via format param' },
    { url: 'https://example.com/search', method: 'GET', params: ['q','page'], type: 'Web', risk: 'HIGH', finding: 'Reflected XSS in q parameter' },
    { url: 'https://api.example.com/v2/upload', method: 'POST', params: ['file','type'], type: 'Upload', risk: 'HIGH', finding: 'Unrestricted file upload — no type validation' },
    { url: 'https://dev.example.com/debug', method: 'GET', params: ['verbose','cmd'], type: 'Debug', risk: 'CRITICAL', finding: 'Remote code execution via cmd param — ACTIVE' },
    { url: 'https://example.com/api/webhook', method: 'POST', params: ['url','secret'], type: 'Webhook', risk: 'HIGH', finding: 'SSRF via url parameter' },
    { url: 'https://api.example.com/v1/reset-password', method: 'POST', params: ['email','token'], type: 'Auth', risk: 'MEDIUM', finding: 'Token brute-force possible — no rate limit' },
    { url: 'https://example.com/assets/', method: 'GET', params: [], type: 'Static', risk: 'MEDIUM', finding: 'Directory listing enabled' },
    { url: 'https://api.example.com/v1/health', method: 'GET', params: [], type: 'API', risk: 'LOW', finding: 'Internal server info disclosure' },
    { url: 'https://example.com/sitemap.xml', method: 'GET', params: [], type: 'Static', risk: 'LOW', finding: 'Exposes all route structure to attackers' },
  ],
  jsSecrets: [
    { file: '/static/js/main.chunk.js', secret: 'AWS_SECRET_KEY', value: 'AKIAXXX...REDACTED', severity: 'CRITICAL', line: 2847 },
    { file: '/static/js/vendor.js', secret: 'API_TOKEN', value: 'tok_live_XXXX...REDACTED', severity: 'CRITICAL', line: 1204 },
    { file: '/static/js/app.js', secret: 'GOOGLE_API_KEY', value: 'AIzaSy...REDACTED', severity: 'HIGH', line: 341 },
    { file: '/static/js/main.chunk.js', secret: 'STRIPE_SECRET', value: 'sk_live_XXXX...REDACTED', severity: 'CRITICAL', line: 5912 },
    { file: '/static/js/config.js', secret: 'SENTRY_DSN', value: 'https://xxx@sentry.io/...', severity: 'MEDIUM', line: 12 },
    { file: '/static/js/auth.js', secret: 'JWT_SECRET', value: 'mysecretkey123...', severity: 'HIGH', line: 78 },
  ],
  forms: [
    { action: '/login', method: 'POST', inputs: ['username','password','_csrf'], notes: 'CSRF token present. SQLi tested — vulnerable.' },
    { action: '/register', method: 'POST', inputs: ['email','name','password','confirm_password'], notes: 'No email verification. Weak password policy.' },
    { action: '/search', method: 'GET', inputs: ['q','category','sort'], notes: 'Reflected XSS in q parameter confirmed.' },
    { action: '/contact', method: 'POST', inputs: ['name','email','message'], notes: 'Stored XSS possible in message field.' },
    { action: '/upload', method: 'POST', inputs: ['file','description','type'], notes: 'No file type validation — SVG upload allows XSS.' },
    { action: '/api/feedback', method: 'POST', inputs: ['rating','comment','user_id'], notes: 'IDOR via user_id — no ownership check.' },
  ],
  terminalOutput: [
    { type: 'cyan', text: '$ katana -u https://example.com -d 5 -jc -ef png,jpg,gif -o katana_results.txt' },
    { type: 'green', text: '   __        __' },
    { type: 'green', text: '  / /_____ _/ /____ ____  ___ _' },
    { type: 'cyan', text: ' / // / _ `/ __/ _ `/ _ \/ _ `/' },
    { type: 'cyan', text: '/_//_/\_,_/\__/\_,_/_//_/\_,_/' },
    { type: 'gray', text: '                    projectdiscovery.io' },
    { type: 'gray', text: '' },
    { type: 'amber', text: '[INF] Current katana version v1.1.2 (latest)' },
    { type: 'amber', text: '[INF] Started standard crawling for => https://example.com' },
    { type: 'green', text: 'https://example.com/login' },
    { type: 'green', text: 'https://example.com/register' },
    { type: 'green', text: 'https://api.example.com/v1/login' },
    { type: 'green', text: 'https://api.example.com/v1/users' },
    { type: 'red',   text: 'https://dev.example.com/debug?cmd=' },
    { type: 'green', text: 'https://admin.example.com/dashboard' },
    { type: 'green', text: 'https://api.example.com/v1/export' },
    { type: 'red',   text: '[FINDING] Hardcoded secret in /static/js/main.chunk.js (line 2847): AWS_SECRET_KEY' },
    { type: 'red',   text: '[FINDING] Hardcoded secret in /static/js/vendor.js (line 1204): API_TOKEN' },
    { type: 'amber', text: '[INF] Identified 19 HTML forms for parameter analysis' },
    { type: 'amber', text: '[INF] Extracted 134 unique input parameters across all endpoints' },
    { type: 'red',   text: '[CRITICAL] RCE vector: https://dev.example.com/debug?cmd= — blind cmd injection' },
    { type: 'green', text: '[INF] Crawl complete: 247 URLs | 38 JS files | 61 API endpoints | 4m 12s' },
  ],
};

// ══════════ MOCK DATA ══════════
const DATA = {
  cases: [
    {
      id: 'CASE-2026-0017', subject: 'example.com', status: 'Active', statusClass: 'active-case',
      investigator: 'Analyst 01', opened: '2026-09-14', riskLevel: 'HIGH', riskClass: 'badge-critical',
      evidence: 127, iocs: 43, findings: 18, subdomains: 34, ips: 12,
      description: 'Advanced persistent threat detected targeting corporate domain. Phishing infrastructure identified with IoCs linked to APT-29 cluster.',
      tags: ['APT-29', 'Phishing', 'C2', 'Exfiltration'],
    },
    {
      id: 'CASE-2026-0014', subject: 'corp-vpn.net', status: 'Active', statusClass: 'active-case',
      investigator: 'Analyst 02', opened: '2026-09-02', riskLevel: 'CRITICAL', riskClass: 'badge-critical',
      evidence: 89, iocs: 27, findings: 11, subdomains: 8, ips: 5,
      description: 'Suspicious VPN endpoint discovered with anomalous certificate chain. Possible network interception attempt.',
      tags: ['MitM', 'VPN', 'Certificate'],
    },
    {
      id: 'CASE-2026-0011', subject: '192.168.47.22', status: 'Pending', statusClass: 'pending-case',
      investigator: 'Analyst 01', opened: '2026-08-21', riskLevel: 'MEDIUM', riskClass: 'badge-medium',
      evidence: 45, iocs: 9, findings: 7, subdomains: 0, ips: 3,
      description: 'Internal lateral movement detected from compromised workstation. Memory dump analysis pending.',
      tags: ['LateralMovement', 'Malware', 'Memory'],
    },
    {
      id: 'CASE-2026-0009', subject: 'supply-chain.io', status: 'Pending', statusClass: 'pending-case',
      investigator: 'Analyst 03', opened: '2026-08-10', riskLevel: 'HIGH', riskClass: 'badge-high',
      evidence: 62, iocs: 15, findings: 9, subdomains: 19, ips: 7,
      description: 'Third-party software vendor domain showing signs of compromise. Supply chain risk assessment underway.',
      tags: ['SupplyChain', 'ThirdParty', 'SBOM'],
    },
    {
      id: 'CASE-2026-0007', subject: 'ransom-srv-01', status: 'Closed', statusClass: 'closed-case',
      investigator: 'Analyst 02', opened: '2026-07-05', riskLevel: 'CRITICAL', riskClass: 'badge-critical',
      evidence: 204, iocs: 78, findings: 31, subdomains: 0, ips: 14,
      description: 'Ransomware incident fully contained. LOCKBIT 3.0 variant isolated. Recovery completed.',
      tags: ['Ransomware', 'LOCKBIT', 'Resolved'],
    },
    {
      id: 'CASE-2026-0003', subject: 'phish-kit-cdn', status: 'Closed', statusClass: 'closed-case',
      investigator: 'Analyst 01', opened: '2026-06-12', riskLevel: 'HIGH', riskClass: 'badge-high',
      evidence: 33, iocs: 12, findings: 6, subdomains: 5, ips: 2,
      description: 'Phishing kit distributed via CDN edge nodes. Takedown completed in coordination with hosting providers.',
      tags: ['Phishing', 'CDN', 'Takedown'],
    },
  ],
  iocs: [
    { id: 'IOC-0001', type: 'Domain', value: 'evil-c2.ru', confidence: 95, severity: 'CRITICAL', threat: 'APT-29 C2', first_seen: '2026-09-14 08:12', last_seen: '2026-10-07 22:41', tags: ['APT-29', 'C2'] },
    { id: 'IOC-0002', type: 'IP', value: '185.220.101.45', confidence: 88, severity: 'HIGH', threat: 'TOR Exit Node', first_seen: '2026-09-15 14:33', last_seen: '2026-10-08 11:20', tags: ['TOR', 'C2'] },
    { id: 'IOC-0003', type: 'Hash', value: 'a3f2bc...e891d4', confidence: 99, severity: 'CRITICAL', threat: 'LOCKBIT 3.0 Payload', first_seen: '2026-09-20 06:44', last_seen: '2026-09-20 06:44', tags: ['Ransomware', 'LOCKBIT'] },
    { id: 'IOC-0004', type: 'URL', value: 'hxxps://phish.evil/login', confidence: 76, severity: 'HIGH', threat: 'Credential Harvester', first_seen: '2026-09-22 16:01', last_seen: '2026-10-01 09:15', tags: ['Phishing'] },
    { id: 'IOC-0005', type: 'Email', value: 'noreply@evil-c2.ru', confidence: 91, severity: 'HIGH', threat: 'Spear Phishing Sender', first_seen: '2026-09-14 08:00', last_seen: '2026-09-30 17:22', tags: ['APT-29', 'Phishing'] },
    { id: 'IOC-0006', type: 'IP', value: '45.142.212.100', confidence: 72, severity: 'MEDIUM', threat: 'Scanning Node', first_seen: '2026-10-01 00:00', last_seen: '2026-10-08 23:59', tags: ['Recon'] },
    { id: 'IOC-0007', type: 'Domain', value: 'cdn-update.net', confidence: 84, severity: 'HIGH', threat: 'Dropper Distribution', first_seen: '2026-09-28 12:00', last_seen: '2026-10-05 18:45', tags: ['Dropper'] },
    { id: 'IOC-0008', type: 'Hash', value: 'd8c1a0...7f3b22', confidence: 97, severity: 'CRITICAL', threat: 'Cobalt Strike Beacon', first_seen: '2026-10-02 03:11', last_seen: '2026-10-07 23:58', tags: ['CobaltStrike', 'Beacon'] },
  ],
  evidence: [
    { id: 'EVD-0001', name: 'memory_dump_host01.raw', type: 'memory', hash: 'sha256:a3f2bc9d...e891d4f7', source: 'Host 192.168.47.22', acquired: '2026-09-14 09:00', analyst: 'Analyst 01', size: '4.2 GB', chain: 'VERIFIED', notes: 'Full memory image via LiME kernel module' },
    { id: 'EVD-0002', name: 'network_capture_2026-09-14.pcap', type: 'network', hash: 'sha256:b91d2e3f...c748a1d2', source: 'Firewall TAP', acquired: '2026-09-14 10:30', analyst: 'Analyst 01', size: '892 MB', chain: 'VERIFIED', notes: '6-hour capture window during incident' },
    { id: 'EVD-0003', name: 'lockbit3_payload.exe', type: 'malware', hash: 'sha256:d8c1a0e4...7f3b2209', source: 'Quarantine — Endpoint01', acquired: '2026-09-20 07:15', analyst: 'Analyst 02', size: '1.2 MB', chain: 'VERIFIED', notes: 'LOCKBIT 3.0 variant, packed with UPX' },
    { id: 'EVD-0004', name: 'registry_hive_SOFTWARE', type: 'file', hash: 'sha256:f2e9c71b...0ab43d88', source: 'Disk Image — Workstation-04', acquired: '2026-09-21 14:22', analyst: 'Analyst 01', size: '48 MB', chain: 'VERIFIED', notes: 'Registry hive extracted from compromised system' },
    { id: 'EVD-0005', name: 'phish_kit_extraction.zip', type: 'file', hash: 'sha256:3e8fa19d...9c712b40', source: 'CDN Host Seizure', acquired: '2026-09-22 16:45', analyst: 'Analyst 03', size: '8.7 MB', chain: 'PENDING', notes: 'Phishing kit with credential stealer and proxy code' },
    { id: 'EVD-0006', name: 'smtp_logs_sept14-21.txt', type: 'file', hash: 'sha256:7a2bc08e...4f1d93ac', source: 'Mail Gateway', acquired: '2026-09-23 08:00', analyst: 'Analyst 01', size: '3.1 MB', chain: 'VERIFIED', notes: 'SMTP server logs covering incident window' },
  ],
  osintResults: [
    { module: 'DNS Records', count: 24, status: 'complete', findings: ['A: 104.21.35.67', 'MX: aspmx.l.google.com', 'TXT: v=spf1 include:_spf.google.com', 'NS: kate.ns.cloudflare.com'] },
    { module: 'Subdomains', count: 34, status: 'complete', findings: ['mail.example.com', 'api.example.com', 'admin.example.com', 'vpn.example.com', 'dev.example.com'] },
    { module: 'WHOIS', count: 1, status: 'complete', findings: ['Registrar: Cloudflare', 'Created: 2019-03-14', 'Expires: 2027-03-14', 'Registrant: REDACTED'] },
    { module: 'Technologies', count: 11, status: 'complete', findings: ['Nginx 1.25', 'React 18', 'Cloudflare CDN', 'Google Workspace', 'AWS S3'] },
    { module: 'Certificates', count: 8, status: 'complete', findings: ['Issuer: Let\'s Encrypt', 'SANs: example.com, *.example.com', 'Valid: 2026-07-01 to 2026-10-01'] },
    { module: 'Related Domains', count: 7, status: 'complete', findings: ['example.net', 'example.org', 'exampleinc.com'] },
    { module: 'Shodan', count: 3, status: 'complete', findings: ['Port 443 (HTTPS)', 'Port 80 (HTTP)', 'Port 22 (SSH)'] },
    { module: 'VirusTotal', count: 2, status: 'running', findings: ['0/94 malicious engines'] },
    { module: 'Katana Web Spider', count: 247, status: 'complete', findings: ['247 URLs crawled', '61 API endpoints', '4 CRITICAL findings', '6 hardcoded secrets'] },
  ],
  vulnerabilities: [
    { id: 'VUL-001', title: 'Exposed Admin Panel', severity: 'CRITICAL', cvss: 9.1, path: '/admin/', discovered: '2026-10-01', status: 'Open', tool: 'Nuclei' },
    { id: 'VUL-002', title: 'SQL Injection — Login Form', severity: 'CRITICAL', cvss: 9.8, path: '/login?id=1', discovered: '2026-10-02', status: 'Open', tool: 'Nuclei' },
    { id: 'VUL-003', title: 'Outdated Apache 2.4.51', severity: 'HIGH', cvss: 7.5, path: '/', discovered: '2026-10-01', status: 'Open', tool: 'Nmap' },
    { id: 'VUL-004', title: 'Cross-Site Scripting (XSS)', severity: 'HIGH', cvss: 7.2, path: '/search?q=', discovered: '2026-10-03', status: 'Open', tool: 'Nuclei' },
    { id: 'VUL-005', title: 'Directory Listing Enabled', severity: 'MEDIUM', cvss: 5.3, path: '/assets/', discovered: '2026-10-01', status: 'Open', tool: 'httpx' },
    { id: 'VUL-006', title: 'Weak SSL/TLS Config', severity: 'MEDIUM', cvss: 5.9, path: ':443', discovered: '2026-10-02', status: 'Open', tool: 'Nmap' },
    { id: 'VUL-007', title: 'CORS Misconfiguration', severity: 'LOW', cvss: 3.7, path: '/api/', discovered: '2026-10-04', status: 'Accepted', tool: 'httpx' },
    { id: 'VUL-008', title: 'HTTP Security Headers Missing', severity: 'LOW', cvss: 3.1, path: '/', discovered: '2026-10-01', status: 'Fixed', tool: 'httpx' },
  ],
  threats: [
    { actor: 'APT-29 (Cozy Bear)', origin: '🇷🇺 Russia', motivation: 'Espionage', confidence: 'HIGH', ttps: 'T1566, T1059, T1021', severity: 'CRITICAL', last_seen: '2026-10-07' },
    { actor: 'LOCKBIT 3.0 Affiliates', origin: '🌍 Unknown', motivation: 'Financial', confidence: 'HIGH', ttps: 'T1486, T1490, T1041', severity: 'CRITICAL', last_seen: '2026-09-20' },
    { actor: 'Scattered Spider', origin: '🇺🇸 USA/UK', motivation: 'Financial', confidence: 'MEDIUM', ttps: 'T1598, T1621, T1552', severity: 'HIGH', last_seen: '2026-09-30' },
    { actor: 'UNC2452', origin: '🇷🇺 Russia', motivation: 'Supply Chain', confidence: 'LOW', ttps: 'T1195, T1078, T1027', severity: 'HIGH', last_seen: '2026-10-03' },
  ],
  feedItems: [
    { color: '#ff3d3d', text: '<strong>CRITICAL:</strong> New C2 beacon activity from 185.220.101.45 detected on port 4444', time: '2m ago' },
    { color: '#ffb800', text: '<strong>IOC Match:</strong> evil-c2.ru resolved to known APT-29 infrastructure cluster', time: '8m ago' },
    { color: '#00d4ff', text: '<strong>OSINT:</strong> 3 new subdomains discovered during passive recon of example.com', time: '14m ago' },
    { color: '#ff6b35', text: '<strong>Vulnerability:</strong> SQL Injection confirmed on /login endpoint — CVSS 9.8', time: '22m ago' },
    { color: '#7b2ff7', text: '<strong>AI Analysis:</strong> Correlation identified between network anomalies and phishing campaign timeline', time: '31m ago' },
    { color: '#00ff9d', text: '<strong>Evidence:</strong> memory_dump_host01.raw successfully ingested and indexed', time: '45m ago' },
    { color: '#ffb800', text: '<strong>Threat Intel:</strong> MISP feed updated — 847 new IOCs ingested from CIRCL feed', time: '1h ago' },
    { color: '#ff3d3d', text: '<strong>DFIR:</strong> Volatility analysis identified 4 suspicious processes in memory dump', time: '1h 20m ago' },
  ],
  aiConversations: [
    {
      id: 'conv-001', title: 'example.com Investigation',
      msgs: [
        { role: 'ai', text: 'Intelligence collected for **example.com**. I\'ve identified **34 subdomains**, **12 associated IPs**, and **43 IOCs** linked to APT-29 infrastructure. The domain shows signs of being a target in an active phishing campaign. Shall I generate a full risk assessment?', time: '09:14 AM', cites: ['OSINT Engine', 'IOC Fusion'] },
        { role: 'user', text: 'Show all assets connected to this domain and which are highest priority.', time: '09:16 AM' },
        { role: 'ai', text: 'Based on collected evidence, the **highest priority assets** connected to example.com are:\n\n**1. admin.example.com** — Exposed admin panel (CVSS 9.1, Critical)\n**2. api.example.com** — SQL injection vector (CVSS 9.8, Critical)\n**3. 104.21.35.67** — Resolves to known APT-29 infrastructure\n**4. mail.example.com** — Origin of spear-phishing emails to 14 employees\n\nThese findings are based on active recon results and correlated IOCs. [FACT] All findings have supporting evidence in the Evidence Vault.', time: '09:16 AM', cites: ['Attack Surface', 'Evidence Vault', 'IOC Fusion'] },
      ]
    }
  ],
  notifications: [
    { icon: '🕷', iconClass: 'red', title: 'Katana — RCE Vector Found', desc: 'dev.example.com/debug?cmd= — blind command injection via crawl', time: 'Just now' },
    { icon: '⚠', iconClass: 'red', title: 'Critical IOC Match', desc: 'evil-c2.ru matched in live traffic on CASE-2026-0017', time: '2 minutes ago' },
    { icon: '🔍', iconClass: 'cyan', title: 'New Subdomains Found', desc: 'Subfinder discovered 3 new subdomains on example.com', time: '14 minutes ago' },
    { icon: '🧠', iconClass: 'amber', title: 'AI Insight Ready', desc: 'AI Investigator generated new correlation report', time: '31 minutes ago' },
    { icon: '📁', iconClass: 'cyan', title: 'Evidence Ingested', desc: 'memory_dump_host01.raw (4.2GB) processed successfully', time: '45 minutes ago' },
    { icon: '⚡', iconClass: 'red', title: 'New Vulnerability', desc: 'SQL Injection CVSS 9.8 confirmed on /login endpoint', time: '1 hour ago' },
  ],
};

// ══════════ SPLASH SCREEN ══════════
const BOOT_STEPS = [
  { msg: 'Initializing INTELFUSE X core...', pct: 5 },
  { msg: 'Loading OSINT engine modules...', pct: 15 },
  { msg: 'Connecting MISP threat intelligence feed...', pct: 25 },
  { msg: 'Initializing Nuclei scan engine...', pct: 35 },
  { msg: 'Loading forensics workbench (Volatility, YARA)...', pct: 45 },
  { msg: 'Connecting AI investigator (GPT-4 RAG pipeline)...', pct: 55 },
  { msg: 'Importing evidence vault (127 artifacts)...', pct: 65 },
  { msg: 'Building investigation graph index...', pct: 75 },
  { msg: 'Syncing STIX/TAXII threat feeds...', pct: 85 },
  { msg: 'Verifying chain-of-custody records...', pct: 93 },
  { msg: 'All systems nominal. Welcome, Analyst 01.', pct: 100 },
];
const MODULES = ['OSINT', 'DFIR', 'IOC', 'GRAPH', 'AI', 'THREAT-INTEL', 'EVIDENCE', 'NUCLEI', 'VOLATILITY', 'MISP', 'YARA', 'STIX'];

function bootSplash() {
  // Particles
  const container = document.getElementById('splash-particles');
  for (let i = 0; i < 30; i++) {
    const p = document.createElement('div');
    p.className = 'splash-particle';
    const size = Math.random() * 4 + 2;
    p.style.cssText = `width:${size}px;height:${size}px;left:${Math.random()*100}%;animation-duration:${Math.random()*8+6}s;animation-delay:${Math.random()*6}s;opacity:${Math.random()*0.5+0.1}`;
    container.appendChild(p);
  }

  // Boot sequence
  let step = 0;
  const fill = document.getElementById('loader-fill');
  const status = document.getElementById('loader-status');
  const modulesEl = document.getElementById('splash-modules');

  function nextStep() {
    if (step >= BOOT_STEPS.length) {
      setTimeout(launchApp, 600);
      return;
    }
    const s = BOOT_STEPS[step];
    fill.style.width = s.pct + '%';
    status.textContent = s.msg;

    // Add a module tag
    if (step < MODULES.length) {
      const m = document.createElement('div');
      m.className = 'splash-module';
      m.textContent = MODULES[step];
      m.style.animationDelay = '0s';
      modulesEl.appendChild(m);
    }
    step++;
    setTimeout(nextStep, step === BOOT_STEPS.length ? 200 : 320 + Math.random() * 180);
  }
  setTimeout(nextStep, 400);
}

function launchApp() {
  const splash = document.getElementById('splash-screen');
  splash.classList.add('exiting');
  setTimeout(() => {
    splash.remove();
    document.getElementById('app').classList.remove('hidden');
    initApp();
  }, 800);
}

// ══════════ APP INIT ══════════
function initApp() {
  initClock();
  initNotifications();
  renderPage('dashboard');
  initKeyboard();
}

function initClock() {
  function tick() {
    const now = new Date();
    const t = now.toTimeString().slice(0, 8);
    const el = document.getElementById('sidebar-time');
    if (el) el.textContent = t;
  }
  tick();
  setInterval(tick, 1000);
}

function initNotifications() {
  const list = document.getElementById('notif-list');
  DATA.notifications.forEach(n => {
    const el = document.createElement('div');
    el.className = 'notif-item';
    el.innerHTML = `
      <div class="notif-icon ${n.iconClass}">${n.icon}</div>
      <div class="notif-body">
        <div class="notif-title">${n.title}</div>
        <div class="notif-desc">${n.desc}</div>
        <div class="notif-time">${n.time}</div>
      </div>`;
    list.appendChild(el);
  });
}

function toggleNotifications() {
  document.getElementById('notification-panel').classList.toggle('hidden');
}

function toggleSidebar() {
  STATE.sidebarCollapsed = !STATE.sidebarCollapsed;
  document.getElementById('sidebar').classList.toggle('collapsed', STATE.sidebarCollapsed);
}

function initKeyboard() {
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      document.getElementById('global-search-input').focus();
    }
    if (e.key === 'Escape') {
      closeModal();
      document.getElementById('notification-panel').classList.add('hidden');
    }
  });
}

// ══════════ PAGE ROUTING ══════════
const PAGE_TITLES = {
  dashboard: 'Mission Control',
  cases: 'Case Management',
  graph: 'Investigation Graph',
  osint: 'OSINT Engine',
  cyber: 'Attack Surface',
  katana: 'Katana Web Spider',
  threat: 'Threat Intelligence',
  ioc: 'IOC Fusion',
  dfir: 'DFIR Workbench',
  evidence: 'Evidence Vault',
  timeline: 'Event Timeline',
  ai: 'AI Investigator',
  report: 'Intel Reports',
};

function showPage(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(`page-${page}`).classList.add('active');
  document.getElementById(`nav-${page}`)?.classList.add('active');
  document.getElementById('breadcrumb').textContent = PAGE_TITLES[page] || page;
  STATE.currentPage = page;
  renderPage(page);
}

function renderPage(page) {
  const container = document.getElementById(`page-${page}`);
  if (!container || container.dataset.rendered === '1') return;
  container.dataset.rendered = '1';

  switch (page) {
    case 'dashboard': renderDashboard(container); break;
    case 'cases': renderCases(container); break;
    case 'graph': renderGraph(container); break;
    case 'osint': renderOSINT(container); break;
    case 'cyber': renderCyber(container); break;
    case 'katana': renderKatana(container); break;
    case 'threat': renderThreat(container); break;
    case 'ioc': renderIOC(container); break;
    case 'dfir': renderDFIR(container); break;
    case 'evidence': renderEvidence(container); break;
    case 'timeline': renderTimeline(container); break;
    case 'ai': renderAI(container); break;
    case 'report': renderReport(container); break;
  }
}

// ══════════ ICON HELPERS ══════════
const ICONS = {
  shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  search: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>`,
  file: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`,
  network: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><line x1="12" y1="8" x2="5" y2="16"/><line x1="12" y1="8" x2="19" y2="16"/></svg>`,
  cpu: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>`,
  alert: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  activity: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
  box: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/></svg>`,
  brain: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9.5 2a2.5 2.5 0 010 5H12a2.5 2.5 0 010 5 2.5 2.5 0 010 5H9.5a2.5 2.5 0 010-5"/><path d="M14.5 7A2.5 2.5 0 0117 4.5a2.5 2.5 0 012.5 2.5A2.5 2.5 0 0117 9.5"/><path d="M14.5 17a2.5 2.5 0 002.5 2.5 2.5 2.5 0 002.5-2.5 2.5 2.5 0 00-2.5-2.5"/></svg>`,
  send: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>`,
  download: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  plus: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  eye: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  zap: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  refresh: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>`,
  link: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>`,
  globe: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>`,
};

function icon(name, extra = '') { return `<span class="card-title-icon" ${extra}>${ICONS[name] || ''}</span>`; }

// ══════════ DASHBOARD ══════════
function renderDashboard(el) {
  const case_ = DATA.cases[0];
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div>
      <div class="page-title">Mission Control</div>
      <div class="page-subtitle">Active operations overview — ${new Date().toLocaleDateString('en-US', {weekday:'long',year:'numeric',month:'long',day:'numeric'})}</div>
    </div>
    <div class="page-actions">
      <button class="btn btn-secondary" onclick="showPage('report')">${ICONS.file} Generate Report</button>
      <button class="btn btn-primary" onclick="showPage('cases')">${ICONS.plus} New Case</button>
    </div>
  </div>

  <!-- CASE BANNER -->
  <div class="card fade-in-up" style="margin-bottom:20px;border-color:rgba(255,61,61,0.3);background:linear-gradient(135deg, rgba(255,61,61,0.06), var(--bg-card))">
    <div class="card-body" style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">
      <div style="flex:1;min-width:200px">
        <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);margin-bottom:4px">ACTIVE PRIORITY CASE</div>
        <div style="font-family:var(--font-display);font-size:1.3rem;font-weight:700;color:var(--text-primary)">CASE-2026-0017</div>
        <div style="font-size:0.82rem;color:var(--text-secondary);margin-top:2px">Subject: <span class="glow-cyan">example.com</span> — APT-29 infrastructure linkage confirmed</div>
      </div>
      <div style="display:flex;gap:24px;flex-wrap:wrap">
        ${[['Evidence','127','cyan'],['IOCs','43','red'],['Findings','18','amber'],['Risk','HIGH','red']].map(([k,v,c])=>`<div style="text-align:center"><div style="font-family:var(--font-display);font-size:1.6rem;font-weight:700;color:var(--${c})">${v}</div><div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-muted)">${k}</div></div>`).join('')}
      </div>
      <button class="btn btn-danger" onclick="showPage('graph')">View Investigation Graph &rarr;</button>
    </div>
  </div>

  <!-- STATS -->
  <div class="stats-grid fade-in-up">
    ${statCard('ACTIVE CASES', '7', 'cyan', '+2 this week', 'up', 'shield')}
    ${statCard('TOTAL IOCs', '43', 'red', '↑ 8 new today', 'up', 'alert')}
    ${statCard('VULNERABILITIES', '12', 'amber', '2 critical open', 'down', 'zap')}
    ${statCard('EVIDENCE ITEMS', '127', 'purple', 'All verified', '', 'box')}
    ${statCard('AI INSIGHTS', '31', 'green', '5 unreviewed', 'up', 'brain')}
    ${statCard('THREAT ACTORS', '4', 'red', 'APT-29 active', 'down', 'eye')}
  </div>

  <div class="grid-2 fade-in-up" style="margin-bottom:16px">
    <!-- LIVE INTEL FEED -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">${icon('activity')} Live Intel Feed</div>
        <div style="display:flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:0.65rem;color:var(--green)"><div class="status-dot active"></div>LIVE</div>
      </div>
      <div class="card-body" style="padding:12px">
        <div class="live-feed">
          ${DATA.feedItems.map(f=>`
          <div class="feed-item">
            <div class="feed-dot" style="background:${f.color}"></div>
            <div class="feed-text">${f.text}</div>
            <div class="feed-time">${f.time}</div>
          </div>`).join('')}
        </div>
      </div>
    </div>

    <!-- RIGHT COLUMN -->
    <div style="display:flex;flex-direction:column;gap:16px">
      <!-- THREAT ACTORS -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">${icon('alert')} Active Threat Actors</div>
          <button class="btn btn-secondary" style="padding:4px 10px;font-size:0.7rem" onclick="showPage('threat')">View All</button>
        </div>
        <div class="card-body" style="padding:0">
          ${DATA.threats.map(t=>`
          <div class="feed-item" style="border-bottom:1px solid rgba(255,255,255,0.04)">
            <div>
              <div style="font-size:0.8rem;font-weight:600;color:var(--text-primary)">${t.actor}</div>
              <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted)">${t.origin} · ${t.motivation}</div>
            </div>
            <div style="margin-left:auto"><span class="badge ${t.severity==='CRITICAL'?'badge-critical':'badge-high'}">${t.severity}</span></div>
          </div>`).join('')}
        </div>
      </div>

      <!-- RISK BREAKDOWN -->
      <div class="card">
        <div class="card-header"><div class="card-title">${icon('zap')} Vulnerability Breakdown</div></div>
        <div class="card-body">
          ${[['CRITICAL',2,'var(--red)',100],['HIGH',4,'var(--orange)',80],['MEDIUM',4,'var(--amber)',60],['LOW',2,'var(--cyan)',30]].map(([label,count,color,pct])=>`
          <div style="margin-bottom:12px">
            <div style="display:flex;justify-content:space-between;margin-bottom:5px">
              <span style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-secondary)">${label}</span>
              <span style="font-family:var(--font-mono);font-size:0.65rem;font-weight:700;color:${color}">${count}</span>
            </div>
            <div class="progress-bar"><div class="progress-fill" style="width:${pct}%;background:${color}"></div></div>
          </div>`).join('')}
        </div>
      </div>
    </div>
  </div>

  <!-- RECENT CASES -->
  <div class="card fade-in-up">
    <div class="card-header">
      <div class="card-title">${icon('file')} Recent Cases</div>
      <button class="btn btn-secondary" style="padding:4px 10px;font-size:0.7rem" onclick="showPage('cases')">All Cases</button>
    </div>
    <div style="overflow-x:auto">
      <table class="data-table">
        <thead><tr><th>Case ID</th><th>Subject</th><th>Status</th><th>Risk</th><th>Evidence</th><th>Investigator</th><th>Opened</th><th>Action</th></tr></thead>
        <tbody>
          ${DATA.cases.slice(0,5).map(c=>`
          <tr onclick="showPage('cases')" style="cursor:pointer">
            <td class="mono">${c.id}</td>
            <td style="color:var(--cyan);font-weight:600">${c.subject}</td>
            <td><span class="badge ${c.status==='Active'?'badge-critical':c.status==='Pending'?'badge-medium':'badge-safe'}">${c.status}</span></td>
            <td><span class="badge ${c.riskClass}">${c.riskLevel}</span></td>
            <td class="mono">${c.evidence}</td>
            <td>${c.investigator}</td>
            <td style="font-family:var(--font-mono);font-size:0.72rem">${c.opened}</td>
            <td><button class="btn btn-secondary" style="padding:3px 10px;font-size:0.7rem" onclick="event.stopPropagation();showPage('graph')">Graph</button></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>`;
}

function statCard(label, value, color, change, dir, iconName) {
  return `<div class="stat-card ${color} fade-in-up">
    <div class="stat-label">${label}</div>
    <div class="stat-value">${value}</div>
    <div class="stat-change ${dir}">${change}</div>
    <div class="stat-bg-icon">${ICONS[iconName]||''}</div>
  </div>`;
}

// ══════════ CASE MANAGEMENT ══════════
function renderCases(el) {
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div>
      <div class="page-title">Case Management</div>
      <div class="page-subtitle">Manage and track active cyber investigations</div>
    </div>
    <div class="page-actions">
      <input type="text" class="input-field" style="width:220px;height:36px;margin:0" placeholder="Filter cases..." />
      <select class="input-field" style="width:130px;height:36px;margin:0">
        <option>All Statuses</option><option>Active</option><option>Pending</option><option>Closed</option>
      </select>
      <button class="btn btn-primary" onclick="openNewCaseModal()">${ICONS.plus} New Case</button>
    </div>
  </div>

  <!-- SUMMARY STRIP -->
  <div class="stats-grid fade-in-up" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px">
    ${statCard('TOTAL CASES','7','cyan','','','file')}
    ${statCard('ACTIVE','2','red','2 critical','down','alert')}
    ${statCard('PENDING','2','amber','1 awaiting','','zap')}
    ${statCard('CLOSED','3','green','Resolved','up','shield')}
  </div>

  <!-- CASE CARDS -->
  <div class="grid-auto fade-in-up">
    ${DATA.cases.map(c=>caseCard(c)).join('')}
  </div>`;
}

function caseCard(c) {
  return `
  <div class="case-card ${c.statusClass} fade-in-up" onclick="openCaseDetail('${c.id}')">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
      <div class="case-id">${c.id}</div>
      <span class="badge ${c.riskClass}"><span class="badge-dot"></span>${c.riskLevel}</span>
    </div>
    <div class="case-subject">${c.subject}</div>
    <div class="case-meta">
      <div class="case-meta-item">${ICONS.shield}<span>${c.status}</span></div>
      <div class="case-meta-item">${ICONS.search}<span>${c.investigator}</span></div>
      <div class="case-meta-item">${ICONS.file}<span>${c.opened}</span></div>
    </div>
    <div style="font-size:0.75rem;color:var(--text-secondary);line-height:1.5;margin:8px 0">${c.description}</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px">
      ${c.tags.map(t=>`<span class="msg-tag">${t}</span>`).join('')}
    </div>
    <div class="case-stats">
      <div class="case-stat"><span class="case-stat-val">${c.evidence}</span><span class="case-stat-key">Evidence</span></div>
      <div class="case-stat"><span class="case-stat-val" style="color:var(--red)">${c.iocs}</span><span class="case-stat-key">IOCs</span></div>
      <div class="case-stat"><span class="case-stat-val" style="color:var(--amber)">${c.findings}</span><span class="case-stat-key">Findings</span></div>
    </div>
    <div style="display:flex;gap:6px;margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
      <button class="btn btn-secondary" style="flex:1;font-size:0.72rem;padding:5px" onclick="event.stopPropagation();showPage('graph')">Investigation Graph</button>
      <button class="btn btn-primary" style="flex:1;font-size:0.72rem;padding:5px" onclick="event.stopPropagation();showPage('ai')">AI Analysis</button>
    </div>
  </div>`;
}

function openCaseDetail(id) {
  const c = DATA.cases.find(x => x.id === id);
  if (!c) return;
  openModal(`Case: ${c.id}`, `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
      ${[['Case ID',c.id],['Subject',c.subject],['Status',c.status],['Risk Level',c.riskLevel],['Investigator',c.investigator],['Opened',c.opened]].map(([k,v])=>`<div><div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:4px">${k}</div><div style="font-weight:600;color:var(--text-primary)">${v}</div></div>`).join('')}
    </div>
    <div style="margin-bottom:16px">
      <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:6px">DESCRIPTION</div>
      <div style="font-size:0.82rem;color:var(--text-secondary);line-height:1.6">${c.description}</div>
    </div>
    <div style="display:flex;gap:24px;padding:14px;background:var(--bg-secondary);border-radius:var(--radius-sm);margin-bottom:16px">
      ${[['Evidence Items',c.evidence,'cyan'],['IOCs Tracked',c.iocs,'red'],['Findings',c.findings,'amber'],['Subdomains',c.subdomains,'purple'],['IPs Identified',c.ips,'green']].map(([k,v,col])=>`<div style="text-align:center;flex:1"><div style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;color:var(--${col})">${v}</div><div style="font-family:var(--font-mono);font-size:0.58rem;color:var(--text-muted)">${k}</div></div>`).join('')}
    </div>
    <div>
      <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:6px">TAGS</div>
      ${c.tags.map(t=>`<span class="msg-tag">${t}</span>`).join(' ')}
    </div>`,
    [
      { label: 'Investigation Graph', action: () => { closeModal(); showPage('graph'); }, primary: true },
      { label: 'Close', action: closeModal },
    ]
  );
}

function openNewCaseModal() {
  openModal('Create New Case', `
    <div class="input-group"><label class="input-label">CASE SUBJECT (Domain / IP / Entity)</label><input class="input-field input-field-mono" placeholder="e.g. evil-corp.com" /></div>
    <div class="input-group"><label class="input-label">DESCRIPTION</label><textarea class="input-field" rows="3" placeholder="Brief description of the investigation..."></textarea></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div class="input-group"><label class="input-label">ASSIGNED ANALYST</label><select class="input-field"><option>Analyst 01</option><option>Analyst 02</option><option>Analyst 03</option></select></div>
      <div class="input-group"><label class="input-label">INITIAL RISK LEVEL</label><select class="input-field"><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div>
    </div>
    <div class="input-group"><label class="input-label">INITIAL TAGS (comma-separated)</label><input class="input-field" placeholder="APT, Phishing, C2..." /></div>`,
    [
      { label: 'Create Case & Start OSINT Scan', action: () => { closeModal(); showPage('osint'); }, primary: true },
      { label: 'Cancel', action: closeModal },
    ]
  );
}

// ══════════ INVESTIGATION GRAPH ══════════
function renderGraph(el) {
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div>
      <div class="page-title">Investigation Graph</div>
      <div class="page-subtitle">Interactive relationship map — CASE-2026-0017 / example.com</div>
    </div>
    <div class="page-actions">
      <select class="input-field" style="width:200px;height:36px;margin:0" onchange="changeGraphSubject(this.value)">
        <option>example.com (CASE-2026-0017)</option>
        <option>corp-vpn.net (CASE-2026-0014)</option>
        <option>192.168.47.22 (CASE-2026-0011)</option>
      </select>
      <button class="btn btn-secondary" onclick="expandAllNodes()">Expand All</button>
      <button class="btn btn-primary" onclick="exportGraph()">${ICONS.download} Export</button>
    </div>
  </div>

  <div style="display:flex;gap:16px;height:calc(100vh - 230px);min-height:500px">
    <!-- GRAPH CANVAS -->
    <div id="graph-canvas-container" style="flex:1;position:relative">
      <svg id="graph-svg" xmlns="http://www.w3.org/2000/svg"></svg>
      <div class="graph-controls">
        <button class="graph-ctrl-btn" onclick="zoomGraph(1.2)" title="Zoom In">+</button>
        <button class="graph-ctrl-btn" onclick="zoomGraph(0.8)" title="Zoom Out">−</button>
        <button class="graph-ctrl-btn" onclick="resetGraphView()" title="Reset">⟳</button>
        <button class="graph-ctrl-btn" onclick="fitGraph()" title="Fit">⊙</button>
      </div>
      <div class="graph-legend">
        ${[['#00d4ff','Domain/IP'],['#7b2ff7','Service/Tech'],['#ff3d3d','IOC/Finding'],['#ffb800','Evidence'],['#00ff9d','Clean']].map(([c,l])=>`<div class="legend-item"><div class="legend-dot" style="background:${c}"></div>${l}</div>`).join('')}
      </div>
      <div class="node-detail-panel hidden" id="node-detail-panel">
        <div class="ndp-header"><span id="ndp-title">Node Details</span><button onclick="closeNodePanel()" style="color:var(--text-muted)">✕</button></div>
        <div class="ndp-body" id="ndp-body"></div>
      </div>
    </div>

    <!-- SIDE PANEL -->
    <div style="width:260px;display:flex;flex-direction:column;gap:12px;flex-shrink:0">
      <div class="card" style="flex:0 0 auto">
        <div class="card-header"><div class="card-title">${icon('search')} Quick Add Node</div></div>
        <div class="card-body" style="padding:12px">
          <input id="add-node-input" class="input-field input-field-mono" placeholder="domain / IP / hash" style="margin-bottom:8px"/>
          <select id="add-node-type" class="input-field" style="margin-bottom:8px">
            <option value="domain">Domain</option><option value="ip">IP Address</option>
            <option value="hash">File Hash</option><option value="email">Email</option>
            <option value="url">URL</option><option value="actor">Threat Actor</option>
          </select>
          <button class="btn btn-primary" style="width:100%" onclick="addNodeFromInput()">Add to Graph</button>
        </div>
      </div>

      <div class="card" style="flex:1;overflow:hidden;display:flex;flex-direction:column">
        <div class="card-header"><div class="card-title">${icon('activity')} Graph Stats</div></div>
        <div class="card-body" style="padding:12px">
          ${[['Nodes','24','cyan'],['Edges','38','purple'],['IOCs','8','red'],['Domains','12','cyan'],['IPs','6','amber']].map(([k,v,c])=>`
          <div style="display:flex;justify-content:space-between;margin-bottom:8px;font-size:0.78rem">
            <span style="color:var(--text-secondary)">${k}</span>
            <span style="font-family:var(--font-mono);font-weight:700;color:var(--${c})">${v}</span>
          </div>`).join('')}
        </div>
      </div>

      <div class="card" style="flex:0 0 auto">
        <div class="card-header"><div class="card-title">${icon('zap')} Top Findings</div></div>
        <div class="card-body" style="padding:12px">
          ${DATA.vulnerabilities.slice(0,4).map(v=>`
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:0.75rem">
            <span class="badge ${v.severity==='CRITICAL'?'badge-critical':v.severity==='HIGH'?'badge-high':'badge-medium'}" style="font-size:0.55rem">${v.severity}</span>
            <span style="color:var(--text-secondary);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${v.title}</span>
          </div>`).join('')}
        </div>
      </div>
    </div>
  </div>`;

  setTimeout(() => initGraphVisualization(), 100);
}

// Graph Visualization Engine
function initGraphVisualization() {
  const svg = document.getElementById('graph-svg');
  if (!svg) return;
  const container = document.getElementById('graph-canvas-container');
  const W = container.clientWidth || 800;
  const H = container.clientHeight || 600;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('width', W);
  svg.setAttribute('height', H);

  // Define nodes
  const CX = W / 2, CY = H / 2;
  const nodeTypes = {
    domain: { color: '#00d4ff', r: 18, stroke: '#00d4ff' },
    ip: { color: '#7b2ff7', r: 14, stroke: '#7b2ff7' },
    tech: { color: '#7b2ff7', r: 12, stroke: '#7b2ff7' },
    subdomain: { color: '#0099bb', r: 11, stroke: '#0099bb' },
    ioc: { color: '#ff3d3d', r: 13, stroke: '#ff3d3d' },
    finding: { color: '#ff6b35', r: 12, stroke: '#ff6b35' },
    evidence: { color: '#ffb800', r: 11, stroke: '#ffb800' },
    actor: { color: '#ff2d78', r: 15, stroke: '#ff2d78' },
    url: { color: '#00ff9d', r: 10, stroke: '#00ff9d' },
  };

  const nodes = [
    // ROOT
    { id: 'root', label: 'example.com', type: 'domain', x: CX, y: CY, detail: { Type:'Domain', Resolved:'104.21.35.67', Registrar:'Cloudflare', Status:'Active', Risk:'HIGH' } },
    // IPs
    { id: 'ip1', label: '104.21.35.67', type: 'ip', x: CX-200, y: CY-80, detail: { Type:'IP', ASN:'AS13335 Cloudflare', Country:'US', Open_Ports:'80,443' } },
    { id: 'ip2', label: '172.67.182.94', type: 'ip', x: CX+200, y: CY-80, detail: { Type:'IP', ASN:'AS13335 Cloudflare', Country:'US', Open_Ports:'80,443' } },
    { id: 'ip3', label: '185.220.101.45', type: 'ioc', x: CX, y: CY-220, detail: { Type:'IP', Threat:'TOR Exit Node', Confidence:'88%', Status:'MALICIOUS' } },
    // Subdomains
    { id: 'sub1', label: 'mail.example.com', type: 'subdomain', x: CX-280, y: CY+120, detail: { Type:'Subdomain', Resolved:'104.21.35.67', Services:'SMTP,IMAP' } },
    { id: 'sub2', label: 'admin.example.com', type: 'subdomain', x: CX-160, y: CY+200, detail: { Type:'Subdomain', Finding:'Exposed admin panel CVSS 9.1', Status:'VULNERABLE' } },
    { id: 'sub3', label: 'api.example.com', type: 'subdomain', x: CX+160, y: CY+200, detail: { Type:'Subdomain', Finding:'SQLi CVSS 9.8', Status:'VULNERABLE' } },
    { id: 'sub4', label: 'vpn.example.com', type: 'subdomain', x: CX+280, y: CY+120, detail: { Type:'Subdomain', Status:'Active', Services:'OpenVPN 2.4.x' } },
    { id: 'sub5', label: 'dev.example.com', type: 'subdomain', x: CX-60, y: CY+240, detail: { Type:'Subdomain', Status:'Exposed', Tech:'React Dev Server' } },
    // Technologies
    { id: 'tech1', label: 'Cloudflare CDN', type: 'tech', x: CX-320, y: CY-30, detail: { Type:'Technology', Version:'Enterprise', Risk:'LOW' } },
    { id: 'tech2', label: 'Google Workspace', type: 'tech', x: CX+320, y: CY-30, detail: { Type:'Technology', Services:'Gmail,Drive,Meet' } },
    { id: 'tech3', label: 'AWS S3', type: 'tech', x: CX+240, y: CY-180, detail: { Type:'Technology', Buckets:'3 discovered', Risk:'MEDIUM', Note:'Public bucket found' } },
    // IOCs
    { id: 'ioc1', label: 'evil-c2.ru', type: 'ioc', x: CX-100, y: CY-280, detail: { Type:'C2 Domain', Threat:'APT-29', Confidence:'95%', Status:'MALICIOUS' } },
    { id: 'ioc2', label: 'a3f2bc...e891d4', type: 'ioc', x: CX+100, y: CY-260, detail: { Type:'File Hash (SHA256)', Threat:'LOCKBIT 3.0', Confidence:'99%', Status:'MALICIOUS' } },
    // Threat Actor
    { id: 'actor1', label: 'APT-29', type: 'actor', x: CX-200, y: CY-200, detail: { Type:'Threat Actor', Origin:'Russia', Motivation:'Espionage', TTPs:'T1566,T1059' } },
    // URLs
    { id: 'url1', label: 'hxxps://phish.evil/login', type: 'url', x: CX+60, y: CY-180, detail: { Type:'Phishing URL', Confidence:'76%', Status:'ACTIVE', Redirects_to:'Credential Harvester' } },
    // Evidence
    { id: 'evd1', label: 'network_capture.pcap', type: 'evidence', x: CX-360, y: CY+60, detail: { Type:'PCAP Evidence', Size:'892 MB', Chain:'VERIFIED', SHA256:'b91d2e3f...c748a1d2' } },
  ];

  const edges = [
    // Root connections
    { from: 'root', to: 'ip1' }, { from: 'root', to: 'ip2' },
    { from: 'root', to: 'sub1' }, { from: 'root', to: 'sub2' },
    { from: 'root', to: 'sub3' }, { from: 'root', to: 'sub4' }, { from: 'root', to: 'sub5' },
    { from: 'root', to: 'tech1' }, { from: 'root', to: 'tech2' },
    { from: 'ip1', to: 'tech1' }, { from: 'ip2', to: 'tech2' },
    { from: 'tech2', to: 'tech3' },
    { from: 'tech3', to: 'ioc2' },
    // IOC Connections
    { from: 'ip3', to: 'ioc1', dashed: true }, { from: 'ioc1', to: 'actor1', dashed: true },
    { from: 'ip3', to: 'actor1', dashed: true },
    { from: 'url1', to: 'ioc1', dashed: true },
    { from: 'sub2', to: 'ioc2' }, { from: 'sub3', to: 'ioc2' },
    // Evidence
    { from: 'sub1', to: 'evd1' }, { from: 'ip1', to: 'evd1' },
    // C2
    { from: 'root', to: 'ip3', dashed: true },
    { from: 'root', to: 'url1', dashed: true },
  ];

  STATE.graphNodes = nodes;
  STATE.graphEdges = edges;

  // Build SVG
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = `
    <filter id="glow-cyan"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <filter id="glow-red"><feGaussianBlur stdDeviation="4" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="rgba(0,212,255,0.3)"/></marker>
    <radialGradient id="bgGrad"><stop offset="0%" stop-color="#070f1f"/><stop offset="100%" stop-color="#030812"/></radialGradient>`;
  svg.appendChild(defs);

  // Background
  const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  bg.setAttribute('width', W); bg.setAttribute('height', H);
  bg.setAttribute('fill', 'url(#bgGrad)');
  svg.appendChild(bg);

  // Grid dots
  const grid = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  for (let gx = 0; gx < W; gx += 40) {
    for (let gy = 0; gy < H; gy += 40) {
      const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      dot.setAttribute('cx', gx); dot.setAttribute('cy', gy);
      dot.setAttribute('r', '0.8'); dot.setAttribute('fill', 'rgba(0,212,255,0.06)');
      grid.appendChild(dot);
    }
  }
  svg.appendChild(grid);

  const mainG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  mainG.id = 'graph-main-g';
  svg.appendChild(mainG);

  // Draw edges
  const edgesG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  edges.forEach(e => {
    const from = nodes.find(n => n.id === e.from);
    const to = nodes.find(n => n.id === e.to);
    if (!from || !to) return;
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', from.x); line.setAttribute('y1', from.y);
    line.setAttribute('x2', to.x); line.setAttribute('y2', to.y);
    line.setAttribute('stroke', e.dashed ? 'rgba(255,61,61,0.25)' : 'rgba(0,212,255,0.2)');
    line.setAttribute('stroke-width', '1');
    if (e.dashed) line.setAttribute('stroke-dasharray', '4,4');
    line.setAttribute('marker-end', 'url(#arrow)');
    edgesG.appendChild(line);
  });
  mainG.appendChild(edgesG);

  // Draw nodes
  const nodesG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  nodes.forEach(n => {
    const nt = nodeTypes[n.type] || nodeTypes.domain;
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('transform', `translate(${n.x},${n.y})`);
    g.classList.add('graph-node');
    g.dataset.nodeId = n.id;

    // Glow circle
    const glow = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    glow.setAttribute('r', nt.r + 8);
    glow.setAttribute('fill', nt.color);
    glow.setAttribute('opacity', '0.08');
    g.appendChild(glow);

    // Main circle
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('r', nt.r);
    circle.setAttribute('fill', nt.color + '22');
    circle.setAttribute('stroke', nt.stroke);
    circle.setAttribute('stroke-width', n.id === 'root' ? '2.5' : '1.5');
    if (n.type === 'ioc' || n.type === 'actor') {
      circle.setAttribute('filter', 'url(#glow-red)');
    } else if (n.id === 'root') {
      circle.setAttribute('filter', 'url(#glow-cyan)');
    }
    g.appendChild(circle);

    // Icon text (1-2 chars)
    const abbr = n.label.slice(0, 2).toUpperCase();
    const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    txt.setAttribute('text-anchor', 'middle');
    txt.setAttribute('dominant-baseline', 'central');
    txt.setAttribute('fill', nt.color);
    txt.setAttribute('font-family', 'JetBrains Mono, monospace');
    txt.setAttribute('font-size', Math.max(8, nt.r * 0.65));
    txt.setAttribute('font-weight', '700');
    txt.textContent = abbr;
    g.appendChild(txt);

    // Label below
    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('y', nt.r + 14);
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('fill', 'rgba(180,200,220,0.75)');
    label.setAttribute('font-family', 'JetBrains Mono, monospace');
    label.setAttribute('font-size', '9');
    label.textContent = n.label.length > 18 ? n.label.slice(0, 16) + '…' : n.label;
    g.appendChild(label);

    g.addEventListener('click', () => selectNode(n));
    nodesG.appendChild(g);
  });
  mainG.appendChild(nodesG);

  // Pan & zoom
  let isPanning = false, panStart = { x: 0, y: 0 }, panOffset = { x: 0, y: 0 };
  STATE.graphScale = 1; STATE.graphOffsetX = 0; STATE.graphOffsetY = 0;

  svg.addEventListener('mousedown', e => {
    isPanning = true;
    panStart = { x: e.clientX - panOffset.x, y: e.clientY - panOffset.y };
    svg.style.cursor = 'grabbing';
  });
  window.addEventListener('mousemove', e => {
    if (!isPanning) return;
    panOffset.x = e.clientX - panStart.x;
    panOffset.y = e.clientY - panStart.y;
    updateGraphTransform();
  });
  window.addEventListener('mouseup', () => { isPanning = false; svg.style.cursor = 'grab'; });
  svg.addEventListener('wheel', e => {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 1.1 : 0.9;
    STATE.graphScale = Math.min(3, Math.max(0.3, STATE.graphScale * delta));
    updateGraphTransform();
  });

  function updateGraphTransform() {
    mainG.setAttribute('transform', `translate(${panOffset.x},${panOffset.y}) scale(${STATE.graphScale})`);
  }

  window.zoomGraph = (factor) => { STATE.graphScale = Math.min(3, Math.max(0.3, STATE.graphScale * factor)); updateGraphTransform(); };
  window.resetGraphView = () => { STATE.graphScale = 1; panOffset = { x: 0, y: 0 }; updateGraphTransform(); };
  window.fitGraph = () => { STATE.graphScale = 0.75; panOffset = { x: 0, y: 0 }; updateGraphTransform(); };
  window.expandAllNodes = () => {};
  window.exportGraph = () => alert('Graph exported as SVG/PNG (feature in production version)');
  window.changeGraphSubject = () => {};
  window.addNodeFromInput = () => {
    const val = document.getElementById('add-node-input').value.trim();
    const type = document.getElementById('add-node-type').value;
    if (!val) return;
    // Simulate adding
    document.getElementById('add-node-input').value = '';
    showToast(`Node "${val}" (${type}) added to graph`);
  };
}

function selectNode(n) {
  const panel = document.getElementById('node-detail-panel');
  const title = document.getElementById('ndp-title');
  const body = document.getElementById('ndp-body');
  panel.classList.remove('hidden');
  title.textContent = n.label;
  const nt = { domain:'#00d4ff', ip:'#7b2ff7', subdomain:'#0099bb', ioc:'#ff3d3d', tech:'#7b2ff7', actor:'#ff2d78', evidence:'#ffb800', url:'#00ff9d' };
  body.innerHTML = `
    <div style="display:inline-block;padding:3px 10px;border-radius:3px;background:rgba(${n.type==='ioc'?'255,61,61':'0,212,255'},0.12);color:${nt[n.type]||'#00d4ff'};font-family:var(--font-mono);font-size:0.65rem;margin-bottom:10px">${n.type.toUpperCase()}</div>
    ${Object.entries(n.detail||{}).map(([k,v])=>`<div class="ndp-row"><div class="ndp-key">${k}</div><div class="ndp-val" style="font-family:var(--font-mono);font-size:0.7rem">${v}</div></div>`).join('')}
    <div style="margin-top:12px;display:flex;gap:6px">
      <button class="btn btn-secondary" style="flex:1;font-size:0.68rem;padding:5px" onclick="showPage('evidence')">Evidence</button>
      <button class="btn btn-primary" style="flex:1;font-size:0.68rem;padding:5px" onclick="showPage('ai')">AI Analysis</button>
    </div>`;
  document.querySelectorAll('.graph-node').forEach(g => g.classList.remove('selected'));
  document.querySelector(`.graph-node[data-node-id="${n.id}"]`)?.classList.add('selected');
}
window.closeNodePanel = () => document.getElementById('node-detail-panel').classList.add('hidden');

// ══════════ OSINT ENGINE ══════════
function renderOSINT(el) {
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div><div class="page-title">OSINT Engine</div><div class="page-subtitle">Open-source intelligence gathering — Subfinder, Amass, theHarvester, Shodan</div></div>
    <div class="page-actions">
      <button class="btn btn-secondary">${ICONS.file} Export Results</button>
    </div>
  </div>

  <div class="scan-target-bar fade-in-up">
    <input class="input-field input-field-mono" id="osint-target" placeholder="Enter target: domain, IP, email, company..." value="example.com" style="margin:0"/>
    <select class="input-field" style="width:160px;margin:0">
      <option>Passive Recon</option><option>Active Recon</option><option>Full Scan</option>
    </select>
    <button class="btn btn-primary" onclick="runOSINTScan()">Run Scan</button>
  </div>

  <div class="scan-module-grid fade-in-up">
    ${[
      {name:'DNS Records',desc:'A, MX, TXT, NS',icon:'🌐',color:'#00d4ff',on:true},
      {name:'Subdomain Enum',desc:'Subfinder + Amass',icon:'🔍',color:'#7b2ff7',on:true},
      {name:'WHOIS Lookup',desc:'Registrar info',icon:'📋',color:'#0099bb',on:true},
      {name:'Certificate CT',desc:'SSL/TLS cert logs',icon:'🔒',color:'#00ff9d',on:true},
      {name:'Shodan Scan',desc:'Open ports, banners',icon:'📡',color:'#ff6b35',on:true},
      {name:'VirusTotal',desc:'Reputation check',icon:'🦠',color:'#ff3d3d',on:true},
      {name:'theHarvester',desc:'Emails, names',icon:'📧',color:'#ffb800',on:true},
      {name:'Katana Spider',desc:'Web crawl, JS, APIs',icon:'🕷',color:'#ff2d78',on:true,link:'katana'},
      {name:'Web Tech',desc:'httpx, Wappalyzer',icon:'⚡',color:'#7b2ff7',on:false},
      {name:'Google Dorking',desc:'Advanced queries',icon:'🔎',color:'#00d4ff',on:false},
      {name:'OSINT Framework',desc:'SpiderFoot',icon:'🕸',color:'#ff2d78',on:false},
    ].map(m=>`
    <div class="scan-module ${m.on?'active':''}" ${m.link?`onclick="showPage('${m.link}')" style="cursor:pointer"`:''}>
      <div class="scan-module-icon" style="background:${m.color}22;color:${m.color}">${m.icon}</div>
      <div style="flex:1"><div class="scan-module-name">${m.name}${m.link?` <span style="font-size:0.55rem;background:rgba(255,45,120,0.2);color:#ff2d78;border:1px solid rgba(255,45,120,0.35);padding:1px 5px;border-radius:3px;margin-left:4px">NEW</span>`:''}</div><div class="scan-module-desc">${m.desc}</div></div>
      <div class="toggle-pill ${m.on?'on':''}" onclick="event.stopPropagation();this.classList.toggle('on');this.closest('.scan-module').classList.toggle('active')"></div>
    </div>`).join('')}
  </div>

  <div class="grid-2 fade-in-up">
    <!-- RESULTS -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">${icon('activity')} Scan Results — example.com</div>
        <span class="badge badge-safe">COMPLETE</span>
      </div>
      <div class="card-body" style="padding:0">
        ${DATA.osintResults.map(r=>`
        <div style="border-bottom:1px solid rgba(255,255,255,0.04);padding:12px 16px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
            <span style="font-weight:600;font-size:0.82rem;color:var(--text-primary)">${r.module}</span>
            <div style="display:flex;gap:8px;align-items:center">
              <span class="badge badge-low">${r.count} found</span>
              <span class="badge ${r.status==='complete'?'badge-safe':'badge-medium'}">${r.status}</span>
            </div>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${r.findings.map(f=>`<span style="font-family:var(--font-mono);font-size:0.68rem;padding:2px 8px;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.15);border-radius:3px;color:var(--text-secondary)">${f}</span>`).join('')}
          </div>
        </div>`).join('')}
      </div>
    </div>

    <!-- TERMINAL -->
    <div style="display:flex;flex-direction:column;gap:12px">
      <div class="card">
        <div class="card-header"><div class="card-title">${icon('cpu')} Live Terminal</div></div>
        <div class="card-body" style="padding:12px">
          <div class="terminal-block" id="osint-terminal">
<span class="term-cyan">$ subfinder -d example.com -silent</span>
<span class="term-green">mail.example.com</span>
<span class="term-green">api.example.com</span>
<span class="term-green">admin.example.com</span>
<span class="term-green">vpn.example.com</span>
<span class="term-green">dev.example.com</span>
<span class="term-gray">[+] 34 subdomains enumerated</span>

<span class="term-cyan">$ theHarvester -d example.com -b google</span>
<span class="term-green">[*] Emails found: 3</span>
<span class="term-white">john.doe@example.com</span>
<span class="term-white">admin@example.com</span>
<span class="term-white">noreply@example.com</span>

<span class="term-cyan">$ nmap -sV -p 80,443,22 104.21.35.67</span>
<span class="term-green">22/tcp  open  ssh     OpenSSH 8.9</span>
<span class="term-green">80/tcp  open  http    nginx 1.25</span>
<span class="term-green">443/tcp open  https   nginx 1.25</span>
<span class="term-amber">[!] Port 22 exposed to internet</span>

<span class="term-cyan">$ katana -u https://example.com -d 5 -jc</span>
<span class="term-green">[INF] Crawling https://example.com (depth: 5)</span>
<span class="term-green">https://api.example.com/v1/login</span>
<span class="term-red">https://dev.example.com/debug?cmd=  ← RCE VECTOR</span>
<span class="term-red">[CRITICAL] Hardcoded AWS_SECRET_KEY in main.chunk.js:2847</span>
<span class="term-green">[INF] 247 URLs | 61 APIs | 6 secrets | 4m 12s</span>
<span class="term-amber">[!] 4 CRITICAL endpoints require immediate attention</span></div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title">${icon('shield')} Certificate Transparency</div></div>
        <div class="card-body" style="padding:12px">
          <table class="data-table">
            <thead><tr><th>Domain</th><th>Issued</th><th>Expires</th></tr></thead>
            <tbody>
              ${[['*.example.com','2026-07-01','2026-10-01'],['mail.example.com','2026-06-15','2026-09-15'],['api.example.com','2026-08-01','2026-11-01'],['admin.example.com','2026-05-10','2026-08-10']].map(([d,i,e])=>`<tr><td class="mono">${d}</td><td style="font-family:var(--font-mono);font-size:0.72rem">${i}</td><td style="font-family:var(--font-mono);font-size:0.72rem;color:var(--amber)">${e}</td></tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>`;
}

function runOSINTScan() { showToast('OSINT scan launched — Subfinder, Amass, theHarvester, Katana & Shodan modules running...'); }

// ══════════ KATANA WEB SPIDER ══════════
function renderKatana(el) {
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div>
      <div class="page-title" style="display:flex;align-items:center;gap:12px">
        <span style="font-size:1.8rem">🕷</span> Katana Web Spider
        <span style="font-family:var(--font-mono);font-size:0.65rem;padding:3px 10px;background:rgba(255,45,120,0.15);border:1px solid rgba(255,45,120,0.35);border-radius:99px;color:#ff2d78;font-weight:600">ProjectDiscovery · v1.1.2</span>
      </div>
      <div class="page-subtitle">Advanced web crawling, JS analysis, endpoint discovery &amp; secret detection</div>
    </div>
    <div class="page-actions">
      <button class="btn btn-secondary" onclick="exportKatana()">${ICONS.download} Export Results</button>
      <button class="btn btn-primary" onclick="runKatanaScan()">▶ Run Katana Scan</button>
    </div>
  </div>

  <!-- TARGET BAR -->
  <div class="card fade-in-up" style="margin-bottom:20px;border-color:rgba(255,45,120,0.2);background:linear-gradient(135deg,rgba(255,45,120,0.05),var(--bg-card))">
    <div class="card-body" style="padding:14px">
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
        <div style="flex:1;min-width:200px">
          <label class="input-label">TARGET URL</label>
          <input class="input-field input-field-mono" id="katana-target" value="https://example.com" placeholder="https://target.com" style="margin:0"/>
        </div>
        <div>
          <label class="input-label">DEPTH</label>
          <select class="input-field" style="margin:0;width:80px" id="katana-depth">
            ${[1,2,3,4,5,6,7,8,10].map(d=>`<option ${d===5?'selected':''}>${d}</option>`).join('')}
          </select>
        </div>
        <div>
          <label class="input-label">JS CRAWL</label>
          <select class="input-field" style="margin:0;width:90px"><option>Enabled</option><option>Disabled</option></select>
        </div>
        <div>
          <label class="input-label">MODE</label>
          <select class="input-field" style="margin:0;width:130px"><option>Headless</option><option>Standard</option><option>Hybrid</option></select>
        </div>
        <div>
          <label class="input-label">CONCURRENCY</label>
          <select class="input-field" style="margin:0;width:80px"><option>10</option><option selected>25</option><option>50</option></select>
        </div>
        <button class="btn btn-primary" onclick="runKatanaScan()" style="height:38px">▶ Scan</button>
        <button class="btn btn-secondary" onclick="showPage('cyber')" style="height:38px">→ Attack Surface</button>
      </div>
      <div style="display:flex;gap:12px;margin-top:14px;padding-top:14px;border-top:1px solid var(--border);flex-wrap:wrap">
        ${[
          ['Exclude Extensions','png,jpg,gif,svg,ico,css'],
          ['Rate Limit','150 req/s'],
          ['Timeout','10s'],
          ['Output','katana_results.txt'],
        ].map(([k,v])=>`<div style="font-family:var(--font-mono);font-size:0.65rem"><span style="color:var(--text-muted)">${k}: </span><span style="color:var(--cyan)">${v}</span></div>`).join('')}
      </div>
    </div>
  </div>

  <!-- STATS STRIP -->
  <div class="stats-grid fade-in-up" style="grid-template-columns:repeat(6,1fr);margin-bottom:20px">
    ${KATANA_DATA.stats.map(s=>`
    <div class="stat-card ${s.color} fade-in-up">
      <div class="stat-label">${s.label}</div>
      <div class="stat-value">${s.value}</div>
    </div>`).join('')}
  </div>

  <!-- MAIN GRID -->
  <div class="tab-bar fade-in-up">
    ${['Endpoints','JS Secrets','HTML Forms','Terminal','Crawl Map'].map((t,i)=>
      `<button class="tab-btn ${i===0?'active':''}" onclick="switchKatanaTab(this,'ktab-${i}')">${t}</button>`
    ).join('')}
  </div>

  <!-- TAB: ENDPOINTS -->
  <div id="ktab-0" class="tab-content active fade-in-up">
    <div class="card">
      <div class="card-header">
        <div class="card-title">${icon('link')} Discovered Endpoints <span class="badge badge-critical" style="margin-left:6px">${KATANA_DATA.endpoints.length} endpoints</span></div>
        <div style="display:flex;gap:8px">
          <select class="input-field" style="height:30px;margin:0;font-size:0.72rem" onchange="filterKatanaEndpoints(this.value)">
            <option value="all">All Risk Levels</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
          <select class="input-field" style="height:30px;margin:0;font-size:0.72rem">
            <option>All Types</option><option>Auth</option><option>API</option><option>Admin</option><option>Upload</option><option>Debug</option>
          </select>
        </div>
      </div>
      <div style="overflow-x:auto" id="katana-endpoint-table">
        <table class="data-table">
          <thead><tr><th>Risk</th><th>Method</th><th>URL</th><th>Type</th><th>Parameters</th><th>Finding</th><th>Action</th></tr></thead>
          <tbody id="katana-endpoint-body">
            ${KATANA_DATA.endpoints.map(ep=>katanaEndpointRow(ep)).join('')}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB: JS SECRETS -->
  <div id="ktab-1" class="tab-content fade-in-up">
    <div style="display:flex;align-items:center;gap:12px;padding:12px 16px;background:rgba(255,61,61,0.08);border:1px solid rgba(255,61,61,0.2);border-radius:var(--radius-md);margin-bottom:16px">
      <span style="font-size:1.5rem">⚠</span>
      <div>
        <div style="font-weight:700;color:var(--red);font-size:0.9rem">CRITICAL — ${KATANA_DATA.jsSecrets.length} Hardcoded Secrets Detected in JavaScript Files</div>
        <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:2px">Katana's JS crawler extracted and analyzed all loaded JavaScript bundles. These secrets must be rotated immediately.</div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">${icon('eye')} JavaScript Secret Extraction</div><span class="badge badge-critical">${KATANA_DATA.jsSecrets.length} Secrets</span></div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead><tr><th>Severity</th><th>Secret Type</th><th>Value (Redacted)</th><th>JS File</th><th>Line</th><th>Action</th></tr></thead>
          <tbody>
            ${KATANA_DATA.jsSecrets.map(s=>`
            <tr>
              <td><span class="badge ${s.severity==='CRITICAL'?'badge-critical':'badge-high'}">${s.severity}</span></td>
              <td style="font-weight:700;color:var(--red);font-family:var(--font-mono);font-size:0.75rem">${s.secret}</td>
              <td class="mono" style="color:var(--amber)">${s.value}</td>
              <td class="mono" style="color:var(--text-secondary);font-size:0.68rem">${s.file}</td>
              <td class="mono">${s.line}</td>
              <td>
                <button class="btn btn-danger" style="padding:3px 10px;font-size:0.68rem" onclick="reportSecret('${s.secret}')">Report IOC</button>
              </td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
    <div class="grid-2" style="margin-top:16px">
      <div class="card">
        <div class="card-header"><div class="card-title">${icon('shield')} Detection Summary</div></div>
        <div class="card-body">
          ${[['AWS Credentials',1,'red'],['API Tokens',1,'red'],['Payment Keys',1,'red'],['Google API Keys',1,'amber'],['JWT Secrets',1,'amber'],['DSN / Config',1,'cyan']].map(([k,v,c])=>
          `<div style="display:flex;justify-content:space-between;margin-bottom:10px;align-items:center">
            <span style="font-size:0.8rem;color:var(--text-secondary)">${k}</span>
            <span style="font-family:var(--font-mono);font-weight:700;color:var(--${c})">${v} found</span>
          </div>`).join('')}
        </div>
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title">${icon('alert')} Remediation Steps</div></div>
        <div class="card-body">
          ${[
            'Immediately rotate ALL exposed credentials',
            'Audit AWS CloudTrail for unauthorized access',
            'Replace client-side secrets with server-side proxy',
            'Implement secret scanning in CI/CD pipeline',
            'Use environment variables — never hardcode secrets',
            'Enable GitHub Secret Scanning on all repos',
          ].map((s,i)=>`<div style="display:flex;gap:10px;margin-bottom:10px;font-size:0.78rem;color:var(--text-secondary)"><span style="color:var(--cyan);font-weight:700;flex-shrink:0">${i+1}.</span>${s}</div>`).join('')}
        </div>
      </div>
    </div>
  </div>

  <!-- TAB: FORMS -->
  <div id="ktab-2" class="tab-content fade-in-up">
    <div class="card">
      <div class="card-header"><div class="card-title">${icon('search')} HTML Forms Extracted</div><span class="badge badge-high">${KATANA_DATA.forms.length} Forms</span></div>
      <div class="card-body" style="padding:0">
        ${KATANA_DATA.forms.map((f,i)=>`
        <div style="padding:16px;border-bottom:1px solid rgba(255,255,255,0.04)">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
            <span class="mono" style="color:var(--cyan);font-weight:700">${f.method}</span>
            <span style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text-primary);font-weight:600">${f.action}</span>
            <span class="badge ${f.notes.includes('XSS')||f.notes.includes('injection')||f.notes.includes('RCE')?'badge-critical':f.notes.includes('IDOR')||f.notes.includes('upload')?'badge-high':'badge-medium'}" style="margin-left:auto">VULN</span>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px">
            ${f.inputs.map(inp=>`<span style="font-family:var(--font-mono);font-size:0.68rem;padding:2px 8px;background:rgba(123,47,247,0.1);border:1px solid rgba(123,47,247,0.2);border-radius:3px;color:var(--purple)">${inp}</span>`).join('')}
          </div>
          <div style="font-size:0.75rem;color:var(--red);display:flex;align-items:center;gap:6px">⚠ ${f.notes}</div>
        </div>`).join('')}
      </div>
    </div>
  </div>

  <!-- TAB: TERMINAL -->
  <div id="ktab-3" class="tab-content fade-in-up">
    <div class="card">
      <div class="card-header">
        <div class="card-title">${icon('cpu')} Katana Live Terminal</div>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="status-dot active"></div>
          <span style="font-family:var(--font-mono);font-size:0.65rem;color:var(--green)">COMPLETE</span>
          <span style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted)">Duration: ${KATANA_DATA.duration}</span>
        </div>
      </div>
      <div class="card-body" style="padding:12px">
        <div class="terminal-block" style="max-height:500px;overflow-y:auto">
          ${KATANA_DATA.terminalOutput.map(l=>`<span class="term-${l.type}">${l.text}</span>`).join('\n')}
        </div>
        <div style="margin-top:12px;display:flex;gap:8px">
          <input class="input-field input-field-mono" placeholder="Add flags: -H 'Cookie: ...' -proxy http://127.0.0.1:8080" style="flex:1"/>
          <button class="btn btn-primary" onclick="runKatanaScan()">Re-run</button>
          <button class="btn btn-secondary" onclick="copyKatanaCmd()">Copy Command</button>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB: CRAWL MAP -->
  <div id="ktab-4" class="tab-content fade-in-up">
    <div class="card">
      <div class="card-header"><div class="card-title">${icon('globe')} Crawl Site Map</div><span class="badge badge-safe">${KATANA_DATA.crawledUrls} URLs</span></div>
      <div class="card-body">
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px">
          ${[
            {domain:'example.com', urls:89, risk:'HIGH', color:'var(--amber)'},
            {domain:'api.example.com', urls:61, risk:'CRITICAL', color:'var(--red)'},
            {domain:'admin.example.com', urls:12, risk:'CRITICAL', color:'var(--red)'},
            {domain:'dev.example.com', urls:23, risk:'CRITICAL', color:'var(--red)'},
            {domain:'vpn.example.com', urls:8, risk:'MEDIUM', color:'var(--cyan)'},
            {domain:'mail.example.com', urls:14, risk:'LOW', color:'var(--green)'},
            {domain:'cdn.example.com', urls:31, risk:'LOW', color:'var(--green)'},
            {domain:'assets.example.com', urls:9, risk:'MEDIUM', color:'var(--amber)'},
          ].map(d=>`
          <div class="card" style="border-color:${d.color}33;background:${d.color}08">
            <div class="card-body" style="padding:14px">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
                <span style="font-family:var(--font-mono);font-size:0.8rem;font-weight:700;color:var(--text-primary)">${d.domain}</span>
                <span class="badge ${d.risk==='CRITICAL'?'badge-critical':d.risk==='HIGH'?'badge-high':d.risk==='MEDIUM'?'badge-medium':'badge-low'}">${d.risk}</span>
              </div>
              <div style="display:flex;align-items:center;gap:10px">
                <div class="progress-bar" style="flex:1"><div class="progress-fill" style="width:${Math.round(d.urls/2.47)}%;background:${d.color}"></div></div>
                <span style="font-family:var(--font-mono);font-size:0.72rem;color:${d.color};font-weight:700">${d.urls} URLs</span>
              </div>
            </div>
          </div>`).join('')}
        </div>
      </div>
    </div>
  </div>`;
}

function katanaEndpointRow(ep) {
  const riskClass = ep.risk==='CRITICAL'?'badge-critical':ep.risk==='HIGH'?'badge-high':ep.risk==='MEDIUM'?'badge-medium':'badge-low';
  return `<tr>
    <td><span class="badge ${riskClass}">${ep.risk}</span></td>
    <td><span style="font-family:var(--font-mono);font-size:0.7rem;font-weight:700;color:${ep.method==='POST'?'var(--amber)':'var(--cyan)'}">${ep.method}</span></td>
    <td class="mono" style="font-size:0.7rem;color:${ep.risk==='CRITICAL'?'var(--red)':'var(--text-secondary)'}">${ep.url}</td>
    <td><span class="badge badge-info">${ep.type}</span></td>
    <td>${ep.params.length?ep.params.map(p=>`<span class="msg-tag">${p}</span>`).join(' '):'<span style="color:var(--text-muted);font-size:0.7rem">none</span>'}</td>
    <td style="font-size:0.75rem;color:${ep.risk==='CRITICAL'||ep.risk==='HIGH'?'var(--red)':'var(--text-secondary)'}">${ep.finding}</td>
    <td style="display:flex;gap:4px">
      <button class="btn btn-secondary" style="padding:3px 8px;font-size:0.65rem" onclick="addToGraph('${ep.url}')">Graph</button>
      <button class="btn btn-danger" style="padding:3px 8px;font-size:0.65rem" onclick="addKatanaIOC('${ep.url}')">IOC</button>
    </td>
  </tr>`;
}

window.switchKatanaTab = (btn, tabId) => {
  btn.closest('.tab-bar').querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#page-katana .tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById(tabId)?.classList.add('active');
};

window.runKatanaScan = () => {
  const target = document.getElementById('katana-target')?.value || 'https://example.com';
  showToast(`🕷 Katana crawling ${target} — depth 5, JS crawl enabled, headless mode...`);
};

window.exportKatana = () => showToast('Katana results exported as JSON + TXT (247 URLs, 61 endpoints)');

window.filterKatanaEndpoints = (risk) => {
  const rows = document.querySelectorAll('#katana-endpoint-body tr');
  rows.forEach(r => {
    if (risk === 'all') { r.style.display = ''; return; }
    r.style.display = r.textContent.includes(risk) ? '' : 'none';
  });
};

window.addToGraph = (url) => { showToast(`Node added to Investigation Graph: ${url.slice(0,40)}...`); };
window.addKatanaIOC = (url) => { showToast(`IOC registered from Katana: ${url.slice(0,40)}...`); showPage('ioc'); };
window.reportSecret = (secret) => { showToast(`🔴 ${secret} added to IOC Fusion as CRITICAL indicator`); };
window.copyKatanaCmd = () => { showToast('Command copied: katana -u https://example.com -d 5 -jc -ef png,jpg,gif'); };


// ══════════ ATTACK SURFACE ══════════
function renderCyber(el) {
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div><div class="page-title">Attack Surface</div><div class="page-subtitle">Vulnerability research — Nuclei, Nmap, httpx, Katana</div></div>
    <div class="page-actions">
      <button class="btn btn-secondary">${ICONS.download} Export Report</button>
      <button class="btn btn-primary" onclick="runVulnScan()">Run Nuclei Scan</button>
    </div>
  </div>

  <div class="stats-grid fade-in-up">
    ${statCard('CRITICAL',2,'red','','','alert')}
    ${statCard('HIGH',4,'amber','','','zap')}
    ${statCard('MEDIUM',4,'purple','','','shield')}
    ${statCard('LOW',2,'green','','','search')}
  </div>

  <div class="card fade-in-up" style="margin-bottom:16px">
    <div class="card-header">
      <div class="card-title">${icon('zap')} Vulnerability Findings</div>
      <div style="display:flex;gap:8px">
        <select class="input-field" style="height:30px;margin:0;font-size:0.75rem">
          <option>All Severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
        </select>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table class="data-table">
        <thead><tr><th>ID</th><th>Vulnerability</th><th>Severity</th><th>CVSS</th><th>Path</th><th>Tool</th><th>Status</th><th>Action</th></tr></thead>
        <tbody>
          ${DATA.vulnerabilities.map(v=>`
          <tr>
            <td class="mono">${v.id}</td>
            <td style="font-weight:600">${v.title}</td>
            <td><span class="badge ${v.severity==='CRITICAL'?'badge-critical':v.severity==='HIGH'?'badge-high':v.severity==='MEDIUM'?'badge-medium':'badge-low'}">${v.severity}</span></td>
            <td class="mono" style="color:${v.cvss>=9?'var(--red)':v.cvss>=7?'var(--orange)':v.cvss>=5?'var(--amber)':'var(--cyan)'}">${v.cvss}</td>
            <td class="mono">${v.path}</td>
            <td><span class="badge badge-info">${v.tool}</span></td>
            <td><span class="badge ${v.status==='Open'?'badge-critical':v.status==='Fixed'?'badge-safe':'badge-medium'}">${v.status}</span></td>
            <td><button class="btn btn-secondary" style="padding:3px 10px;font-size:0.7rem" onclick="showVulnDetail('${v.id}')">Details</button></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>

  <div class="grid-2 fade-in-up">
    <div class="card">
      <div class="card-header"><div class="card-title">${icon('network')} Port Scan Results</div><span class="badge badge-safe">NMAP</span></div>
      <div class="card-body" style="padding:0">
        ${[
          {port:22,service:'SSH',version:'OpenSSH 8.9',state:'open',risk:'MEDIUM'},
          {port:80,service:'HTTP',version:'nginx 1.25.0',state:'open',risk:'LOW'},
          {port:443,service:'HTTPS',version:'nginx 1.25.0 + TLS 1.3',state:'open',risk:'LOW'},
          {port:3306,service:'MySQL',version:'8.0.32',state:'open',risk:'HIGH'},
          {port:8080,service:'HTTP-alt',version:'Apache 2.4.51',state:'open',risk:'CRITICAL'},
          {port:21,service:'FTP',version:'vsftpd 3.0.3',state:'filtered',risk:'MEDIUM'},
        ].map(p=>`
        <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid rgba(255,255,255,0.04)">
          <span class="mono" style="width:40px;text-align:right;color:var(--cyan)">${p.port}</span>
          <div class="status-dot ${p.state==='open'?'active':''}" style="width:6px;height:6px;flex-shrink:0"></div>
          <span style="width:60px;font-size:0.78rem;color:var(--text-primary)">${p.service}</span>
          <span style="flex:1;font-family:var(--font-mono);font-size:0.7rem;color:var(--text-secondary)">${p.version}</span>
          <span class="badge ${p.risk==='CRITICAL'?'badge-critical':p.risk==='HIGH'?'badge-high':p.risk==='MEDIUM'?'badge-medium':'badge-low'}">${p.risk}</span>
        </div>`).join('')}
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">${icon('globe')} Web Technology Stack</div></div>
      <div class="card-body">
        ${[
          {cat:'Frontend',items:['React 18.2','TypeScript 5.0','Webpack 5']},
          {cat:'Backend',items:['Node.js 20 LTS','Express 4.18','nginx 1.25']},
          {cat:'Database',items:['MySQL 8.0','Redis 7.2']},
          {cat:'Cloud/CDN',items:['Cloudflare Enterprise','AWS S3','AWS CloudFront']},
          {cat:'Auth',items:['JWT Tokens','OAuth 2.0','Google SSO']},
        ].map(t=>`
        <div style="margin-bottom:14px">
          <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:6px">${t.cat}</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${t.items.map(i=>`<span class="msg-tag">${i}</span>`).join('')}
          </div>
        </div>`).join('')}
      </div>
    </div>
  </div>`;
}

function runVulnScan() { showToast('Nuclei scan initiated with community templates...'); }
window.showVulnDetail = (id) => {
  const v = DATA.vulnerabilities.find(x => x.id === id);
  if (!v) return;
  openModal(`${v.title}`, `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      ${[['ID',v.id],['Severity',v.severity],['CVSS Score',v.cvss],['Status',v.status],['Path',v.path],['Tool',v.tool],['Discovered',v.discovered]].map(([k,val])=>`<div><div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:4px">${k}</div><div style="font-weight:600;color:var(--text-primary);font-family:var(--font-mono);font-size:0.78rem">${val}</div></div>`).join('')}
    </div>
    <div class="report-highlight">This vulnerability should be prioritized for immediate remediation due to its ${v.severity} severity rating and CVSS score of ${v.cvss}.</div>
    <div style="margin-top:14px">
      <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:8px">REMEDIATION</div>
      <div style="font-size:0.8rem;color:var(--text-secondary);line-height:1.6">Apply latest security patches, enforce proper input validation, implement WAF rules, and conduct a post-fix penetration test to confirm resolution.</div>
    </div>`,
    [{ label: 'Add to Evidence', action: closeModal, primary: true }, { label: 'Close', action: closeModal }]
  );
};

// ══════════ THREAT INTELLIGENCE ══════════
function renderThreat(el) {
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div><div class="page-title">Threat Intelligence</div><div class="page-subtitle">MISP feeds, STIX/TAXII, ATT&CK Matrix correlation</div></div>
    <div class="page-actions">
      <button class="btn btn-secondary">${ICONS.refresh} Sync Feeds</button>
      <button class="btn btn-primary">Add TI Source</button>
    </div>
  </div>

  <div class="stats-grid fade-in-up">
    ${statCard('THREAT ACTORS','4','red','Active tracking','','alert')}
    ${statCard('TI FEEDS','12','cyan','11 active','up','globe')}
    ${statCard('IOC MATCHES','43','amber','Last 24h','up','zap')}
    ${statCard('MITRE TTPs','31','purple','Mapped to cases','','brain')}
  </div>

  <div class="card fade-in-up" style="margin-bottom:16px">
    <div class="card-header"><div class="card-title">${icon('alert')} Active Threat Actors</div></div>
    <div style="overflow-x:auto">
      <table class="data-table">
        <thead><tr><th>Threat Actor</th><th>Origin</th><th>Motivation</th><th>Confidence</th><th>Key TTPs</th><th>Severity</th><th>Last Seen</th></tr></thead>
        <tbody>
          ${DATA.threats.map(t=>`
          <tr>
            <td style="font-weight:700;color:var(--red)">${t.actor}</td>
            <td>${t.origin}</td>
            <td>${t.motivation}</td>
            <td><span class="badge ${t.confidence==='HIGH'?'badge-critical':t.confidence==='MEDIUM'?'badge-medium':'badge-low'}">${t.confidence}</span></td>
            <td class="mono" style="font-size:0.68rem">${t.ttps}</td>
            <td><span class="badge ${t.severity==='CRITICAL'?'badge-critical':'badge-high'}">${t.severity}</span></td>
            <td style="font-family:var(--font-mono);font-size:0.72rem">${t.last_seen}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>

  <div class="grid-2 fade-in-up">
    <div class="card">
      <div class="card-header"><div class="card-title">${icon('shield')} MITRE ATT&CK Mapping</div></div>
      <div class="card-body" style="padding:12px">
        <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);margin-bottom:12px">TECHNIQUES IDENTIFIED IN CASE-2026-0017</div>
        ${[
          {id:'T1566',name:'Phishing',tactic:'Initial Access',count:8},
          {id:'T1059',name:'Command & Scripting Interpreter',tactic:'Execution',count:5},
          {id:'T1021',name:'Remote Services',tactic:'Lateral Movement',count:3},
          {id:'T1486',name:'Data Encrypted for Impact',tactic:'Impact',count:2},
          {id:'T1041',name:'Exfiltration Over C2 Channel',tactic:'Exfiltration',count:4},
          {id:'T1078',name:'Valid Accounts',tactic:'Defense Evasion',count:6},
        ].map(t=>`
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
          <span class="badge badge-info" style="width:50px;justify-content:center">${t.id}</span>
          <div style="flex:1">
            <div style="font-size:0.78rem;font-weight:600;color:var(--text-primary)">${t.name}</div>
            <div style="font-size:0.68rem;color:var(--text-muted)">${t.tactic}</div>
          </div>
          <div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--amber)">${t.count} events</div>
        </div>`).join('')}
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">${icon('globe')} Active TI Feeds</div></div>
      <div class="card-body" style="padding:0">
        ${[
          {name:'CIRCL MISP',type:'STIX/TAXII',iocs:847,status:'LIVE'},
          {name:'AlienVault OTX',type:'REST API',iocs:2341,status:'LIVE'},
          {name:'Abuse.ch URLhaus',type:'CSV Feed',iocs:1205,status:'LIVE'},
          {name:'VirusTotal Intel',type:'API',iocs:412,status:'LIVE'},
          {name:'Shodan MonitorAPI',type:'API',iocs:89,status:'LIVE'},
          {name:'CISA KEV',type:'JSON',iocs:1078,status:'LIVE'},
          {name:'Spamhaus',type:'DNS BL',iocs:5521,status:'LIVE'},
          {name:'NVD CVE Feed',type:'XML/JSON',iocs:321,status:'SYNCING'},
        ].map(f=>`
        <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid rgba(255,255,255,0.04)">
          <div class="status-dot active"></div>
          <div style="flex:1"><div style="font-size:0.8rem;font-weight:600;color:var(--text-primary)">${f.name}</div><div style="font-size:0.68rem;color:var(--text-muted)">${f.type}</div></div>
          <div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--cyan)">${f.iocs.toLocaleString()} IOCs</div>
          <span class="badge ${f.status==='LIVE'?'badge-safe':'badge-medium'}">${f.status}</span>
        </div>`).join('')}
      </div>
    </div>
  </div>`;
}

// ══════════ IOC FUSION ══════════
function renderIOC(el) {
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div><div class="page-title">IOC Fusion</div><div class="page-subtitle">Indicator of Compromise correlation — STIX/TAXII compatible</div></div>
    <div class="page-actions">
      <button class="btn btn-secondary">${ICONS.download} Export STIX</button>
      <button class="btn btn-primary" onclick="openAddIOCModal()">Add IOC</button>
    </div>
  </div>

  <div class="scan-target-bar fade-in-up" style="margin-bottom:20px">
    <input class="input-field input-field-mono" placeholder="Search IOC: hash, IP, domain, URL, email..." style="margin:0;flex:1" />
    <select class="input-field" style="width:130px;margin:0"><option>All Types</option><option>Domain</option><option>IP</option><option>Hash</option><option>URL</option><option>Email</option></select>
    <select class="input-field" style="width:130px;margin:0"><option>All Severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option></select>
    <button class="btn btn-secondary">Filter</button>
  </div>

  <div class="card fade-in-up">
    <div class="card-header"><div class="card-title">${icon('box')} IOC Registry</div><div class="badge badge-critical">${DATA.iocs.length} Active IOCs</div></div>
    <div style="overflow-x:auto">
      <table class="data-table">
        <thead><tr><th>IOC ID</th><th>Type</th><th>Indicator</th><th>Threat</th><th>Confidence</th><th>Severity</th><th>First Seen</th><th>Last Seen</th><th>Tags</th></tr></thead>
        <tbody>
          ${DATA.iocs.map(ioc=>`
          <tr onclick="openIOCDetail('${ioc.id}')" style="cursor:pointer">
            <td class="mono">${ioc.id}</td>
            <td><span class="badge badge-info">${ioc.type}</span></td>
            <td class="mono" style="color:var(--${ioc.severity==='CRITICAL'?'red':ioc.severity==='HIGH'?'orange':'cyan'})">${ioc.value}</td>
            <td style="font-size:0.78rem">${ioc.threat}</td>
            <td>
              <div style="display:flex;align-items:center;gap:6px">
                <div class="progress-bar" style="width:60px"><div class="progress-fill ${ioc.confidence>90?'red':ioc.confidence>75?'amber':'cyan'}" style="width:${ioc.confidence}%"></div></div>
                <span class="mono" style="font-size:0.68rem">${ioc.confidence}%</span>
              </div>
            </td>
            <td><span class="badge ${ioc.severity==='CRITICAL'?'badge-critical':ioc.severity==='HIGH'?'badge-high':'badge-medium'}">${ioc.severity}</span></td>
            <td style="font-family:var(--font-mono);font-size:0.68rem">${ioc.first_seen}</td>
            <td style="font-family:var(--font-mono);font-size:0.68rem">${ioc.last_seen}</td>
            <td>${ioc.tags.map(t=>`<span class="msg-tag">${t}</span>`).join('')}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>`;
}

window.openAddIOCModal = () => {
  openModal('Add New IOC', `
    <div class="input-group"><label class="input-label">INDICATOR VALUE</label><input class="input-field input-field-mono" placeholder="Domain, IP, Hash, URL, Email..."/></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div class="input-group"><label class="input-label">TYPE</label><select class="input-field"><option>Domain</option><option>IP</option><option>Hash</option><option>URL</option><option>Email</option></select></div>
      <div class="input-group"><label class="input-label">SEVERITY</label><select class="input-field"><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div>
    </div>
    <div class="input-group"><label class="input-label">THREAT DESCRIPTION</label><input class="input-field" placeholder="C2 Server, Phishing Domain, Malware Hash..."/></div>
    <div class="input-group"><label class="input-label">TAGS (comma-separated)</label><input class="input-field" placeholder="APT-29, C2, Phishing..."/></div>`,
    [{ label: 'Add IOC', action: () => { closeModal(); showToast('IOC added to registry'); }, primary: true }, { label: 'Cancel', action: closeModal }]
  );
};

window.openIOCDetail = (id) => {
  const ioc = DATA.iocs.find(x => x.id === id);
  if (!ioc) return;
  openModal(`IOC: ${ioc.value}`, `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      ${[['ID',ioc.id],['Type',ioc.type],['Severity',ioc.severity],['Confidence',ioc.confidence+'%'],['First Seen',ioc.first_seen],['Last Seen',ioc.last_seen]].map(([k,v])=>`<div><div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:4px">${k}</div><div style="font-weight:600;color:var(--text-primary);font-family:var(--font-mono);font-size:0.78rem">${v}</div></div>`).join('')}
    </div>
    <div class="report-highlight"><strong>Threat: </strong>${ioc.threat}</div>
    <div style="margin-top:12px"><div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:6px">TAGS</div>${ioc.tags.map(t=>`<span class="msg-tag">${t}</span>`).join(' ')}</div>`,
    [{ label: 'View in Graph', action: () => { closeModal(); showPage('graph'); }, primary: true }, { label: 'Close', action: closeModal }]
  );
};

// ══════════ DFIR WORKBENCH ══════════
function renderDFIR(el) {
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div><div class="page-title">DFIR Workbench</div><div class="page-subtitle">Digital Forensics & Incident Response — Autopsy, Volatility, YARA</div></div>
    <div class="page-actions">
      <button class="btn btn-secondary">Upload Artifact</button>
      <button class="btn btn-primary">New Analysis</button>
    </div>
  </div>

  <div class="tab-bar fade-in-up">
    ${['Memory Analysis','Disk Forensics','YARA Scan','Network PCAP','Log Analysis'].map((t,i)=>`<button class="tab-btn ${i===0?'active':''}" onclick="switchDFIRTab(this,'dfir-tab-${i}')">${t}</button>`).join('')}
  </div>

  <div id="dfir-tab-0" class="tab-content active fade-in-up">
    <div class="grid-2" style="margin-bottom:16px">
      <div class="card">
        <div class="card-header"><div class="card-title">${icon('cpu')} Volatility Analysis — memory_dump_host01.raw</div></div>
        <div class="card-body" style="padding:12px">
          <div class="terminal-block">
<span class="term-cyan">$ vol.py -f memory_dump_host01.raw windows.pslist</span>
<span class="term-gray">Offset   PID  PPID  ImageFileName  Handles Threads</span>
<span class="term-green">0x...  4      0     System         2003    142</span>
<span class="term-green">0x...  584    4     smss.exe       43      3</span>
<span class="term-red">0x...  1337   584   svchost.exe*   891     47   ← SUSPICIOUS</span>
<span class="term-red">0x...  2048   1337  cmd.exe        94      3    ← CHILD PROCESS</span>
<span class="term-red">0x...  2049   2048  powershell.exe 204     8    ← ENCODED CMD</span>
<span class="term-green">0x...  892    692   explorer.exe   1203    52</span>
<span class="term-amber">[!] 4 suspicious processes identified</span>
<span class="term-amber">[!] Network connections: port 4444 → 185.220.101.45</span>
<span class="term-amber">[!] Injected DLL detected in svchost PID 1337</span></div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title">${icon('alert')} Suspicious Processes</div></div>
        <div class="card-body" style="padding:0">
          ${[
            {pid:'1337',name:'svchost.exe*',parent:'smss.exe',risk:'CRITICAL',note:'Anomalous parent process, injected DLL'},
            {pid:'2048',name:'cmd.exe',parent:'svchost.exe',risk:'HIGH',note:'Spawned by modified svchost'},
            {pid:'2049',name:'powershell.exe',parent:'cmd.exe',risk:'CRITICAL',note:'Base64 encoded command detected'},
            {pid:'3012',name:'rundll32.exe',parent:'cmd.exe',risk:'HIGH',note:'Loading unsigned DLL from temp'},
          ].map(p=>`
          <div style="padding:10px 16px;border-bottom:1px solid rgba(255,255,255,0.04)">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
              <span class="mono" style="color:var(--cyan);width:40px">${p.pid}</span>
              <span style="font-weight:600;color:var(--text-primary)">${p.name}</span>
              <span class="badge ${p.risk==='CRITICAL'?'badge-critical':'badge-high'}" style="margin-left:auto">${p.risk}</span>
            </div>
            <div style="font-size:0.72rem;color:var(--text-secondary);margin-left:50px">${p.note}</div>
          </div>`).join('')}
        </div>
      </div>
    </div>
    <div class="card fade-in-up">
      <div class="card-header"><div class="card-title">${icon('network')} Network Connections from Memory</div></div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead><tr><th>PID</th><th>Process</th><th>Local</th><th>Remote IP</th><th>Port</th><th>State</th><th>IOC Match</th></tr></thead>
          <tbody>
            ${[
              {pid:'1337',proc:'svchost.exe',local:'192.168.47.22:49231',remote:'185.220.101.45',port:'4444',state:'ESTABLISHED',ioc:true},
              {pid:'892',proc:'explorer.exe',local:'192.168.47.22:49100',remote:'142.250.80.78',port:'443',state:'ESTABLISHED',ioc:false},
              {pid:'2049',proc:'powershell.exe',local:'192.168.47.22:49340',remote:'185.220.101.45',port:'443',state:'CLOSE_WAIT',ioc:true},
            ].map(c=>`
            <tr>
              <td class="mono">${c.pid}</td>
              <td style="color:${c.ioc?'var(--red)':'var(--text-primary)'}; font-weight:${c.ioc?'700':'400'}">${c.proc}</td>
              <td class="mono">${c.local}</td>
              <td class="mono" style="color:${c.ioc?'var(--red)':'var(--text-secondary)'}">${c.remote}</td>
              <td class="mono">${c.port}</td>
              <td><span class="badge ${c.state==='ESTABLISHED'?'badge-high':'badge-medium'}">${c.state}</span></td>
              <td>${c.ioc?'<span class="badge badge-critical">⚠ IOC MATCH</span>':'<span class="badge badge-safe">CLEAN</span>'}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="dfir-tab-1" class="tab-content fade-in-up">
    <div class="card"><div class="card-header"><div class="card-title">Disk Forensics — Autopsy</div></div><div class="card-body">
      <div class="terminal-block">
<span class="term-cyan">$ autopsy --analyze disk_image.dd</span>
<span class="term-green">[+] Partition table: GPT</span>
<span class="term-green">[+] File system: NTFS (Windows 10)</span>
<span class="term-amber">[!] Deleted files recovered: 1,247</span>
<span class="term-red">[!] Suspicious file: %TEMP%\svch0st.exe (SHA256: d8c1a0...)</span>
<span class="term-red">[!] Registry persistence: HKCU\Run → "updater.exe"</span>
<span class="term-amber">[!] Recent access: 2026-09-14 08:03 — sensitive_data.xlsx</span>
<span class="term-green">[+] Timeline exported: 12,445 events</span></div>
    </div></div>
  </div>

  <div id="dfir-tab-2" class="tab-content fade-in-up">
    <div class="card"><div class="card-header"><div class="card-title">YARA Rule Matches</div></div><div class="card-body" style="padding:0">
      ${[
        {rule:'LOCKBIT3_Ransomware',file:'svch0st.exe',score:99,desc:'Matches LOCKBIT 3.0 string signatures and encryption routines'},
        {rule:'CobaltStrike_Beacon',file:'svchost_dll_inject.bin',score:97,desc:'Cobalt Strike beacon shellcode pattern detected'},
        {rule:'Phishing_HTML_Kit',file:'index.html (phish_kit)',score:88,desc:'Credential harvester HTML template with proxy code'},
        {rule:'Mimic_Ransomware',file:'update_helper.dll',score:71,desc:'Potential Mimic ransomware variant strings'},
      ].map(y=>`
      <div style="padding:14px 16px;border-bottom:1px solid rgba(255,255,255,0.04)">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <span style="font-family:var(--font-mono);font-size:0.75rem;font-weight:700;color:var(--red)">${y.rule}</span>
          <span class="badge badge-critical" style="margin-left:auto">Score: ${y.score}%</span>
        </div>
        <div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--cyan);margin-bottom:4px">${y.file}</div>
        <div style="font-size:0.75rem;color:var(--text-secondary)">${y.desc}</div>
      </div>`).join('')}
    </div></div>
  </div>
  <div id="dfir-tab-3" class="tab-content"><div class="card"><div class="card-body"><p style="color:var(--text-secondary)">PCAP analysis loaded — Wireshark integration active.</p></div></div></div>
  <div id="dfir-tab-4" class="tab-content"><div class="card"><div class="card-body"><p style="color:var(--text-secondary)">Log analysis via Wazuh/Elastic integration.</p></div></div></div>`;
}

window.switchDFIRTab = (btn, tabId) => {
  btn.closest('.tab-bar').querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll(`#page-dfir .tab-content`).forEach(t => t.classList.remove('active'));
  document.getElementById(tabId)?.classList.add('active');
};

// ══════════ EVIDENCE VAULT ══════════
function renderEvidence(el) {
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div><div class="page-title">Evidence Vault</div><div class="page-subtitle">SHA-256 hashed, immutable chain-of-custody — NIST forensic standards</div></div>
    <div class="page-actions">
      <button class="btn btn-secondary">${ICONS.download} Export Manifest</button>
      <button class="btn btn-primary" onclick="openAddEvidenceModal()">Add Evidence</button>
    </div>
  </div>

  <div class="stats-grid fade-in-up">
    ${statCard('TOTAL ITEMS','127','cyan','','','box')}
    ${statCard('VERIFIED','119','green','Chain intact','up','shield')}
    ${statCard('PENDING','8','amber','Awaiting review','','zap')}
    ${statCard('TOTAL SIZE','47.3 GB','purple','','','cpu')}
  </div>

  <div class="card fade-in-up">
    <div class="card-header">
      <div class="card-title">${icon('box')} Evidence Registry — CASE-2026-0017</div>
      <div style="display:flex;gap:8px">
        <select class="input-field" style="height:30px;margin:0;font-size:0.75rem"><option>All Types</option><option>Memory</option><option>Network</option><option>Malware</option><option>File</option></select>
      </div>
    </div>
    <div class="card-body" style="padding:12px;display:flex;flex-direction:column;gap:8px">
      ${DATA.evidence.map(e=>evidenceItem(e)).join('')}
    </div>
  </div>`;
}

function evidenceItem(e) {
  const typeMap = { memory: 'memory', network: 'network', malware: 'malware', file: 'file' };
  const iconMap = { memory: ICONS.cpu, network: ICONS.network, malware: ICONS.alert, file: ICONS.file };
  return `
  <div class="evidence-item fade-in-up" onclick="openEvidenceDetail('${e.id}')">
    <div class="evidence-icon ${typeMap[e.type]||'file'}">${iconMap[e.type]||ICONS.file}</div>
    <div class="evidence-body">
      <div class="evidence-name">${e.id} — ${e.name}</div>
      <div class="evidence-hash">${e.hash}</div>
      <div class="evidence-meta">
        <span>${e.source}</span>
        <span>${e.size}</span>
        <span>Acquired: ${e.acquired}</span>
        <span>${e.analyst}</span>
      </div>
    </div>
    <div class="chain-tag">${e.chain === 'VERIFIED' ? '✓ VERIFIED' : '⏳ PENDING'}</div>
  </div>`;
}

window.openEvidenceDetail = (id) => {
  const e = DATA.evidence.find(x => x.id === id);
  if (!e) return;
  openModal(`Evidence: ${e.id}`, `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      ${[['Evidence ID',e.id],['Filename',e.name],['Type',e.type.toUpperCase()],['Size',e.size],['Source',e.source],['Analyst',e.analyst],['Acquired',e.acquired],['Chain of Custody',e.chain]].map(([k,v])=>`<div><div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:4px">${k}</div><div style="font-weight:600;color:var(--text-primary);font-family:var(--font-mono);font-size:0.7rem;word-break:break-all">${v}</div></div>`).join('')}
    </div>
    <div class="report-highlight"><strong>SHA-256:</strong> ${e.hash}</div>
    <div style="margin-top:12px"><div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:6px">ANALYST NOTES</div><div style="font-size:0.8rem;color:var(--text-secondary)">${e.notes}</div></div>`,
    [{ label: 'DFIR Analysis', action: () => { closeModal(); showPage('dfir'); }, primary: true }, { label: 'Close', action: closeModal }]
  );
};

window.openAddEvidenceModal = () => {
  openModal('Add Evidence Item', `
    <div class="input-group"><label class="input-label">EVIDENCE FILE / ARTIFACT</label><input class="input-field" type="file" style="padding:8px"/></div>
    <div class="input-group"><label class="input-label">SOURCE / ACQUISITION METHOD</label><input class="input-field" placeholder="e.g. LiME kernel module, Firewall TAP..."/></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div class="input-group"><label class="input-label">TYPE</label><select class="input-field"><option>Memory Dump</option><option>PCAP Capture</option><option>Malware Sample</option><option>Log File</option><option>Disk Image</option></select></div>
      <div class="input-group"><label class="input-label">ASSIGNED ANALYST</label><select class="input-field"><option>Analyst 01</option><option>Analyst 02</option><option>Analyst 03</option></select></div>
    </div>
    <div class="input-group"><label class="input-label">ANALYST NOTES</label><textarea class="input-field" rows="3" placeholder="Acquisition context, tools used, observations..."></textarea></div>`,
    [{ label: 'Hash & Ingest', action: () => { closeModal(); showToast('Evidence ingested — SHA-256 computed, chain-of-custody initiated'); }, primary: true }, { label: 'Cancel', action: closeModal }]
  );
};

// ══════════ TIMELINE ══════════
function renderTimeline(el) {
  const events = [
    { time: '2026-09-14 08:00', title: 'Spear-Phishing Emails Sent', desc: 'APT-29 sent targeted phishing to 14 employees from noreply@evil-c2.ru with malicious .docm attachment.', severity: 'critical', tags: ['APT-29','Phishing','Initial Access'] },
    { time: '2026-09-14 08:12', title: 'C2 Domain evil-c2.ru Registered', desc: 'Threat actor registered evil-c2.ru resolving to 185.220.101.45 (TOR exit node) to establish C2 infrastructure.', severity: 'critical', tags: ['C2','Infrastructure'] },
    { time: '2026-09-14 09:03', title: 'Employee Opens Phishing Attachment', desc: 'User john.doe@example.com opens malicious .docm file enabling macros, executing initial stager payload.', severity: 'critical', tags: ['Execution','T1059'] },
    { time: '2026-09-14 09:07', title: 'Process Injection — svchost PID 1337', desc: 'Stager injects Cobalt Strike beacon into svchost.exe (PID 1337). DLL injection confirmed in memory analysis.', severity: 'critical', tags: ['Injection','CobaltStrike'] },
    { time: '2026-09-14 10:15', title: 'C2 Beacon Established', desc: 'Cobalt Strike beacon connects to 185.220.101.45:4444 (TOR). Encrypted command channel established.', severity: 'critical', tags: ['C2','Beacon','T1041'] },
    { time: '2026-09-15 14:30', title: 'Lateral Movement Detected', desc: 'Threat actor uses Pass-the-Hash to move to 3 additional workstations in the finance department.', severity: 'high', tags: ['LateralMovement','T1021'] },
    { time: '2026-09-18 22:00', title: 'Data Staging — sensitive_data.xlsx', desc: 'Attacker stages sensitive financial documents in %TEMP% directory. File access logged at 22:03.', severity: 'high', tags: ['Staging','Exfiltration','T1041'] },
    { time: '2026-09-20 06:44', title: 'LOCKBIT 3.0 Payload Deployed', desc: 'Ransomware payload dropped and executed. Encryption initiated across 47 systems. VSS deleted.', severity: 'critical', tags: ['Ransomware','LOCKBIT','T1486'] },
    { time: '2026-09-20 07:15', title: 'Incident Detected — SOC Alert', desc: 'Wazuh SIEM triggers critical alert on mass file encryption. SOC analyst escalates to IR team.', severity: 'high', tags: ['Detection','SIEM'] },
    { time: '2026-09-20 08:00', title: 'Incident Response Initiated', desc: 'DFIR team deploys. Network isolation of affected segments. Memory dump collection begins.', severity: 'medium', tags: ['Response','DFIR'] },
    { time: '2026-09-22 16:45', title: 'Phishing Kit Seized from CDN', desc: 'Coordination with hosting provider results in seizure of phishing kit from CDN edge node.', severity: 'info', tags: ['Remediation','Takedown'] },
    { time: '2026-10-08', title: 'Investigation Ongoing', desc: 'DFIR analysis, IOC correlation and AI-assisted investigation continuing. Case remains active.', severity: 'info', tags: ['Active','Ongoing'] },
  ];

  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div><div class="page-title">Event Timeline</div><div class="page-subtitle">Chronological incident timeline — CASE-2026-0017</div></div>
    <div class="page-actions">
      <button class="btn btn-secondary">${ICONS.download} Export Timeline</button>
      <button class="btn btn-primary" onclick="showPage('ai')">AI Timeline Analysis</button>
    </div>
  </div>

  <div class="stats-grid fade-in-up">
    ${statCard('TOTAL EVENTS',events.length.toString(),'cyan','','','activity')}
    ${statCard('CRITICAL',events.filter(e=>e.severity==='critical').length.toString(),'red','','','alert')}
    ${statCard('HIGH',events.filter(e=>e.severity==='high').length.toString(),'amber','','','zap')}
    ${statCard('DURATION','24 days','purple','Sep 14 — Oct 8','','file')}
  </div>

  <div class="card fade-in-up">
    <div class="card-header"><div class="card-title">${icon('activity')} Incident Timeline</div></div>
    <div class="card-body">
      <div class="timeline">
        ${events.map(e=>`
        <div class="timeline-item">
          <div class="timeline-dot ${e.severity}"></div>
          <div class="timeline-time">${e.time}</div>
          <div class="timeline-title">${e.title}</div>
          <div class="timeline-desc">${e.desc}</div>
          <div class="timeline-tags">
            ${e.tags.map(t=>`<span class="msg-tag">${t}</span>`).join('')}
          </div>
        </div>`).join('')}
      </div>
    </div>
  </div>`;
}

// ══════════ AI INVESTIGATOR ══════════
function renderAI(el) {
  el.style.padding = '0';
  el.innerHTML = `
  <div class="ai-page">
    <!-- AI Sidebar -->
    <div class="ai-sidebar">
      <div style="padding:14px;border-bottom:1px solid var(--border)">
        <button class="btn btn-primary" style="width:100%;justify-content:center" onclick="newAIConversation()">+ New Investigation</button>
      </div>
      <div style="padding:8px;overflow-y:auto;flex:1">
        <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);padding:8px 8px 4px;letter-spacing:0.1em">RECENT SESSIONS</div>
        ${DATA.aiConversations.map((c,i)=>`
        <div style="padding:10px;border-radius:var(--radius-sm);margin-bottom:2px;cursor:pointer;background:${i===0?'rgba(0,212,255,0.08)':'transparent'};border:1px solid ${i===0?'rgba(0,212,255,0.2)':'transparent'};transition:all 0.2s" onmouseover="this.style.background='rgba(0,212,255,0.06)'" onmouseout="this.style.background='${i===0?'rgba(0,212,255,0.08)':'transparent'}'">
          <div style="font-size:0.78rem;font-weight:600;color:var(--text-primary);margin-bottom:3px">${c.title}</div>
          <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted)">${c.msgs.length} messages</div>
        </div>`).join('')}
      </div>
      <div style="padding:12px;border-top:1px solid var(--border)">
        <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-muted);margin-bottom:8px">AI MODEL</div>
        <div style="display:flex;align-items:center;gap:8px;padding:8px;background:rgba(123,47,247,0.1);border:1px solid rgba(123,47,247,0.2);border-radius:var(--radius-sm)">
          <div style="width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,var(--purple),var(--cyan));display:flex;align-items:center;justify-content:center;font-size:0.65rem;font-weight:700;color:white">AI</div>
          <div>
            <div style="font-size:0.78rem;font-weight:600;color:var(--text-primary)">GPT-4 Turbo</div>
            <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-muted)">RAG Pipeline Active</div>
          </div>
          <div class="status-dot active" style="margin-left:auto"></div>
        </div>
      </div>
    </div>

    <!-- AI Chat -->
    <div class="ai-chat-area">
      <div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px">
        <div>
          <div style="font-family:var(--font-display);font-size:0.95rem;font-weight:700;color:var(--text-primary)">example.com — CASE-2026-0017</div>
          <div style="font-size:0.72rem;color:var(--text-secondary)">RAG context: 127 evidence items, 43 IOCs, 8 OSINT modules</div>
        </div>
        <div style="margin-left:auto;display:flex;gap:8px">
          <button class="btn btn-secondary" style="padding:5px 10px;font-size:0.72rem" onclick="showPage('report')">Generate Report</button>
          <button class="btn btn-secondary" style="padding:5px 10px;font-size:0.72rem">Clear Chat</button>
        </div>
      </div>

      <div class="ai-messages" id="ai-messages">
        <!-- System greeting -->
        <div class="ai-msg ai">
          <div class="msg-avatar ai">IX</div>
          <div>
            <div class="msg-bubble">
              Welcome, Analyst 01. I'm the INTELFUSE X AI Investigator, operating with full RAG context for <strong>CASE-2026-0017</strong>.<br><br>
              I have access to <strong>127 evidence items</strong>, <strong>43 IOCs</strong>, <strong>34 subdomains</strong>, <strong>12 IPs</strong>, Volatility memory analysis, YARA matches, and MITRE ATT&amp;CK correlations for this case.<br><br>
              I distinguish between <span style="color:var(--cyan)">⬤ OBSERVED FACTS</span>, <span style="color:var(--amber)">⬤ INFERRED RELATIONSHIPS</span>, and <span style="color:var(--purple)">⬤ HYPOTHESES</span> in all analyses. How can I assist with this investigation?
            </div>
            <div class="msg-cite">Context: Evidence Vault (127) · IOC Fusion (43) · OSINT Engine · DFIR Workbench</div>
            <div class="msg-meta">INTELFUSE AI · Just now</div>
          </div>
        </div>

        ${DATA.aiConversations[0].msgs.map(m => aiMsgHTML(m)).join('')}
      </div>

      <div class="ai-input-area">
        <div class="ai-quick-btns">
          ${[
            "What assets are connected to this domain?",
            "Show all related indicators",
            "Which findings are highest priority?",
            "Build chronological incident timeline",
            "Explain why these events may be related",
            "Generate investigation report",
          ].map(q=>`<button class="ai-quick-btn" onclick="sendAIMessage('${q.replace(/'/g,"\\\'")}')">${q}</button>`).join('')}
        </div>
        <div class="ai-input-row">
          <textarea class="ai-input" id="ai-input" placeholder="Ask anything about the investigation — assets, IOCs, findings, timelines, relationships..." rows="1" onkeydown="handleAIKey(event)"></textarea>
          <button class="ai-send-btn" onclick="sendAIMessage()">${ICONS.send}</button>
        </div>
      </div>
    </div>
  </div>`;
}

function aiMsgHTML(m) {
  return `<div class="ai-msg ${m.role}">
    <div class="msg-avatar ${m.role}">${m.role==='ai'?'IX':'A1'}</div>
    <div>
      <div class="msg-bubble">${m.text.replace(/\*\*(.*?)\*\*/g,'<strong>$1</strong>').replace(/\n/g,'<br>')}</div>
      ${m.cites ? `<div class="msg-cite">Sources: ${m.cites.join(' · ')}</div>` : ''}
      <div class="msg-meta">${m.role==='ai'?'INTELFUSE AI':'Analyst 01'} · ${m.time}</div>
    </div>
  </div>`;
}

window.handleAIKey = (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendAIMessage(); } };

window.sendAIMessage = (preset) => {
  const input = document.getElementById('ai-input');
  const text = preset || input?.value?.trim();
  if (!text) return;
  if (input) input.value = '';

  const msgs = document.getElementById('ai-messages');
  if (!msgs) return;

  // User message
  const userMsg = document.createElement('div');
  userMsg.innerHTML = aiMsgHTML({ role: 'user', text, time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) });
  msgs.appendChild(userMsg.firstElementChild);

  // Typing indicator
  const typingEl = document.createElement('div');
  typingEl.className = 'ai-msg ai';
  typingEl.id = 'ai-typing';
  typingEl.innerHTML = `<div class="msg-avatar ai">IX</div><div><div class="msg-bubble"><div class="typing-indicator"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div></div></div>`;
  msgs.appendChild(typingEl);
  msgs.scrollTop = msgs.scrollHeight;

  // Simulate AI response
  setTimeout(() => {
    typingEl.remove();
    const response = getAIResponse(text);
    const aiMsg = document.createElement('div');
    aiMsg.innerHTML = aiMsgHTML({ role: 'ai', text: response.text, time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }), cites: response.cites });
    msgs.appendChild(aiMsg.firstElementChild);
    msgs.scrollTop = msgs.scrollHeight;
  }, 1500 + Math.random() * 1000);
};

function getAIResponse(query) {
  const q = query.toLowerCase();
  if (q.includes('asset') || q.includes('connected') || q.includes('domain')) {
    return {
      text: `⬤ OBSERVED: **4 critical assets** are connected to example.com:\n\n**1. admin.example.com** — Exposed admin panel (CVSS 9.1 Critical). Unauthenticated access to Django admin interface confirmed.\n**2. api.example.com** — SQL Injection (CVSS 9.8 Critical). Blind SQLi in /login?id= parameter.\n**3. 185.220.101.45** — ⬤ INFERRED: This IP resolves to known APT-29 C2 infrastructure with 88% confidence.\n**4. mail.example.com** — Source of spear-phishing campaign targeting 14 employees.\n\n⬤ HYPOTHESIS: The exposure of admin.example.com may have been leveraged by the threat actor for initial reconnaissance prior to the phishing campaign.`,
      cites: ['Attack Surface', 'OSINT Engine', 'IOC Fusion', 'Threat Intelligence']
    };
  }
  if (q.includes('indicator') || q.includes('ioc')) {
    return {
      text: `⬤ OBSERVED: **43 IOCs** are currently tracked in this case. Top priority indicators:\n\n• **evil-c2.ru** (Domain) — APT-29 C2, Confidence 95%, CRITICAL\n• **185.220.101.45** (IP) — TOR exit node, Confidence 88%, HIGH\n• **a3f2bc...e891d4** (Hash) — LOCKBIT 3.0 payload, Confidence 99%, CRITICAL\n• **d8c1a0...7f3b22** (Hash) — Cobalt Strike Beacon, Confidence 97%, CRITICAL\n\n⬤ INFERRED: IOCs evil-c2.ru and 185.220.101.45 share infrastructure with 3 other known APT-29 campaigns per MISP feed correlation.`,
      cites: ['IOC Fusion', 'MISP Feed', 'Threat Intelligence']
    };
  }
  if (q.includes('priority') || q.includes('highest') || q.includes('finding')) {
    return {
      text: `⬤ OBSERVED: Ranked by severity and impact, the **highest priority findings** are:\n\n**[P1-CRITICAL]** Active C2 beacon on svchost PID 1337 → 185.220.101.45:4444. Network isolation required immediately.\n**[P1-CRITICAL]** SQL Injection on api.example.com — confirmed data exfiltration vector.\n**[P2-HIGH]** Lateral movement to 3 finance workstations — contain and reimage required.\n**[P2-HIGH]** LOCKBIT 3.0 ransomware artifacts present on Workstation-04.\n**[P3-MEDIUM]** AWS S3 public bucket exposes /assets/ directory listing.\n\nRecommendation: Initiate immediate network isolation of affected segments and disable api.example.com SQL endpoint.`,
      cites: ['DFIR Workbench', 'Attack Surface', 'Evidence Vault']
    };
  }
  if (q.includes('timeline') || q.includes('chronological')) {
    return {
      text: `⬤ OBSERVED: Chronological incident timeline:\n\n**2026-09-14 08:00** — APT-29 sends spear-phishing to 14 employees\n**09:03** — Employee opens malicious .docm, macros execute stager\n**09:07** — Cobalt Strike beacon injected into svchost PID 1337\n**10:15** — C2 channel established to 185.220.101.45:4444\n**2026-09-15** — Lateral movement via Pass-the-Hash to finance workstations\n**2026-09-18** — Data staging of sensitive documents in %TEMP%\n**2026-09-20 06:44** — LOCKBIT 3.0 deployed, 47 systems encrypted\n**07:15** — SOC detects incident via Wazuh SIEM alert\n\n⬤ INFERRED: Dwell time of **6 days** from initial compromise to ransomware deployment is consistent with APT-29 TTPs documented in CISA advisory.`,
      cites: ['Event Timeline', 'DFIR Workbench', 'Threat Intelligence', 'SIEM Logs']
    };
  }
  if (q.includes('report')) {
    return {
      text: `⬤ OBSERVED: I can generate a comprehensive investigation report for CASE-2026-0017 covering:\n\n• **Executive Summary** — High-level risk assessment and business impact\n• **Technical Findings** — 18 findings with evidence citations\n• **Attack Timeline** — Chronological sequence of events\n• **IOC Summary** — 43 indicators with confidence scores\n• **MITRE ATT&CK Mapping** — 31 techniques identified\n• **Evidence Chain** — 127 artifacts with SHA-256 hashes\n• **Recommendations** — Immediate, short-term, and long-term actions\n\nNavigating to Intel Reports to generate the full report...`,
      cites: ['All Modules', 'Evidence Vault', 'DFIR Workbench']
    };
  }
  // Default
  return {
    text: `⬤ OBSERVED: Based on my RAG analysis of the evidence collected for CASE-2026-0017, I can provide intelligence on **domains, IPs, IOCs, vulnerabilities, memory artifacts, network captures, and threat actor TTPs**.\n\n⬤ INFERRED: The current investigation shows strong attribution to APT-29 with moderate-to-high confidence (85%) based on C2 infrastructure overlap, phishing kit signature, and LOCKBIT 3.0 affiliate partnership patterns.\n\nCould you clarify what specific aspect of the investigation you'd like me to analyze? I can correlate evidence, explain relationships, assess risk, or generate a formal report.`,
    cites: ['INTELFUSE AI Engine', 'RAG Context', 'All Case Evidence']
  };
}

window.newAIConversation = () => {
  const msgs = document.getElementById('ai-messages');
  if (msgs) msgs.innerHTML = '';
};

// ══════════ INTEL REPORT ══════════
function renderReport(el) {
  el.innerHTML = `
  <div class="page-header fade-in-up">
    <div><div class="page-title">Intel Reports</div><div class="page-subtitle">AI-generated investigation reports with evidence citations</div></div>
    <div class="page-actions">
      <button class="btn btn-secondary">${ICONS.download} Export PDF</button>
      <button class="btn btn-primary" onclick="generateNewReport()">Generate Report</button>
    </div>
  </div>

  <div class="grid-2 fade-in-up" style="margin-bottom:20px">
    <!-- REPORT CONTENT -->
    <div style="grid-column:1 / -1" class="card">
      <div class="card-header" style="background:linear-gradient(135deg,rgba(255,61,61,0.08),rgba(123,47,247,0.05))">
        <div>
          <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);margin-bottom:4px">INTELLIGENCE REPORT · CONFIDENTIAL</div>
          <div class="card-title" style="font-size:1.2rem">CASE-2026-0017 — APT-29 Compromise Investigation</div>
        </div>
        <div style="text-align:right">
          <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted)">Generated: ${new Date().toLocaleDateString()}</div>
          <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted)">Analyst: Analyst 01</div>
          <div style="margin-top:4px"><span class="badge badge-critical">CLASSIFICATION: TLP:RED</span></div>
        </div>
      </div>
      <div class="card-body">

        <div class="report-section">
          <div class="report-section-title">${icon('alert')} Executive Summary</div>
          <div class="report-body">
            A sophisticated cyberattack attributed with <strong>HIGH confidence to APT-29 (Cozy Bear)</strong>, a Russian state-sponsored threat actor, was detected targeting <strong>example.com</strong> and associated infrastructure. The attacker achieved initial access via spear-phishing on <strong>2026-09-14</strong>, established persistent C2 communication via a Cobalt Strike beacon, conducted lateral movement across 4 workstations, staged sensitive data, and ultimately deployed <strong>LOCKBIT 3.0 ransomware</strong> on <strong>2026-09-20</strong>, encrypting 47 systems.
          </div>
          <div class="report-highlight">
            <strong>Risk Level: CRITICAL</strong> — Active threat actor with established C2 channel. Immediate containment actions required. Estimated business impact: $2.4M–$4.8M based on downtime, recovery, and data breach costs.
          </div>
        </div>

        <div class="report-section">
          <div class="report-section-title">${icon('zap')} Key Findings (Top 5)</div>
          <div style="overflow-x:auto">
            <table class="data-table">
              <thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Evidence</th><th>Status</th></tr></thead>
              <tbody>
                ${[
                  ['F-01','Active Cobalt Strike C2 Beacon in svchost.exe PID 1337','CRITICAL','EVD-0001 (Memory Dump)','ACTIVE'],
                  ['F-02','SQL Injection CVSS 9.8 on api.example.com/login','CRITICAL','EVD-0002 (PCAP)','OPEN'],
                  ['F-03','LOCKBIT 3.0 Ransomware Deployed on 47 Systems','CRITICAL','EVD-0003 (Malware Sample)','CONTAINED'],
                  ['F-04','Data Exfiltration via Encrypted C2 — sensitive_data.xlsx','HIGH','EVD-0006 (SMTP Logs)','INVESTIGATING'],
                  ['F-05','Exposed Admin Panel on admin.example.com (CVSS 9.1)','CRITICAL','OSINT Results','OPEN'],
                ].map(([id,finding,sev,evd,status])=>`<tr>
                  <td class="mono">${id}</td>
                  <td style="font-weight:600">${finding}</td>
                  <td><span class="badge ${sev==='CRITICAL'?'badge-critical':'badge-high'}">${sev}</span></td>
                  <td class="mono" style="font-size:0.7rem">${evd}</td>
                  <td><span class="badge ${status==='ACTIVE'?'badge-critical':status==='OPEN'?'badge-high':status==='CONTAINED'?'badge-safe':'badge-medium'}">${status}</span></td>
                </tr>`).join('')}
              </tbody>
            </table>
          </div>
        </div>

        <div class="report-section">
          <div class="report-section-title">${icon('shield')} Attribution Analysis</div>
          <div class="report-body">
            Attribution to <strong>APT-29</strong> is assessed with <strong>85% confidence</strong> based on the following indicators:
            <ul style="margin-top:8px;margin-left:20px;display:flex;flex-direction:column;gap:6px">
              <li>C2 domain evil-c2.ru shares registrar, ASN, and nameserver patterns with 3 previously attributed APT-29 campaigns</li>
              <li>Cobalt Strike beacon configuration (jitter: 50ms, sleep: 30s) matches known APT-29 profiles in MISP database</li>
              <li>LOCKBIT 3.0 affiliate pattern consistent with APT-29 ransomware-as-a-service partnership documented in NSA advisory</li>
              <li>Phishing email infrastructure (SMTP headers, template design) matches APT-29 spear-phishing toolkit v4</li>
            </ul>
          </div>
        </div>

        <div class="report-section">
          <div class="report-section-title">${icon('activity')} IOC Summary</div>
          <div style="overflow-x:auto">
            <table class="data-table">
              <thead><tr><th>IOC ID</th><th>Type</th><th>Indicator</th><th>Threat</th><th>Confidence</th></tr></thead>
              <tbody>
                ${DATA.iocs.slice(0,6).map(ioc=>`<tr>
                  <td class="mono">${ioc.id}</td>
                  <td><span class="badge badge-info">${ioc.type}</span></td>
                  <td class="mono" style="color:var(--${ioc.severity==='CRITICAL'?'red':'orange'})">${ioc.value}</td>
                  <td style="font-size:0.78rem">${ioc.threat}</td>
                  <td class="mono">${ioc.confidence}%</td>
                </tr>`).join('')}
              </tbody>
            </table>
          </div>
        </div>

        <div class="report-section">
          <div class="report-section-title">${icon('box')} Recommendations</div>
          <div class="report-body">
            <div style="display:flex;flex-direction:column;gap:10px">
              ${[
                ['IMMEDIATE (0-24h)','Isolate affected network segments · Terminate svchost PID 1337 · Block 185.220.101.45 and evil-c2.ru at perimeter · Reset all compromised credentials','red'],
                ['SHORT-TERM (1-7 days)','Patch SQL injection on api.example.com · Disable public admin panel · Reimage 47 affected workstations · Deploy EDR on all endpoints','amber'],
                ['LONG-TERM (1-4 weeks)','Implement Zero Trust architecture · Deploy Wazuh SIEM across all systems · Conduct phishing awareness training · Implement MFA on all external-facing services','cyan'],
              ].map(([phase,actions,color])=>`
              <div style="padding:12px;border-left:3px solid var(--${color});background:rgba(${color==='red'?'255,61,61':color==='amber'?'255,184,0':'0,212,255'},0.05);border-radius:0 var(--radius-sm) var(--radius-sm) 0">
                <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--${color});margin-bottom:6px;font-weight:700">${phase}</div>
                <div style="font-size:0.78rem;color:var(--text-secondary)">${actions}</div>
              </div>`).join('')}
            </div>
          </div>
        </div>

        <div style="margin-top:24px;padding-top:16px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
          <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted)">
            Report ID: RPT-2026-0017-001 · Classification: TLP:RED · Prepared by: Analyst 01
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-secondary" style="font-size:0.72rem">${ICONS.download} Export PDF</button>
            <button class="btn btn-primary" style="font-size:0.72rem" onclick="showPage('ai')">AI Deep-Dive</button>
          </div>
        </div>

      </div>
    </div>
  </div>`;
}

function generateNewReport() { showToast('AI generating investigation report — synthesizing 127 evidence items...'); }

// ══════════ MODAL SYSTEM ══════════
function openModal(title, body, actions = []) {
  const overlay = document.getElementById('modal-overlay');
  const box = document.getElementById('modal-box');
  box.innerHTML = `
    <div class="modal-header">
      <div class="modal-title">${title}</div>
      <button class="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body">${body}</div>
    <div class="modal-footer">
      ${actions.map(a=>`<button class="btn ${a.primary?'btn-primary':'btn-secondary'}" onclick="(${a.action})()">${a.label}</button>`).join('')}
    </div>`;
  overlay.classList.remove('hidden');
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });
}

function closeModal() { document.getElementById('modal-overlay').classList.add('hidden'); }

// ══════════ TOAST ══════════
function showToast(msg) {
  const toast = document.createElement('div');
  toast.style.cssText = `position:fixed;bottom:24px;right:24px;z-index:9999;padding:12px 20px;background:linear-gradient(135deg,rgba(11,21,38,0.98),rgba(7,15,31,0.98));border:1px solid var(--border-bright);border-radius:10px;color:var(--text-primary);font-size:0.8rem;box-shadow:0 8px 30px rgba(0,0,0,0.6),0 0 20px rgba(0,212,255,0.1);backdrop-filter:blur(20px);animation:fadeInMsg 0.3s ease;max-width:360px;line-height:1.5`;
  toast.innerHTML = `<div style="display:flex;align-items:center;gap:10px"><div class="status-dot active"></div>${msg}</div>`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

// ══════════ BOOT ══════════
window.addEventListener('DOMContentLoaded', bootSplash);
