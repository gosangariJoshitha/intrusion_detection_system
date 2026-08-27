const LS_KEY = 'aids_backend_url';
let backendUrl = localStorage.getItem(LS_KEY) || 'http://localhost:8000';
let ws = null;
let currentMode = 'simulated';
let events = [];
const MAX_EVENTS = 300;
let chartBuckets = [];
const BUCKET_SECONDS = 10, MAX_BUCKETS = 30;
let protoCounts = { 'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 'Other': 0 };
let totalProtos = 0;

document.getElementById('backendUrl').value = backendUrl;



function showToast(msg) {
  const t = document.getElementById('toast');
  document.getElementById('toastMsg').textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

async function triggerResponse(action, target) {
  try {
    const res = await fetch(backendUrl + '/api/response', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({action, target, reason: "Manual analyst action"})
    });
    if(res.ok) showToast(`${action} applied to ${target} and logged.`);
  } catch(e) { console.error(e); }
}

async function updateIncidentStatus(id, selectEl) {
  const status = selectEl.value;
  try {
    await fetch(backendUrl + `/api/incidents/${id}/status`, {
      method: 'PATCH', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({status})
    });
    showToast(`Incident #${id} updated to ${status}.`);
  } catch(e) { console.error(e); }
}

async function correctLabel(eventId, label) {
  try {
    const res = await fetch(backendUrl + `/api/events/${eventId}/label`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({label})
    });
    if(res.ok) showToast(`Event marked for retraining as ${label}.`);
  } catch(e) { console.error(e); }
}

async function triggerRetrain() {
  const btn = document.getElementById('retrainBtn');
  const status = document.getElementById('retrainStatus');
  btn.disabled = true;
  status.textContent = 'Retraining models... this may take a moment.';
  try {
    const res = await fetch(backendUrl + '/api/retrain', {method: 'POST'});
    const data = await res.json();
    if (data.status === 'success') {
       status.textContent = `Success! ${data.message}`;
       showToast("Models retrained and reloaded successfully.");
    } else {
       status.textContent = data.message;
    }
  } catch(e) { 
    status.textContent = 'Retraining failed. See console.';
  }
  btn.disabled = false;
}

async function fetchIncidents() {
  if(!backendUrl) return;
  try {
    const res = await fetch(backendUrl + '/api/incidents');
    const data = await res.json();
    const tbody = document.getElementById('incidentsBody');
    tbody.innerHTML = data.map(i => `
      <tr>
        <td>#${i.id}</td>
        <td class="mono" style="color:var(--text-muted);">${new Date(i.updated_at).toLocaleTimeString()}</td>
        <td class="ip" onclick="openIpModal('${i.source_ip}')">${i.source_ip}</td>
        <td class="attack-type">${i.attack_type}</td>
        <td>${sevBadge(i.severity)}</td>
        <td>
          <select onchange="updateIncidentStatus(${i.id}, this)">
            <option value="New" ${i.status==='New'?'selected':''}>New</option>
            <option value="Investigating" ${i.status==='Investigating'?'selected':''}>Investigating</option>
            <option value="Contained" ${i.status==='Contained'?'selected':''}>Contained</option>
            <option value="Resolved" ${i.status==='Resolved'?'selected':''}>Resolved</option>
          </select>
        </td>
      </tr>
    `).join('');
  } catch(e) {}
}

async function fetchHistory() {
  if(!backendUrl) return;
  try {
    const res = await fetch(backendUrl + '/api/events?limit=100');
    const data = await res.json();
    const tbody = document.getElementById('historyBody');
    tbody.innerHTML = data.map(e => `
      <tr>
        <td class="mono" style="color:var(--text-muted);">${new Date(e.timestamp).toLocaleTimeString()}</td>
        <td class="ip" onclick="openIpModal('${e.source_ip}')">${e.source_ip}</td>
        <td class="ip">${e.url ? e.url + '<br><span style="font-size:10px; color:var(--text-muted);">' + e.dest_ip + '</span>' : e.dest_ip}</td>
        <td><span class="proto-badge">${e.protocol}</span></td>
        <td>${e.status === 'Normal' ? '<span class="badge badge-normal">Normal</span>' : (e.status === 'Anomaly' ? '<span class="badge" style="background:rgba(245,185,66,0.15); color:var(--amber);">Anomaly</span>' : '<span class="badge badge-intrusion">Intrusion</span>')}</td>
        <td class="attack-type">${e.attack_type || '—'}</td>
        <td>${sevBadge(e.severity)}</td>
      </tr>
      </tr>
    `).join('');
  } catch(e) {}
}

async function fetchAudit() {
  if(!backendUrl) return;
  try {
    const res = await fetch(backendUrl + '/api/audit?limit=100');
    const data = await res.json();
    const tbody = document.getElementById('auditBody');
    tbody.innerHTML = data.map(a => `
      <tr>
        <td class="mono" style="color:var(--text-muted);">${new Date(a.timestamp).toLocaleTimeString()}</td>
        <td><span class="badge" style="background:rgba(255,255,255,0.1);">${a.actor}</span></td>
        <td><span class="proto-badge">${a.action}</span></td>
        <td class="mono">${a.target}</td>
        <td>${a.reason}</td>
        <td><span style="color:var(--green)">${a.status}</span></td>
      </tr>
    `).join('');
  } catch(e) {}
}

let activeIp = '';
async function openIpModal(ip) {
  activeIp = ip;
  document.getElementById('modalIp').textContent = ip;
  document.getElementById('ipModal').classList.add('open');
  try {
    const res = await fetch(backendUrl + '/api/ip/' + ip);
    const data = await res.json();
    document.getElementById('modalEvents').textContent = data.total_events;
    document.getElementById('modalIntrusions').textContent = data.intrusion_count;
    document.getElementById('modalIncidents').textContent = data.incidents;
    document.getElementById('modalAttacks').textContent = data.attack_types.length ? data.attack_types.join(', ') : 'None';
    
    // Fetch TI Enrichment
    document.getElementById('tiLocation').textContent = 'Loading...';
    document.getElementById('tiAsn').textContent = 'Loading...';
    document.getElementById('tiRiskBadge').textContent = '...';
    document.getElementById('tiRiskBadge').style.background = 'transparent';
    document.getElementById('tiTagsWrap').style.display = 'none';
    
    const tiRes = await fetch(backendUrl + '/api/ip/' + ip + '/enrich');
    const tiData = await tiRes.json();
    
    document.getElementById('tiLocation').textContent = tiData.country;
    document.getElementById('tiAsn').textContent = tiData.asn;
    
    const badge = document.getElementById('tiRiskBadge');
    badge.textContent = `RISK SCORE: ${tiData.risk_score}`;
    if(tiData.risk_score > 70) {
      badge.style.background = 'rgba(240,82,90,0.15)'; badge.style.color = 'var(--red)';
    } else if (tiData.risk_score > 30) {
      badge.style.background = 'rgba(245,185,66,0.15)'; badge.style.color = 'var(--amber)';
    } else {
      badge.style.background = 'rgba(52,225,161,0.15)'; badge.style.color = 'var(--green)';
    }
    
    if(tiData.tags && tiData.tags.length > 0) {
      const wrap = document.getElementById('tiTagsWrap');
      wrap.style.display = 'flex';
      wrap.innerHTML = tiData.tags.map(t => `<span style="font-size:10px; background:rgba(255,255,255,0.05); padding:3px 6px; border-radius:4px; color:var(--text-secondary);">${t}</span>`).join('');
    }
    
  } catch(e) {}
}
function closeIpModal() { document.getElementById('ipModal').classList.remove('open'); }
function blockModalIp() { triggerResponse('BLOCK_IP', activeIp); closeIpModal(); }

// ---------------- Backend Connection ----------------
function toWsUrl(httpUrl){ return httpUrl.trim().replace(/\/+$/,'').replace(/^http/,'ws') + '/ws'; }

function connect(){
  backendUrl = document.getElementById('backendUrl').value.trim().replace(/\/+$/,'');
  if(!backendUrl) return;
  localStorage.setItem(LS_KEY, backendUrl);
  if(ws) try{ ws.close(); }catch(e){}
  
  if(document.getElementById('liveBadgeText')) document.getElementById('liveBadgeText').textContent = 'Connecting…';
  
  ws = new WebSocket(toWsUrl(backendUrl));
  ws.onopen = () => {
    if(document.getElementById('liveBadgeText')) document.getElementById('liveBadgeText').textContent = 'Live sync active';
    if(document.getElementById('liveBadge')) document.getElementById('liveBadge').style.color = 'var(--green)';
    if(document.getElementById('opStatus')) document.getElementById('opStatus').textContent = 'nominal';
    if(document.getElementById('nodeCount')) document.getElementById('nodeCount').textContent = '— Connected securely';
    if(document.getElementById('attackAvgFoot')) document.getElementById('attackAvgFoot').textContent = 'Total since boot';
    if(document.getElementById('detAccFoot')) document.getElementById('detAccFoot').textContent = 'Real-time inference';
    if(document.getElementById('uptimeFoot')) document.getElementById('uptimeFoot').textContent = 'Seconds';
    if(document.getElementById('connectBtn')) {
      document.getElementById('connectBtn').textContent = 'Connected';
      document.getElementById('connectBtn').style.background = 'rgba(52,225,161,0.25)';
    }
  };
  ws.onmessage = (msg) => {
    let data;
    try{ data = JSON.parse(msg.data); } catch(e){ return; }
    if(data.type === 'hello') { currentMode = data.mode; return; }
    ingestEvent(data);
  };
  ws.onclose = () => {
    if(document.getElementById('liveBadgeText')) document.getElementById('liveBadgeText').textContent = 'Disconnected';
    if(document.getElementById('liveBadge')) document.getElementById('liveBadge').style.color = 'var(--red)';
    if(document.getElementById('connectBtn')) {
      document.getElementById('connectBtn').textContent = 'Connect';
      document.getElementById('connectBtn').style.background = '';
    }
    setTimeout(connect, 3000);
  };
}
document.getElementById('connectBtn').addEventListener('click', connect);

function sevBadge(sev){
  if(sev === 'CRITICAL') return `<span class="sev-badge sev-critical">CRITICAL</span>`;
  if(sev === 'LOW') return `<span class="sev-badge sev-low">LOW</span>`;
  return `<span class="sev-badge sev-none">—</span>`;
}

// ---------------- Packet Inspector ----------------
function openInspector(eventId) {
  const e = events.find(x => x.id === eventId);
  if(!e) return;
  const p = document.getElementById('inspectorPanel');
  if(!p) return;
  
  document.getElementById('inspMeta').innerHTML = `
    <div><b>Timestamp:</b> ${e.time}</div>
    <div><b>Source:</b> ${e.src}</div>
    <div><b>Destination:</b> ${e.dst}</div>
    <div><b>Protocol:</b> ${e.proto}</div>
    <div><b>Packet Size:</b> src=${e.src_bytes}B, dst=${e.dst_bytes}B</div>
  `;
  
  // Generate mock hex dump
  let hex = '';
  const bytes = Math.min(e.src_bytes + 20, 256); // max 256 bytes for display
  for(let i=0; i<bytes; i+=16) {
    hex += `<span class="hd-offset">${i.toString(16).padStart(4,'0')}0</span>`;
    let hexRow = '';
    let asciiRow = '';
    for(let j=0; j<16; j++) {
      if(i+j < bytes) {
        const val = Math.floor(Math.random() * 256);
        hexRow += val.toString(16).padStart(2,'0') + ' ';
        asciiRow += (val >= 32 && val <= 126) ? String.fromCharCode(val) : '.';
      } else {
        hexRow += '   ';
        asciiRow += ' ';
      }
    }
    hex += `<span class="hd-hex">${hexRow}</span><span class="hd-ascii">${asciiRow.replace(/</g,'&lt;')}</span>\n`;
  }
  
  document.getElementById('hexDump').innerHTML = hex;
  p.classList.add('open');
}

function closeInspector() {
  const p = document.getElementById('inspectorPanel');
  if(p) p.classList.remove('open');
}

function ingestEvent(e){
  e._new = true;
  events.unshift(e);
  if(events.length > MAX_EVENTS) events.pop();
  bucketEvent(e);
  
  // Track protocols
  const p = (e.proto || 'Other').toUpperCase();
  if (protoCounts[p] !== undefined) protoCounts[p]++;
  else protoCounts['Other']++;
  totalProtos++;
  
  renderEvents();
  renderChart();
  renderProtoChart();
  
  if(e.severity === 'CRITICAL') {
    sendNotification('Critical Threat Detected', `Intrusion from ${e.src} to ${e.dst} via ${e.proto}\nType: ${e.attack_type}`);
    
    // Add to ticker
    const ticker = document.getElementById('tickerContent');
    if (ticker) {
      const el = document.createElement('span');
      el.className = 'ticker-item';
      el.innerHTML = `[${e.time}] <b>CRITICAL:</b> ${e.attack_type} from ${e.src} to ${e.dst} (${e.proto})`;
      ticker.prepend(el);
      // keep only last 5 in ticker
      while(ticker.children.length > 5) ticker.removeChild(ticker.lastChild);
      
      // restart animation to avoid glitches if appending while scrolling
      ticker.style.animation = 'none';
      ticker.offsetHeight; 
      ticker.style.animation = null;
    }
  }
}

function renderEvents(){
  const searchInput = document.getElementById('searchInput');
  const search = searchInput ? searchInput.value.trim().toLowerCase() : '';
  const filtered = events.filter(e => search ? (e.src.includes(search) || (e.attack_type||'').toLowerCase().includes(search)) : true);
  
  const body = document.getElementById('eventsBody');
  if(!body) return;
  body.innerHTML = filtered.slice(0,50).map(e=>`
    <tr class="${e._new ? 'new-row' : ''}">
      <td class="mono" style="color:var(--text-muted);">${e.time}</td>
      <td class="ip" onclick="openIpModal('${e.src}')">${e.src}</td>
      <td class="ip">${e.url ? e.url + '<br><span style="font-size:10px; color:var(--text-muted);">' + e.dst + '</span>' : e.dst}</td>
      <td><span class="proto-badge">${e.proto}</span></td>
      <td>${e.status === 'Normal' ? '<span class="badge badge-normal">Normal</span>' : (e.status === 'Anomaly' ? '<span class="badge" style="background:rgba(245,185,66,0.15); color:var(--amber);">Anomaly</span>' : '<span class="badge badge-intrusion">Intrusion</span>')}</td>
      <td class="attack-type">${e.attack_type || '—'}</td>
      <td>${sevBadge(e.severity)}</td>
      <td class="${e.confidence >= 95 ? 'conf-high' : 'conf-low'}">${(e.confidence*1).toFixed(1)}%</td>
      <td>
        <div class="action-icons">
          <button title="Inspect Packet" onclick="openInspector('${e.id}')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg></button>
          <button title="Block IP" onclick="triggerResponse('BLOCK_IP', '${e.src}')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h7l-1 8 11-14h-7l1-6z"/></svg></button>
          <button title="Mark as Normal (Correct Label)" onclick="correctLabel('${e.id}', 'Normal')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12l5 5L20 7"/></svg></button>
        </div>
      </td>
    </tr>
  `).join('');
  events.forEach(e => e._new = false);
}
if (document.getElementById('searchInput')) {
  document.getElementById('searchInput').addEventListener('input', renderEvents);
}

// ---------------- Chart & Metrics ----------------
function bucketEvent(e){
  const now = Math.floor(Date.now()/1000 / BUCKET_SECONDS) * BUCKET_SECONDS;
  let b = chartBuckets[chartBuckets.length-1];
  if(!b || b.t !== now){
    b = { t: now, requests: 0, threats: 0 };
    chartBuckets.push(b);
    if(chartBuckets.length > MAX_BUCKETS) chartBuckets.shift();
  }
  b.requests += 1;
  if(e.status !== 'Normal') b.threats += 1;
}

function renderChart(){
  const svg = document.getElementById('chartSvg');
  if(!svg) return;
  if(chartBuckets.length < 2) return;
  const W = 760, H = 210, PAD = 20;
  const maxReq = Math.max(...chartBuckets.map(b=>b.requests), 4) * 1.25;
  const stepX = (W - PAD*2) / (chartBuckets.length - 1);
  
  let areaD = `M${PAD},${H-PAD}`, reqD = '', thrD = '';
  chartBuckets.forEach((b,i) => {
    const x = PAD + i*stepX;
    const reqY = H - PAD - (b.requests/maxReq)*(H-PAD*2);
    const thrY = H - PAD - (b.threats/maxReq)*(H-PAD*2);
    areaD += ` L${x},${reqY}`;
    reqD += (i===0 ? `M${x},${reqY}` : `L${x},${reqY}`);
    thrD += (i===0 ? `M${x},${thrY}` : `L${x},${thrY}`);
  });
  areaD += ` L${W-PAD},${H-PAD} Z`;

  svg.innerHTML = `
    <defs><linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#34e7a6" stop-opacity="0.35"/><stop offset="100%" stop-color="#34e7a6" stop-opacity="0"/></linearGradient></defs>
    <path d="${areaD}" fill="url(#areaFill)"/><path d="${reqD}" fill="none" stroke="#34e7a6" stroke-width="2.5"/><path d="${thrD}" fill="none" stroke="#f0525a" stroke-width="1.5" opacity="0.85"/>
  `;
}

function renderProtoChart() {
  const chart = document.getElementById('protoChart');
  const legend = document.getElementById('protoLegend');
  if(!chart || !legend) return;
  
  if(totalProtos === 0) return;
  
  const colors = { 'TCP': '#38bdf8', 'UDP': '#34e7a6', 'ICMP': '#f5b942', 'DNS': '#a855f7', 'Other': '#5a6b63' };
  let currentAngle = 0;
  let gradientStops = [];
  let legendHtml = '';
  
  // Sort by count
  const sorted = Object.entries(protoCounts).sort((a,b)=>b[1]-a[1]);
  
  sorted.forEach(([proto, count]) => {
    if(count === 0) return;
    const pct = count / totalProtos;
    const angle = pct * 100;
    gradientStops.push(`${colors[proto]} ${currentAngle}% ${currentAngle + angle}%`);
    currentAngle += angle;
    
    legendHtml += `
      <div class="proto-legend-item">
        <span><span class="dot" style="background:${colors[proto]}; display:inline-block; margin-right:8px;"></span>${proto}</span>
        <b>${(pct*100).toFixed(1)}%</b>
      </div>
    `;
  });
  
  chart.style.background = `conic-gradient(${gradientStops.join(', ')})`;
  legend.innerHTML = legendHtml;
}

async function updateMetrics() {
  if(!backendUrl) return;
  try{
    const res = await fetch(backendUrl + '/metrics');
    const m = await res.json();
    
    if(m.binary_accuracy) {
      if(document.getElementById('metricBinAcc')) document.getElementById('metricBinAcc').textContent = (m.binary_accuracy*100).toFixed(1)+'%';
      const fill = document.getElementById('metricBinFill');
      if(fill) fill.style.width = (m.binary_accuracy*100)+'%';
    }
    if(m.multiclass_accuracy) {
      if(document.getElementById('metricMultiAcc')) document.getElementById('metricMultiAcc').textContent = (m.multiclass_accuracy*100).toFixed(1)+'%';
      if(document.getElementById('metricMultiFill')) document.getElementById('metricMultiFill').style.width = (m.multiclass_accuracy*100)+'%';
    }
  } catch(e) {}
}

async function pollHealth() {
  if(!backendUrl) return;
  try{
    const res = await fetch(backendUrl + '/health');
    const data = await res.json();
    document.getElementById('activeThreats').textContent = data.intrusions_detected;
    document.getElementById('attackAvg').textContent = data.events_processed;
    if (data.uptime_seconds != null) {
      document.getElementById('uptime').textContent = data.uptime_seconds.toFixed(0);
    }
    
    if(data.avg_confidence != null) {
      document.getElementById('detAcc').textContent = data.avg_confidence.toFixed(1);
    }

    if(data.drift_score != null) {
      const badge = document.getElementById('driftBadge');
      badge.style.display = 'flex';
      document.getElementById('driftVal').textContent = data.drift_score.toFixed(1);
      
      const rtStatus = document.getElementById('retrainStatus');
      if (data.drift_status === 'CRITICAL') {
        badge.style.color = 'var(--red)';
        badge.style.borderColor = 'rgba(240,82,90,0.3)';
        badge.style.background = 'rgba(240,82,90,0.1)';
        if(!rtStatus.textContent.includes('Retraining')) rtStatus.textContent = '⚠️ CRITICAL DRIFT DETECTED: Retraining highly recommended.';
      } else if (data.drift_status === 'WARNING') {
        badge.style.color = 'var(--amber)';
        badge.style.borderColor = 'rgba(245,185,66,0.3)';
        badge.style.background = 'rgba(245,185,66,0.1)';
        if(!rtStatus.textContent.includes('Retraining')) rtStatus.textContent = 'Data distribution shifting. Retraining suggested.';
      } else {
        badge.style.color = 'var(--green)';
        badge.style.borderColor = 'var(--border)';
        badge.style.background = 'rgba(52,225,161,0.05)';
        if(rtStatus.textContent.includes('DRIFT')) rtStatus.textContent = '';
      }
    }
  } catch(e) {}
}

// ---------------- Notifications & CSV Export ----------------
document.addEventListener('DOMContentLoaded', () => {
  if (Notification.permission !== "granted" && Notification.permission !== "denied") {
    Notification.requestPermission();
  }
});

function sendNotification(title, body) {
  if (Notification.permission === "granted") {
    new Notification(title, { body: body, icon: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjZjA1MjVhIiBzdHJva2Utd2lkdGg9IjIiPjxwYXRoIGQ9Ik0xMiAyTDIgMjJoMjBMMTIgMnoiLz48cGF0aCBkPSJNMTIgOXY1TTEyIDE3aC4wMSIvPjwvc3ZnPg==' });
  }
}

function exportTableToCSV(tbodyId, filename) {
  const tbody = document.getElementById(tbodyId);
  let csv = [];
  
  // Extract headers
  const table = tbody.closest('table');
  if (table) {
    const headers = Array.from(table.querySelectorAll('thead th')).map(th => `"${th.innerText.replace(/"/g, '""')}"`);
    csv.push(headers.join(','));
  }

  // Extract rows
  const rows = tbody.querySelectorAll('tr');
  rows.forEach(row => {
    let rowData = [];
    row.querySelectorAll('td').forEach(col => {
      let data = col.innerText.replace(/(\r\n|\n|\r)/gm, ' ').replace(/"/g, '""');
      rowData.push(`"${data}"`);
    });
    csv.push(rowData.join(','));
  });

  // Download
  const csvFile = new Blob([csv.join('\n')], { type: "text/csv" });
  const downloadLink = document.createElement("a");
  downloadLink.download = filename;
  downloadLink.href = window.URL.createObjectURL(csvFile);
  downloadLink.style.display = "none";
  document.body.appendChild(downloadLink);
  downloadLink.click();
  document.body.removeChild(downloadLink);
  showToast(`Exported ${filename} successfully.`);
}
setInterval(pollHealth, 4000);

if(backendUrl) connect();

document.addEventListener('DOMContentLoaded', () => {
  const path = window.location.pathname;
  if(path.includes('incidents.html')) fetchIncidents();
  if(path.includes('history.html')) fetchHistory();
  if(path.includes('audit.html')) fetchAudit();
});