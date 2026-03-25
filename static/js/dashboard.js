/**
 * BotShield — Frontend Dashboard JS
 * Talks to the Python Flask /analyze endpoint.
 */

// ─── State ────────────────────────────────────────────────
let allRows      = [];
let currentFilter = 'all';
let donutChart   = null;
let timelineChart = null;
let fraudChart   = null;
let uaChart      = null;
let selectedFile = null;

const LOG_MSGS = [
  'Uploading CSV to Python backend...',
  'Parsing IP reputation data...',
  'Scanning User-Agent signatures...',
  'Checking AI crawler fingerprints...',
  'Running fraud score analysis...',
  'Detecting headless browsers...',
  'Classifying traffic patterns...',
  'Building threat profiles...',
  'Aggregating rule triggers...',
  'Generating intelligence report...',
];

// ─── File Handling ────────────────────────────────────────
const dropZone  = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('drag');
  const f = e.dataTransfer.files[0]; if (f) handleFile(f);
});
fileInput.addEventListener('change', e => { if (e.target.files[0]) handleFile(e.target.files[0]); });

function handleFile(file) {
  if (!file.name.endsWith('.csv')) { showError('Please upload a .csv file'); return; }
  selectedFile = file;
  document.getElementById('file-info').style.display = 'block';
  document.getElementById('file-name').textContent   = '◈ ' + file.name;
  document.getElementById('file-size-pre').textContent = (file.size / 1024).toFixed(1) + ' KB';
  document.getElementById('btn-analyze').disabled    = false;
  document.getElementById('dash-filename').textContent = file.name;
  hideError();
}

function showError(msg) {
  const el = document.getElementById('upload-error');
  el.textContent = '⚠ ' + msg;
  el.style.display = 'block';
}
function hideError() {
  document.getElementById('upload-error').style.display = 'none';
}

// ─── Start Analysis ───────────────────────────────────────
function startAnalysis() {
  if (!selectedFile) return;

  document.getElementById('upload-screen').style.display = 'none';
  const overlay = document.getElementById('analyzing');
  overlay.style.display = 'flex';

  // Animate the log while waiting for the server
  const log  = document.getElementById('analyze-log');
  const fill = document.getElementById('progress-fill');
  let step = 0;
  const total = LOG_MSGS.length - 1; // last step = server done
  const iv = setInterval(() => {
    if (step >= total) return; // hold last fake step until server responds
    fill.style.width = ((step + 1) / LOG_MSGS.length * 85) + '%'; // up to 85%
    const d = document.createElement('div');
    d.textContent = '> ' + LOG_MSGS[step];
    log.innerHTML = '';
    log.appendChild(d);
    step++;
  }, 250);

  // Upload to Flask
  const formData = new FormData();
  formData.append('file', selectedFile);

  fetch('/analyze', { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
      clearInterval(iv);
      if (data.error) { showUploadError(data.error); return; }

      fill.style.width = '100%';
      const d = document.createElement('div');
      d.textContent = '> ' + LOG_MSGS[LOG_MSGS.length - 1];
      log.innerHTML = '';
      log.appendChild(d);

      setTimeout(() => renderDashboard(data), 400);
    })
    .catch(err => {
      clearInterval(iv);
      showUploadError('Server error: ' + err.message);
    });
}

function showUploadError(msg) {
  document.getElementById('analyzing').style.display = 'none';
  document.getElementById('upload-screen').style.display = 'flex';
  showError(msg);
  document.getElementById('btn-analyze').disabled = false;
}

// ─── Dashboard Render ─────────────────────────────────────
function renderDashboard(data) {
  document.getElementById('analyzing').style.display  = 'none';
  document.getElementById('dashboard').style.display  = 'block';

  const { total, counts, avg_fraud, tor_count, vpn_count,
          donut, timeline, top_crawlers, top_rules, risk_score,
          fraud_dist, ua_breakdown, rows } = data;

  allRows = rows;
  renderStatCards(total, counts, avg_fraud, tor_count);
  renderDonut(donut, total);
  renderLegend(counts, total);
  renderAITable(top_crawlers);
  renderRules(top_rules);
  renderRisk(risk_score, counts, total, tor_count, vpn_count, avg_fraud);
  renderTimeline(timeline);
  renderFraudDist(fraud_dist);
  renderUABreakdown(ua_breakdown);
  renderSummary(data);
  renderTable();
}

// ─── Stat Cards ───────────────────────────────────────────
function renderStatCards(total, counts, avgFraud, torCount) {
  const cards = [
    { label:'Human Traffic',    val:counts.human,    color:'green',  sub:`${pct(counts.human,total)}% of total` },
    { label:'Bad Bots',         val:counts.bad,      color:'red',    sub:`${pct(counts.bad,total)}% of total` },
    { label:'AI Crawlers',      val:counts.ai,       color:'purple', sub:`${pct(counts.ai,total)}% of total` },
    { label:'Generic Crawlers', val:counts.crawler,  color:'amber',  sub:`${pct(counts.crawler,total)}% of total` },
    { label:'Avg Fraud Score',  val:avgFraud,        color:'blue',   sub:'out of 100' },
    { label:'TOR Traffic',      val:torCount,        color:'red',    sub:`${pct(torCount,total)}% of total` },
  ];
  document.getElementById('stats-row').innerHTML = cards.map(c => `
    <div class="stat-card c-${c.color}">
      <div class="stat-label">${c.label}</div>
      <div class="stat-val c-${c.color}">${c.val.toLocaleString()}</div>
      <div class="stat-pct">${c.sub}</div>
    </div>
  `).join('');
}

// ─── Donut Chart ──────────────────────────────────────────
function renderDonut(donut, total) {
  document.getElementById('donut-total').textContent = total.toLocaleString();
  if (donutChart) donutChart.destroy();
  const ctx = document.getElementById('donut-canvas').getContext('2d');
  donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels: donut.labels, datasets:[{
      data: donut.values, backgroundColor: donut.colors,
      borderColor:'#0f1117', borderWidth:3, hoverBorderWidth:5, hoverOffset:6,
    }]},
    options: {
      responsive:true, maintainAspectRatio:false, cutout:'72%',
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:'#141820', borderColor:'#2a3248', borderWidth:1,
          titleColor:'#e2e8f0', bodyColor:'#8892a4', padding:12,
          callbacks:{ label: c => ` ${c.label}: ${c.raw.toLocaleString()} (${pct(c.raw,total)}%)` }
        }
      },
      animation:{ animateRotate:true, duration:900, easing:'easeOutQuart' }
    }
  });
}

function renderLegend(counts, total) {
  const items = [
    {name:'Human Traffic', count:counts.human,   color:'#00ff88', type:'human'},
    {name:'Bad Bots',      count:counts.bad,     color:'#ff3b5c', type:'bad'},
    {name:'AI Crawlers',   count:counts.ai,      color:'#b56dff', type:'ai'},
    {name:'Crawlers',      count:counts.crawler, color:'#ffb800', type:'crawler'},
  ];
  document.getElementById('donut-legend').innerHTML = items.map(it => `
    <div class="legend-item" onclick="setFilter('${it.type}',null)">
      <div class="legend-left">
        <div class="legend-dot" style="background:${it.color}"></div>
        <div>${it.name}</div>
      </div>
      <div class="legend-right">
        <div class="legend-count" style="color:${it.color}">${it.count.toLocaleString()}</div>
        <div class="legend-pct">${pct(it.count,total)}%</div>
      </div>
    </div>
  `).join('');
}

// ─── AI Crawlers Table ────────────────────────────────────
function renderAITable(crawlers) {
  const max = crawlers[0]?.count || 1;
  document.getElementById('ai-table-body').innerHTML = crawlers.map(c => `
    <tr>
      <td>
        <div class="crawler-name">${c.name}</div>
        <div class="crawler-ua" title="${c.ua}">${c.ua}</div>
        <div style="height:3px;background:#1e2535;border-radius:2px;margin-top:6px">
          <div style="height:100%;width:${Math.round(c.count/max*100)}%;background:#b56dff;border-radius:2px"></div>
        </div>
      </td>
      <td style="text-align:right;color:#b56dff;font-family:'Syne',sans-serif;font-weight:700;font-size:15px">
        ${c.count.toLocaleString()}
      </td>
      <td style="min-width:100px">
        <div style="height:4px;background:#1e2535;border-radius:2px">
          <div style="height:100%;width:${Math.round(c.count/max*100)}%;background:#b56dff;border-radius:2px"></div>
        </div>
      </td>
    </tr>
  `).join('');
}

// ─── Detection Rules ──────────────────────────────────────
function renderRules(rules) {
  const max = rules[0]?.count || 1;
  document.getElementById('rules-grid').innerHTML = rules.map(r => `
    <div class="rule-item">
      <div class="rule-header">
        <div class="rule-name">${r.name}</div>
        <div class="rule-count">${r.count.toLocaleString()}</div>
      </div>
      <div class="rule-bar"><div class="rule-bar-fill" style="width:${Math.round(r.count/max*100)}%"></div></div>
      <div class="rule-desc">${r.desc}</div>
    </div>
  `).join('');
}

// ─── Risk Arc ─────────────────────────────────────────────
function renderRisk(score, counts, total, torCount, vpnCount, avgFraud) {
  const canvas = document.getElementById('risk-canvas');
  const ctx    = canvas.getContext('2d');
  const cx=100, cy=100, r=70, start=Math.PI*.75, end=Math.PI*2.25;
  ctx.clearRect(0,0,200,120);
  ctx.beginPath(); ctx.arc(cx,cy,r,start,end);
  ctx.strokeStyle='#1a1f2e'; ctx.lineWidth=14; ctx.lineCap='round'; ctx.stroke();
  const angle = start + (end-start)*(score/100);
  const grad  = ctx.createLinearGradient(30,cy,170,cy);
  grad.addColorStop(0,'#00ff88'); grad.addColorStop(.5,'#ffb800'); grad.addColorStop(1,'#ff3b5c');
  ctx.beginPath(); ctx.arc(cx,cy,r,start,angle);
  ctx.strokeStyle=grad; ctx.lineWidth=14; ctx.lineCap='round'; ctx.stroke();

  const color = score<30?'#00ff88':score<60?'#ffb800':'#ff3b5c';
  const label = score<30?'LOW RISK':score<60?'MODERATE RISK':'HIGH RISK';
  document.getElementById('risk-val').textContent  = score;
  document.getElementById('risk-val').style.color  = color;
  document.getElementById('risk-text').textContent = label;
  document.getElementById('risk-text').style.color = color;

  const badCount = (counts.bad||0) + (counts.ai||0);
  document.getElementById('risk-breakdown').innerHTML = [
    {label:'Bot Rate',        val:`${pct(badCount,total)}%`,  color:'#ff3b5c'},
    {label:'TOR Traffic',     val:`${pct(torCount,total)}%`,  color:'#ff3b5c'},
    {label:'VPN Traffic',     val:`${pct(vpnCount,total)}%`,  color:'#ffb800'},
    {label:'Avg Fraud Score', val:Math.round(avgFraud),       color:'#4d9fff'},
  ].map(it => `
    <div style="display:flex;justify-content:space-between;font-size:11px;padding:6px 0;border-top:1px solid #1e2535">
      <span style="color:#8892a4">${it.label}</span>
      <span style="color:${it.color};font-weight:600">${it.val}</span>
    </div>
  `).join('');
}

// ─── Timeline Chart ───────────────────────────────────────
function renderTimeline(buckets) {
  if (timelineChart) timelineChart.destroy();
  if (!buckets.length) return;
  const ctx = document.getElementById('timeline-canvas').getContext('2d');
  timelineChart = new Chart(ctx, {
    type:'bar',
    data:{
      labels: buckets.map(b=>b.label),
      datasets:[
        {label:'Human',      data:buckets.map(b=>b.human),   backgroundColor:'rgba(0,255,136,.7)',   borderRadius:2},
        {label:'Bad Bot',    data:buckets.map(b=>b.bad),     backgroundColor:'rgba(255,59,92,.7)',   borderRadius:2},
        {label:'AI Crawler', data:buckets.map(b=>b.ai),      backgroundColor:'rgba(181,109,255,.7)', borderRadius:2},
        {label:'Crawler',    data:buckets.map(b=>b.crawler), backgroundColor:'rgba(255,184,0,.7)',   borderRadius:2},
      ]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      interaction:{mode:'index',intersect:false},
      plugins:{
        legend:{display:true,position:'top',labels:{color:'#8892a4',font:{size:11},boxWidth:10,boxHeight:10,padding:16}},
        tooltip:{backgroundColor:'#141820',borderColor:'#2a3248',borderWidth:1,titleColor:'#e2e8f0',bodyColor:'#8892a4'}
      },
      scales:{
        x:{stacked:true,ticks:{color:'#4a5568',font:{size:10},maxRotation:45},grid:{color:'rgba(30,37,53,.8)'}},
        y:{stacked:true,ticks:{color:'#4a5568',font:{size:10}},grid:{color:'rgba(30,37,53,.8)'}}
      }
    }
  });
}

// ─── Fraud Distribution Chart ─────────────────────────────
function renderFraudDist(dist) {
  if (fraudChart) fraudChart.destroy();
  const ctx = document.getElementById('fraud-canvas').getContext('2d');
  fraudChart = new Chart(ctx, {
    type:'bar',
    data:{
      labels: dist.labels,
      datasets:[{
        label:'Requests', data:dist.values,
        backgroundColor: dist.values.map((_,i) => {
          const pctI = i / dist.values.length;
          return pctI < .4 ? 'rgba(0,255,136,.7)' : pctI < .7 ? 'rgba(255,184,0,.7)' : 'rgba(255,59,92,.7)';
        }),
        borderRadius:2
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        tooltip:{backgroundColor:'#141820',borderColor:'#2a3248',borderWidth:1,titleColor:'#e2e8f0',bodyColor:'#8892a4'}
      },
      scales:{
        x:{ticks:{color:'#4a5568',font:{size:9},maxRotation:45},grid:{color:'rgba(30,37,53,.8)'}},
        y:{ticks:{color:'#4a5568',font:{size:10}},grid:{color:'rgba(30,37,53,.8)'}}
      }
    }
  });
}

// ─── UA Breakdown Chart ───────────────────────────────────
function renderUABreakdown(ua) {
  if (uaChart) uaChart.destroy();
  const ctx = document.getElementById('ua-canvas').getContext('2d');
  uaChart = new Chart(ctx, {
    type:'doughnut',
    data:{
      labels:ua.labels,
      datasets:[{data:ua.values,backgroundColor:ua.colors,borderColor:'#0f1117',borderWidth:3}]
    },
    options:{
      responsive:true, maintainAspectRatio:false, cutout:'65%',
      plugins:{
        legend:{display:true,position:'bottom',labels:{color:'#8892a4',font:{size:11},boxWidth:10}},
        tooltip:{backgroundColor:'#141820',borderColor:'#2a3248',borderWidth:1,titleColor:'#e2e8f0',bodyColor:'#8892a4'}
      }
    }
  });
}

// ─── Quick Summary ────────────────────────────────────────
function renderSummary(data) {
  const {total, counts, avg_fraud, tor_count, vpn_count} = data;
  const items = [
    {label:'Total Requests',       val:total.toLocaleString(),                  color:'#e2e8f0'},
    {label:'Human Traffic',        val:`${counts.human.toLocaleString()} (${pct(counts.human,total)}%)`, color:'#00ff88'},
    {label:'Bad Bots',             val:`${counts.bad.toLocaleString()} (${pct(counts.bad,total)}%)`,     color:'#ff3b5c'},
    {label:'AI Crawlers',          val:`${counts.ai.toLocaleString()} (${pct(counts.ai,total)}%)`,       color:'#b56dff'},
    {label:'Generic Crawlers',     val:`${counts.crawler.toLocaleString()} (${pct(counts.crawler,total)}%)`, color:'#ffb800'},
    {label:'TOR Requests',         val:tor_count.toLocaleString(),              color:'#ff3b5c'},
    {label:'VPN Requests',         val:vpn_count.toLocaleString(),              color:'#ffb800'},
    {label:'Avg Fraud Score',      val:avg_fraud,                               color:'#4d9fff'},
  ];
  document.getElementById('summary-content').innerHTML = items.map(it => `
    <div class="summary-item">
      <span class="summary-label">${it.label}</span>
      <span class="summary-val" style="color:${it.color}">${it.val}</span>
    </div>
  `).join('');
}

// ─── Flagged Rows Table ───────────────────────────────────
function renderTable() {
  const search = (document.getElementById('search-input').value || '').toLowerCase();
  const filtered = allRows.filter(r => {
    if (currentFilter !== 'all' && r.type !== currentFilter) return false;
    if (search && !r.ip.toLowerCase().includes(search) && !r.ua.toLowerCase().includes(search)) return false;
    return true;
  });
  document.getElementById('row-count-label').textContent = `${filtered.length.toLocaleString()} rows`;

  const typeTag = t => ({
    human:   `<span class="tag tag-human">Human</span>`,
    bad:     `<span class="tag tag-bad">Bad Bot</span>`,
    ai:      `<span class="tag tag-ai">AI Crawler</span>`,
    crawler: `<span class="tag tag-crawler">Crawler</span>`,
  }[t] || '');

  const scoreTag = s => {
    const cls = s < 30 ? 'score-low' : s < 60 ? 'score-mid' : 'score-high';
    return `<span class="score-pill ${cls}">${s}</span>`;
  };

  const bool = v => v
    ? `<span style="color:#ff3b5c">Yes</span>`
    : `<span style="color:#4a5568">No</span>`;

  document.getElementById('table-body').innerHTML = filtered.slice(0, 300).map(r => `
    <tr>
      <td>${typeTag(r.type)}</td>
      <td style="color:#e2e8f0;font-weight:500">${r.ip}</td>
      <td title="${r.ua}" style="max-width:220px">${r.ua}</td>
      <td>${scoreTag(r.fraud)}</td>
      <td>${bool(r.datacenter)}</td>
      <td>${bool(r.vpn)}</td>
      <td>${bool(r.tor)}</td>
      <td style="color:${r.bad_ua?'#ff3b5c':'#8892a4'}">${r.bad_ua?'Automation':'Browser'}</td>
      <td>${bool(r.missing_headers)}</td>
    </tr>
  `).join('');
}

function filterTable() { renderTable(); }

function setFilter(type, btn) {
  currentFilter = type;
  document.querySelectorAll('.filter-btn').forEach(b => { b.className = 'filter-btn'; });
  if (btn) {
    const cls = {all:'active',human:'active',bad:'active-red',ai:'active-purple',crawler:'active-amber'}[type]||'active';
    btn.classList.add(cls);
  }
  renderTable();
}

function resetDashboard() {
  [donutChart, timelineChart, fraudChart, uaChart].forEach(c => c && c.destroy());
  donutChart = timelineChart = fraudChart = uaChart = null;
  allRows = []; currentFilter = 'all'; selectedFile = null;
  document.getElementById('dashboard').style.display     = 'none';
  document.getElementById('upload-screen').style.display = 'flex';
  document.getElementById('btn-analyze').disabled        = true;
  document.getElementById('file-info').style.display     = 'none';
  document.getElementById('file-input').value            = '';
  document.getElementById('progress-fill').style.width   = '0%';
  hideError();
}

// ─── Helpers ──────────────────────────────────────────────
function pct(val, total) {
  if (!total) return '0.0';
  return (val / total * 100).toFixed(1);
}
