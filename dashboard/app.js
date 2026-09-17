/**
 * app.js — DDoS Shield Dashboard
 * Real-time WebSocket client + Chart.js + REST API integration
 */

'use strict';

const API = 'http://localhost:8000';
const WS_URL = 'ws://localhost:8000/ws';

// ── State ─────────────────────────────────────────────────────────────────────
let ws = null;
let chart = null;
let reconnectTimer = null;
let prevAttackCount = 0;
let knownAttackIds = new Set();

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

const els = {
  systemStatus:   $('systemStatus'),
  statusPulse:    $('statusPulse'),
  statusText:     $('statusText'),
  liveClock:      $('liveClock'),
  kpiTotal:       $('kpiTotal'),
  kpiNormal:      $('kpiNormal'),
  kpiSuspicious:  $('kpiSuspicious'),
  kpiAttacks:     $('kpiAttacks'),
  kpiBlocked:     $('kpiBlocked'),
  kpiChain:       $('kpiChain'),
  attackFeed:     $('attackFeed'),
  blockchainList: $('blockchainList'),
  chainIntegrity: $('chainIntegrity'),
  blockedList:    $('blockedList'),
  blockedCountBadge: $('blockedCountBadge'),
  simStatus:      $('simStatus'),
  verifyChainBtn: $('verifyChainBtn'),
  btnNormal:      $('btnNormal'),
  btnAttack:      $('btnAttack'),
  btnMixed:       $('btnMixed'),
  btnRefresh:     $('btnRefresh'),
  attackTypeSelect: $('attackTypeSelect'),
  durationInput:  $('durationInput'),
  toastContainer: $('toastContainer'),
  attackModal:    $('attackModal'),
  modalBody:      $('modalBody'),
  modalClose:     $('modalClose'),
  nodeA:          $('nodeA'),
  nodeB:          $('nodeB'),
  nodeC:          $('nodeC'),
};

// ── Live Clock ─────────────────────────────────────────────────────────────────
function startClock() {
  const update = () => {
    els.liveClock.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
  };
  update();
  setInterval(update, 1000);
}

// ── Number counter animation ──────────────────────────────────────────────────
function animateCounter(el, target) {
  const current = parseInt(el.textContent.replace(/,/g, ''), 10) || 0;
  if (current === target) return;
  const diff = target - current;
  const steps = Math.min(Math.abs(diff), 20);
  const step = diff / steps;
  let count = 0;
  const tick = () => {
    count++;
    const val = Math.round(current + step * count);
    el.textContent = val.toLocaleString();
    if (count < steps) requestAnimationFrame(tick);
    else el.textContent = target.toLocaleString();
  };
  requestAnimationFrame(tick);
}

// ── Chart setup ───────────────────────────────────────────────────────────────
function initChart() {
  const ctx = document.getElementById('trafficChart').getContext('2d');
  const labels = Array.from({ length: 60 }, (_, i) => `${60 - i}s`).reverse();

  chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Normal (pps)',
          data: new Array(60).fill(0),
          borderColor: '#00d4ff',
          backgroundColor: 'rgba(0, 212, 255, 0.05)',
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.4,
          fill: true,
        },
        {
          label: 'Attack (pps)',
          data: new Array(60).fill(0),
          borderColor: '#ff2d55',
          backgroundColor: 'rgba(255, 45, 85, 0.07)',
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.4,
          fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(8, 15, 32, 0.95)',
          borderColor: 'rgba(255,255,255,0.08)',
          borderWidth: 1,
          titleColor: '#7a92b4',
          bodyColor: '#e8f4ff',
          padding: 10,
        },
      },
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { color: '#3d5478', maxTicksLimit: 8, font: { size: 10, family: 'JetBrains Mono' } },
        },
        y: {
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { color: '#3d5478', font: { size: 10, family: 'JetBrains Mono' } },
          beginAtZero: true,
        },
      },
    },
  });
}

function updateChart(ppsHistory, attackHistory) {
  if (!chart) return;
  const len = ppsHistory.length;

  // Normal = total - attack
  const normalData = ppsHistory.map((pps, i) => Math.max(0, pps - (attackHistory[i] || 0)));

  // Pad to 60 if needed
  const pad = (arr) => {
    const out = new Array(60).fill(0);
    arr.slice(-60).forEach((v, i) => { out[60 - Math.min(len, 60) + i] = v; });
    return out;
  };

  chart.data.datasets[0].data = pad(normalData);
  chart.data.datasets[1].data = pad(attackHistory);
  chart.update('none');
}

// ── System Status ─────────────────────────────────────────────────────────────
function updateStatus(status) {
  const map = {
    'PROTECTED':    { cls: 'status--protected', text: 'PROTECTED', color: 'var(--green)' },
    'ALERT':        { cls: 'status--alert',     text: 'ALERT',     color: 'var(--yellow)' },
    'UNDER_ATTACK': { cls: 'status--under-attack', text: 'UNDER ATTACK', color: 'var(--red)' },
  };
  const s = map[status] || map['PROTECTED'];
  els.systemStatus.className = `system-status ${s.cls}`;
  els.statusText.textContent = s.text;
}

// ── Node Status ───────────────────────────────────────────────────────────────
function updateNodes(nodeStatus) {
  if (!nodeStatus) return;
  const nodeMap = {
    'node-A': els.nodeA,
    'node-B': els.nodeB,
    'node-C': els.nodeC,
  };
  Object.entries(nodeStatus).forEach(([nid, info]) => {
    const el = nodeMap[nid];
    if (!el) return;
    if (info.is_valid) {
      el.classList.remove('offline');
    } else {
      el.classList.add('offline');
    }
  });
}

// ── KPI Update ────────────────────────────────────────────────────────────────
function updateKPIs(data) {
  animateCounter(els.kpiTotal,      data.total_requests       || 0);
  animateCounter(els.kpiNormal,     data.normal_count         || 0);
  animateCounter(els.kpiSuspicious, data.suspicious_count     || 0);
  animateCounter(els.kpiAttacks,    data.attack_count         || 0);
  animateCounter(els.kpiBlocked,    data.blocked_ip_count     || 0);
  animateCounter(els.kpiChain,      data.blockchain_record_count || 0);

  // Flash attack KPI if new attacks
  if ((data.attack_count || 0) > prevAttackCount) {
    $('kpi-attacks').style.borderColor = 'rgba(255, 45, 85, 0.6)';
    setTimeout(() => { $('kpi-attacks').style.borderColor = ''; }, 1000);
  }
  prevAttackCount = data.attack_count || 0;
}

// ── Attack Feed ────────────────────────────────────────────────────────────────
function pushFeedItem(attack) {
  const { attack_id, src_ip, attack_type, severity, pps, timestamp } = attack;

  // Remove empty placeholder
  const empty = els.attackFeed.querySelector('.feed-empty');
  if (empty) empty.remove();

  const ts = timestamp ? new Date(timestamp).toLocaleTimeString('en-GB', { hour12: false }) : '--:--:--';

  const item = document.createElement('div');
  item.className = 'feed-item';
  item.setAttribute('role', 'listitem');
  item.innerHTML = `
    <span class="feed-item-severity sev--${severity}">${severity}</span>
    <div class="feed-item-info">
      <span class="feed-item-ip">${escHtml(src_ip)}</span>
      <span class="feed-item-type">${escHtml(attack_type || 'Unknown')}</span>
      <span class="feed-item-ts">${ts} · ${Math.round(pps || 0).toLocaleString()} pps</span>
    </div>
  `;
  els.attackFeed.prepend(item);

  // Keep max 30 items
  while (els.attackFeed.children.length > 30) {
    els.attackFeed.lastChild?.remove();
  }
}

// ── Blockchain Ledger ──────────────────────────────────────────────────────────
async function loadBlockchain() {
  try {
    const chain = await apiFetch('/api/blockchain');
    if (!Array.isArray(chain) || chain.length <= 1) return;

    const empty = els.blockchainList.querySelector('.chain-empty');
    if (empty) empty.remove();

    // Render newest first (skip genesis = index 0)
    const blocks = chain.slice(1).reverse();
    els.blockchainList.innerHTML = '';

    blocks.slice(0, 15).forEach((block) => {
      const rec = block.attack_record || {};
      const card = document.createElement('div');
      card.className = 'block-card';
      card.innerHTML = `
        <div class="block-index">BLOCK #${block.index} · ${block.node || 'node-A'}</div>
        <div class="block-hash">${block.hash}</div>
        <div class="block-info">
          <div class="block-info-item">
            <span class="block-info-label">Attacker</span>
            <span class="block-info-value">${escHtml(rec.src_ip || '—')}</span>
          </div>
          <div class="block-info-item">
            <span class="block-info-label">Type</span>
            <span class="block-info-value">${escHtml(rec.attack_type || '—')}</span>
          </div>
          <div class="block-info-item">
            <span class="block-info-label">Severity</span>
            <span class="block-info-value">${escHtml(rec.severity || '—')}</span>
          </div>
          <div class="block-info-item">
            <span class="block-info-label">PPS</span>
            <span class="block-info-value">${Math.round(rec.packets_per_sec || 0).toLocaleString()}</span>
          </div>
        </div>
        <div class="block-nodes">Nonce: ${block.nonce} · <span>Verified ✓</span></div>
      `;
      els.blockchainList.appendChild(card);
    });
  } catch (e) {
    // Silently fail if backend not ready
  }
}

// ── Blocked IPs ────────────────────────────────────────────────────────────────
async function loadBlockedIPs() {
  try {
    const list = await apiFetch('/api/blocked');
    if (!Array.isArray(list)) return;

    els.blockedCountBadge.textContent = `${list.length} active`;
    els.blockedList.innerHTML = '';

    if (list.length === 0) {
      els.blockedList.innerHTML = '<div class="chain-empty"><span>No IPs currently blocked</span></div>';
      return;
    }

    list.forEach((item) => {
      const row = document.createElement('div');
      row.className = 'blocked-item';
      row.innerHTML = `
        <div>
          <div class="blocked-ip">${escHtml(item.ip)}</div>
          <div class="blocked-type">${escHtml(item.attack_type || item.reason || '—')}</div>
        </div>
        <button class="btn-unblock" data-ip="${escHtml(item.ip)}" aria-label="Unblock ${escHtml(item.ip)}">
          Unblock
        </button>
      `;
      row.querySelector('.btn-unblock').addEventListener('click', () => unblockIP(item.ip));
      els.blockedList.appendChild(row);
    });
  } catch (e) {}
}

async function unblockIP(ip) {
  try {
    await fetch(`${API}/api/blocked/${encodeURIComponent(ip)}`, { method: 'DELETE' });
    showToast('info', 'IP Unblocked', `${ip} has been removed from the blocklist.`);
    await loadBlockedIPs();
  } catch (e) {
    showToast('danger', 'Error', 'Failed to unblock IP.');
  }
}

// ── Chain Verification ─────────────────────────────────────────────────────────
async function verifyChain() {
  try {
    els.chainIntegrity.textContent = '⏳ Verifying chain...';
    els.chainIntegrity.className = 'chain-integrity';
    const result = await apiFetch('/api/blockchain/verify');
    if (result.valid) {
      els.chainIntegrity.textContent = `✅ Chain VALID — ${result.block_count} blocks verified across ${Object.keys(result.nodes).length} nodes`;
      els.chainIntegrity.className = 'chain-integrity valid';
      showToast('success', 'Chain Verified', `All ${result.block_count} blocks passed integrity check.`);
    } else {
      els.chainIntegrity.textContent = '❌ Chain INVALID — tampering detected!';
      els.chainIntegrity.className = 'chain-integrity invalid';
      showToast('danger', 'Chain Invalid', 'Blockchain integrity check failed!');
    }
  } catch (e) {
    els.chainIntegrity.textContent = '⚠️ Could not verify — backend unreachable';
    els.chainIntegrity.className = 'chain-integrity';
  }
}

// ── Attack Modal ───────────────────────────────────────────────────────────────
function showAttackModal(attack) {
  const { src_ip, attack_type, severity, pps, bc_hash, bc_index, timestamp } = attack;
  const ts = timestamp ? new Date(timestamp).toLocaleTimeString('en-GB') : '--';

  els.modalBody.innerHTML = `
    <div class="modal-row"><span class="modal-row-label">Attacker IP</span><span class="modal-row-value cyan">${escHtml(src_ip)}</span></div>
    <div class="modal-row"><span class="modal-row-label">Attack Type</span><span class="modal-row-value red">${escHtml(attack_type)}</span></div>
    <div class="modal-row"><span class="modal-row-label">Severity</span><span class="modal-row-value red">${escHtml(severity)}</span></div>
    <div class="modal-row"><span class="modal-row-label">Traffic Rate</span><span class="modal-row-value">${Math.round(pps || 0).toLocaleString()} pps</span></div>
    <div class="modal-row"><span class="modal-row-label">Detected At</span><span class="modal-row-value">${ts}</span></div>
    <div class="modal-row"><span class="modal-row-label">Blockchain Block</span><span class="modal-row-value purple">#${bc_index}</span></div>
    <div class="modal-row"><span class="modal-row-label">Block Hash</span><span class="modal-row-value" style="font-size:10px;word-break:break-all">${escHtml((bc_hash || '').substring(0, 32))}...</span></div>
    <div class="modal-row"><span class="modal-row-label">Status</span><span class="modal-row-value red">🚫 BLOCKED</span></div>
  `;
  els.attackModal.hidden = false;
}

els.modalClose.addEventListener('click', () => { els.attackModal.hidden = true; });
els.attackModal.addEventListener('click', (e) => { if (e.target === els.attackModal) els.attackModal.hidden = true; });

// ── Toast ──────────────────────────────────────────────────────────────────────
function showToast(type, title, body, duration = 5000) {
  const toast = document.createElement('div');
  toast.className = `toast toast--${type}`;
  toast.setAttribute('role', 'alert');
  toast.innerHTML = `<div class="toast-title">${escHtml(title)}</div><div class="toast-body">${escHtml(body)}</div>`;
  els.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = 'toast-out 0.3s ease forwards';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Simulation Controls ────────────────────────────────────────────────────────
async function simulate(mode) {
  const attackType = els.attackTypeSelect.value;
  const duration = parseInt(els.durationInput.value, 10) || 30;

  try {
    await fetch(`${API}/api/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, duration, attack_type: attackType }),
    });

    const labels = { normal: 'Normal Traffic', attack: '⚡ Attack', mixed: '⚡ Mixed Mode' };
    const simClass = mode === 'normal' ? 'running-normal' : 'running-attack';
    els.simStatus.textContent = `${labels[mode]} — ${duration}s`;
    els.simStatus.className = `sim-status ${simClass}`;

    showToast(
      mode === 'normal' ? 'info' : 'danger',
      `Simulation Started`,
      `Mode: ${labels[mode]} · Duration: ${duration}s · Type: ${attackType}`,
    );

    setTimeout(() => {
      els.simStatus.textContent = 'Idle';
      els.simStatus.className = 'sim-status';
    }, duration * 1000);
  } catch (e) {
    showToast('danger', 'Error', 'Backend unreachable. Start the server first.');
  }
}

els.btnNormal.addEventListener('click', () => simulate('normal'));
els.btnAttack.addEventListener('click', () => simulate('attack'));
els.btnMixed.addEventListener('click', () => simulate('mixed'));
els.verifyChainBtn.addEventListener('click', verifyChain);
els.btnRefresh.addEventListener('click', async () => {
  await Promise.all([loadBlockchain(), loadBlockedIPs()]);
  showToast('info', 'Refreshed', 'Dashboard data reloaded.');
});

// ── WebSocket ──────────────────────────────────────────────────────────────────
function connectWS() {
  if (ws) { ws.close(); ws = null; }

  try {
    ws = new WebSocket(WS_URL);
  } catch (e) {
    scheduleReconnect();
    return;
  }

  ws.addEventListener('open', () => {
    console.log('[WS] Connected');
    updateStatus('PROTECTED');
    els.statusText.textContent = 'PROTECTED';
  });

  ws.addEventListener('message', (event) => {
    try {
      const msg = JSON.parse(event.data);

      if (msg.type === 'stats') {
        const d = msg.data;
        updateKPIs(d);
        updateChart(d.pps_history || [], d.attack_rate_history || []);
        updateStatus(d.system_status || 'PROTECTED');
        updateNodes(d.node_status);

        // Refresh blockchain + blocked periodically via REST on stat update
        if (d.blockchain_record_count !== lastChainCount) {
          lastChainCount = d.blockchain_record_count;
          loadBlockchain();
        }
        if (d.blocked_ip_count !== lastBlockedCount) {
          lastBlockedCount = d.blocked_ip_count;
          loadBlockedIPs();
        }
      }

      if (msg.type === 'attack_alert') {
        const a = msg.data;
        if (!knownAttackIds.has(a.attack_id)) {
          knownAttackIds.add(a.attack_id);
          pushFeedItem(a);
          showAttackModal(a);
          showToast('danger', '🚨 Attack Detected', `${a.src_ip} — ${a.attack_type} (${a.severity})`);
        }
      }
    } catch (e) {
      console.warn('[WS] Parse error:', e);
    }
  });

  ws.addEventListener('close', () => {
    console.log('[WS] Disconnected');
    els.statusText.textContent = 'DISCONNECTED';
    els.systemStatus.className = 'system-status status--alert';
    scheduleReconnect();
  });

  ws.addEventListener('error', () => scheduleReconnect());
}

function scheduleReconnect() {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(connectWS, 3000);
}

let lastChainCount = -1;
let lastBlockedCount = -1;

// ── REST helper ────────────────────────────────────────────────────────────────
async function apiFetch(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ── HTML escape ────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Load historical attacks on page load ──────────────────────────────────────
async function loadRecentAttacks() {
  try {
    const attacks = await apiFetch('/api/attacks?limit=15');
    if (!Array.isArray(attacks)) return;
    attacks.reverse().forEach((a) => {
      if (!knownAttackIds.has(a.attack_id)) {
        knownAttackIds.add(a.attack_id);
        pushFeedItem({
          attack_id:   a.attack_id,
          src_ip:      a.src_ip,
          attack_type: a.attack_type,
          severity:    a.severity,
          pps:         a.packets_per_sec,
          timestamp:   a.timestamp,
        });
      }
    });
  } catch (e) {}
}

// ── Init ───────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  startClock();
  initChart();
  connectWS();

  // Load initial data
  await Promise.all([
    loadRecentAttacks(),
    loadBlockchain(),
    loadBlockedIPs(),
  ]);

  // Periodic refresh of blockchain + blocked (fallback to polling if WS misses updates)
  setInterval(() => {
    loadBlockchain();
    loadBlockedIPs();
  }, 10_000);
});
