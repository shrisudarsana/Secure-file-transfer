/* ═══════════════════════════════════════════════════════════════
   AI-Based Secure File Transfer System — Frontend Logic
   ═══════════════════════════════════════════════════════════════ */

// ─── State ────────────────────────────────────────────────────────
let currentTab        = "upload";
let pendingTransfer   = null;   // stores { filename, direction, force:false } while alert is open
let statsCounters     = { safe: 0, blocked: 0 };

// ─── Init ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  refreshFiles();
  refreshLogs();
  checkServerStatus();
  // Poll logs every 6 seconds
  setInterval(refreshLogs, 6000);
  // Poll server status every 10 seconds
  setInterval(checkServerStatus, 10000);
  // Poll file lists every 8 seconds
  setInterval(refreshFiles, 8000);
});

// ─── Tab Switching ────────────────────────────────────────────────
function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  document.getElementById("tab-" + tab).classList.add("active");
  document.getElementById("panel-" + tab).classList.add("active");
  resetAIPanel();
}

// ─── File Selection Handlers ──────────────────────────────────────
function onUploadFileChange() {
  const sel    = document.getElementById("upload-file-select");
  const btn    = document.getElementById("btn-analyze-upload");
  const infoBar = document.getElementById("upload-file-info");

  if (!sel.value) {
    btn.disabled = true;
    infoBar.classList.add("hidden");
    return;
  }

  const opt     = sel.options[sel.selectedIndex];
  const sizeB   = parseInt(opt.dataset.size || "0");
  const sizeKB  = (sizeB / 1024).toFixed(1);
  const sizeStr = sizeB > 1024 * 1024
    ? (sizeB / (1024 * 1024)).toFixed(1) + " MB"
    : sizeKB + " KB";

  document.getElementById("upload-fname").textContent = sel.value;
  document.getElementById("upload-fsize").textContent = sizeStr;
  infoBar.classList.remove("hidden");
  btn.disabled = false;
  resetAIPanel();
}

function onDownloadFileChange() {
  const sel    = document.getElementById("download-file-select");
  const btn    = document.getElementById("btn-analyze-download");
  const infoBar = document.getElementById("download-file-info");

  if (!sel.value) {
    btn.disabled = true;
    infoBar.classList.add("hidden");
    return;
  }

  const opt     = sel.options[sel.selectedIndex];
  const sizeB   = parseInt(opt.dataset.size || "0");
  const sizeKB  = (sizeB / 1024).toFixed(1);
  const sizeStr = sizeKB + " KB";

  document.getElementById("download-fname").textContent = sel.value;
  document.getElementById("download-fsize").textContent = sizeStr;
  infoBar.classList.remove("hidden");
  btn.disabled = false;
  resetAIPanel();
}

// ─── Main Action: Analyze + Transfer ─────────────────────────────
async function analyzeAndTransfer(direction, force = false) {
  let filename, fileSizeBytes;

  if (direction === "upload") {
    const sel = document.getElementById("upload-file-select");
    filename      = sel.value;
    fileSizeBytes = parseInt(sel.options[sel.selectedIndex].dataset.size || "0");
    if (!filename) return;
  } else {
    const sel = document.getElementById("download-file-select");
    filename      = sel.value;
    fileSizeBytes = parseInt(sel.options[sel.selectedIndex].dataset.size || "0");
    if (!filename) return;
  }

  pendingTransfer = { filename, direction, fileSizeBytes };

  // Show progress
  showProgress("🔍 Running AI analysis...", 20);
  setButtonsDisabled(true);
  showAIResult(null);

  try {
    // Step 1: AI Analysis
    const analyzeRes = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename, file_size: fileSizeBytes, direction }),
    });
    const aiData = await analyzeRes.json();

    updateProgress(60, "🤖 AI analysis complete — checking result...");
    renderAIResult(aiData);

    if (aiData.label === "SUSPICIOUS" && !force) {
      // Show alert popup — do NOT auto-transfer
      updateProgress(100, "⚠️ Suspicious file detected!");
      setTimeout(() => hideProgress(), 1200);
      setButtonsDisabled(false);
      showAlert(aiData, filename);
      return;
    }

    // Step 2: Perform Transfer
    updateProgress(75, "🔐 Initiating secure socket transfer...");

    const transferRes = await fetch("/api/transfer", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename, direction, force }),
    });
    const transferData = await transferRes.json();

    updateProgress(100, transferData.success ? "✅ Transfer complete!" : "❌ Transfer failed");
    setTimeout(() => hideProgress(), 1500);

    // Update AI panel with transfer outcome
    renderTransferResult(transferData);

    // Refresh stats & logs
    refreshLogs();
    refreshFiles();

  } catch (err) {
    updateProgress(100, "❌ Error: " + err.message);
    setTimeout(() => hideProgress(), 2000);
    setButtonsDisabled(false);
  }

  setButtonsDisabled(false);
}

// ─── Alert Popup ──────────────────────────────────────────────────
function showAlert(aiData, filename) {
  document.getElementById("alert-title").textContent   = "⚠️ Suspicious File Detected!";
  document.getElementById("alert-message").textContent =
    `"${filename}" has been flagged as SUSPICIOUS with ${aiData.confidence}% confidence.`;
  document.getElementById("alert-reason").textContent  = aiData.reason;
  document.getElementById("alert-force").classList.remove("hidden");
  document.getElementById("alert-overlay").classList.remove("hidden");
}

function showSuccessAlert(message) {
  document.getElementById("alert-icon").textContent    = "✅";
  document.getElementById("alert-title").textContent   = "Transfer Successful";
  document.getElementById("alert-message").textContent = message;
  document.getElementById("alert-reason").textContent  = "";
  document.getElementById("alert-reason").style.display = "none";
  document.getElementById("alert-force").classList.add("hidden");
  document.getElementById("alert-overlay").classList.remove("hidden");
  setTimeout(closeAlert, 2500);
}

function closeAlert() {
  document.getElementById("alert-overlay").classList.add("hidden");
  document.getElementById("alert-reason").style.display = "";
  document.getElementById("alert-icon").textContent = "⚠️";
}

function forceTransfer() {
  closeAlert();
  if (pendingTransfer) {
    analyzeAndTransfer(pendingTransfer.direction, true);
  }
}

// ─── AI Result Rendering ──────────────────────────────────────────
function resetAIPanel() {
  document.getElementById("ai-idle").classList.remove("hidden");
  document.getElementById("ai-result").classList.add("hidden");
}

function showAIResult(data) {
  if (!data) {
    resetAIPanel();
    return;
  }
  document.getElementById("ai-idle").classList.add("hidden");
  document.getElementById("ai-result").classList.remove("hidden");
}

function renderAIResult(aiData) {
  showAIResult(aiData);

  const isSupicious = aiData.label === "SUSPICIOUS";
  const badge = document.getElementById("verdict-badge");
  badge.className = "verdict-badge " + (isSupicious ? "suspicious" : "safe");
  document.getElementById("verdict-icon").textContent = isSupicious ? "🚨" : "✅";
  document.getElementById("verdict-text").textContent = aiData.label;

  // Confidence bar
  const pct = aiData.confidence;
  const bar = document.getElementById("conf-bar");
  bar.style.width   = pct + "%";
  bar.className     = "conf-bar " + (isSupicious ? "suspicious" : "safe");
  document.getElementById("conf-pct").textContent = pct + "%";

  // Feature grid
  const feats = aiData.features || {};
  const featureLabels = {
    ext_risk:        "Extension Risk",
    size_kb:         "File Size (KB)",
    suspicious_name: "Suspicious Name",
    has_double_ext:  "Double Extension",
    transfer_freq:   "Freq. Score",
  };
  const featureFormatters = {
    ext_risk:        v => ["Low ✅", "Medium ⚠️", "High 🚨"][v] || v,
    size_kb:         v => Number(v).toFixed(1) + " KB",
    suspicious_name: v => v ? "Yes 🚨" : "No ✅",
    has_double_ext:  v => v ? "Yes 🚨" : "No ✅",
    transfer_freq:   v => v + " / 5",
  };

  const grid = document.getElementById("feature-grid");
  grid.innerHTML = Object.keys(featureLabels).map(key => {
    const val = feats[key] !== undefined ? feats[key] : "—";
    const fmt = featureFormatters[key] ? featureFormatters[key](val) : val;
    return `<div class="feature-item">
      <p class="feature-name">${featureLabels[key]}</p>
      <p class="feature-value">${fmt}</p>
    </div>`;
  }).join("");

  document.getElementById("reason-box").textContent = "🔍 " + aiData.reason;
  document.getElementById("transfer-result").classList.add("hidden");
}

function renderTransferResult(transferData) {
  const el    = document.getElementById("transfer-result");
  const icon  = document.getElementById("transfer-status-icon");
  const text  = document.getElementById("transfer-status-text");
  el.classList.remove("hidden");
  el.style.background = "";
  el.style.borderColor = "";

  if (transferData.blocked) {
    icon.textContent  = "🚫";
    text.textContent  = "Transfer BLOCKED — Suspicious file";
    el.style.background   = "var(--red-light)";
    el.style.borderColor  = "var(--red)";
    statsCounters.blocked++;
    document.getElementById("stat-blocked").textContent = statsCounters.blocked;
  } else if (transferData.success) {
    icon.textContent  = "✅";
    text.textContent  = "Secure transfer complete!";
    el.style.background   = "var(--green-light)";
    el.style.borderColor  = "var(--green)";
    statsCounters.safe++;
    document.getElementById("stat-safe").textContent = statsCounters.safe;
  } else {
    icon.textContent  = "❌";
    text.textContent  = transferData.message || "Transfer failed";
    el.style.background   = "var(--amber-light)";
  }
}

// ─── Progress Bar ─────────────────────────────────────────────────
function showProgress(label, pct) {
  const wrap = document.getElementById("progress-wrap");
  wrap.classList.remove("hidden");
  document.getElementById("progress-bar").style.width  = pct + "%";
  document.getElementById("progress-label").textContent = label;
}
function updateProgress(pct, label) {
  document.getElementById("progress-bar").style.width  = pct + "%";
  document.getElementById("progress-label").textContent = label;
}
function hideProgress() {
  document.getElementById("progress-wrap").classList.add("hidden");
  document.getElementById("progress-bar").style.width = "0%";
}

function setButtonsDisabled(disabled) {
  document.getElementById("btn-analyze-upload").disabled   = disabled || !document.getElementById("upload-file-select").value;
  document.getElementById("btn-analyze-download").disabled = disabled || !document.getElementById("download-file-select").value;
}

// ─── File Lists ───────────────────────────────────────────────────
async function refreshFiles() {
  try {
    const [clientRes, serverRes] = await Promise.all([
      fetch("/api/client-files"),
      fetch("/api/server-files"),
    ]);
    const clientFiles = await clientRes.json();
    const serverFiles = await serverRes.json();

    renderFileList("client-file-list", clientFiles, "📄");
    renderFileList("server-file-list", serverFiles, "🖥️");

    document.getElementById("stat-client-files").textContent = clientFiles.length;
    document.getElementById("stat-server-files").textContent = serverFiles.length;

    // Rebuild upload select
    const sel = document.getElementById("upload-file-select");
    const current = sel.value;
    sel.innerHTML = '<option value="">— Choose a file —</option>';
    clientFiles.forEach(f => {
      const opt = document.createElement("option");
      opt.value = f.name;
      opt.dataset.size = f.size_bytes;
      opt.textContent = `${f.name} (${f.size_kb} KB)`;
      if (f.name === current) opt.selected = true;
      sel.appendChild(opt);
    });

    // Rebuild download select
    const dsel = document.getElementById("download-file-select");
    const dcurrent = dsel.value;
    dsel.innerHTML = '<option value="">— Choose a file —</option>';
    serverFiles.forEach(f => {
      const opt = document.createElement("option");
      opt.value = f.name;
      opt.dataset.size = Math.round(f.size_kb * 1024);
      opt.textContent = `${f.name} (${f.size_kb} KB)`;
      if (f.name === dcurrent) opt.selected = true;
      dsel.appendChild(opt);
    });
  } catch (e) {
    console.error("Failed to refresh files:", e);
  }
}

function renderFileList(containerId, files, icon) {
  const container = document.getElementById(containerId);
  if (!files.length) {
    container.innerHTML = '<p class="empty-state">No files found</p>';
    return;
  }
  container.innerHTML = files.map(f =>
    `<div class="file-item">
      <span class="file-item-name">${icon} ${f.name}</span>
      <span class="file-item-size">${f.size_kb} KB</span>
    </div>`
  ).join("");
}

// ─── Transfer Log ─────────────────────────────────────────────────
async function refreshLogs() {
  try {
    const res  = await fetch("/api/logs");
    const rows = await res.json();
    renderLogTable(rows);
    updateStatsFromLogs(rows);
  } catch (e) {
    console.error("Failed to refresh logs:", e);
  }
}

function renderLogTable(rows) {
  const tbody = document.getElementById("log-tbody");
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No transfers yet</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => {
    const aiPill   = r.ai_label === "SUSPICIOUS"
      ? '<span class="pill pill-suspicious">🚨 SUSPICIOUS</span>'
      : '<span class="pill pill-safe">✅ SAFE</span>';
    const statPill = getStatusPill(r.transfer_status);
    const dirIcon  = r.direction === "upload" ? "⬆️" : "⬇️";
    return `<tr>
      <td>${r.timestamp || "—"}</td>
      <td><strong>${escHtml(r.filename || "—")}</strong></td>
      <td>${r.size_kb || "—"} KB</td>
      <td>${dirIcon} ${r.direction || "—"}</td>
      <td>${aiPill}</td>
      <td>${r.confidence || "—"}</td>
      <td>${statPill}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(r.reason || "")}">${escHtml(r.reason || "—")}</td>
    </tr>`;
  }).join("");
}

function getStatusPill(status) {
  const map = {
    "SUCCESS":             '<span class="pill pill-success">✅ SUCCESS</span>',
    "BLOCKED":             '<span class="pill pill-blocked">🚫 BLOCKED</span>',
    "SUSPICIOUS-ALLOWED":  '<span class="pill pill-suspicious">⚠️ ALLOWED</span>',
    "FAILED":              '<span class="pill pill-failed">❌ FAILED</span>',
  };
  return map[status] || `<span class="pill pill-failed">${escHtml(status || "—")}</span>`;
}

function updateStatsFromLogs(rows) {
  let safe = 0, blocked = 0;
  rows.forEach(r => {
    if (r.transfer_status === "SUCCESS") safe++;
    if (r.transfer_status === "BLOCKED") blocked++;
  });
  document.getElementById("stat-safe").textContent    = safe;
  document.getElementById("stat-blocked").textContent = blocked;
}

// ─── Server Status Check ──────────────────────────────────────────
async function checkServerStatus() {
  const badge = document.getElementById("server-status-badge");
  try {
    // Try to reach the Flask server itself as a proxy — real socket check would need a dedicated endpoint
    const res = await fetch("/api/client-files", { signal: AbortSignal.timeout(2000) });
    if (res.ok) {
      badge.textContent  = "🟢 Dashboard Online";
      badge.className    = "badge badge-green";
    }
  } catch {
    badge.textContent = "🔴 Dashboard Offline";
    badge.className   = "badge badge-red";
  }
}

// ─── Utilities ────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
