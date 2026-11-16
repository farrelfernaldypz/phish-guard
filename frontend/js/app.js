/**
 * PhishGuard Enterprise — High-Assurance Client Controller
 * Focus: Precision telemetry, refined micro-interactions, local audit logging
 */

// DOM Elements - Single Scanner
const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const clearUrlBtn = document.querySelector("#clear-url-btn");
const scanButton = document.querySelector("#scan-button");
const errorBox = document.querySelector("#form-error");
const loadingState = document.querySelector("#loading-state");
const resultCard = document.querySelector("#result-card");
const characterCount = document.querySelector("#char-count");

// DOM Elements - Tabs
const tabSingleBtn = document.querySelector("#tab-single-btn");
const tabBatchBtn = document.querySelector("#tab-batch-btn");
const panelSingle = document.querySelector("#panel-single");
const panelBatch = document.querySelector("#panel-batch");

// DOM Elements - Batch Scanner
const batchTextarea = document.querySelector("#batch-textarea");
const btnRunBatch = document.querySelector("#btn-run-batch");
const btnBatchSample = document.querySelector("#btn-batch-sample");
const batchSpinner = document.querySelector("#batch-spinner");
const batchResultsWrap = document.querySelector("#batch-results-wrap");
const batchTotal = document.querySelector("#batch-total");
const batchSafe = document.querySelector("#batch-safe");
const batchPhish = document.querySelector("#batch-phish");
const batchRatio = document.querySelector("#batch-ratio");
const batchTbody = document.querySelector("#batch-tbody");

// DOM Elements - History
const historyTbody = document.querySelector("#history-tbody");
const btnExportHistory = document.querySelector("#btn-export-history");
const btnClearHistory = document.querySelector("#btn-clear-history");

// Preset demo buttons
const benchmarkPills = document.querySelectorAll(".case-chip[data-url]");

// Cache & Storage
let lastScanResult = null;
const STORAGE_KEY = "phishguard_audit_log_v2";

// 11 Feature Metadata & Explainability Config
const FEATURE_META = {
  url_length: {
    label: "Total URL Length",
    unit: "chars",
    threshold: 75,
    desc: "Long URLs (>75 chars) frequently conceal malicious redirect targets or query chains."
  },
  hostname_length: {
    label: "Hostname Length",
    unit: "chars",
    threshold: 28,
    desc: "Elevated hostname lengths are characteristic of domain squatting and typosquatting."
  },
  has_https: {
    label: "TLS / HTTPS Scheme",
    unit: "bool",
    isReverse: true, // 1 is nominal, 0 is anomalous
    desc: "Insecure plaintext HTTP connections lack transport authentication and integrity."
  },
  has_ip: {
    label: "Raw Numeric IP Host",
    unit: "bool",
    threshold: 1,
    desc: "Direct IP addresses bypass domain reputation hierarchies and denote high risk."
  },
  suspicious_words: {
    label: "Credential Keyword Hits",
    unit: "matches",
    threshold: 1,
    desc: "Matches against canonical phishing triggers (login, verify, secure, banking, etc.)."
  },
  count_dot: {
    label: "Dot Frequency (.)",
    unit: "count",
    threshold: 4,
    desc: "Excessive dot delimiters typically conceal deep subdomain camouflage."
  },
  count_hyphen: {
    label: "Hyphen Frequency (-)",
    unit: "count",
    threshold: 2,
    desc: "Multiple hyphens are commonly exploited to fabricate brand impersonation tokens."
  },
  count_at: {
    label: "At-Symbol Delimiter (@)",
    unit: "count",
    threshold: 1,
    desc: "The '@' character in URL authorities ignores preceding text, misleading victims."
  },
  count_question: {
    label: "Query Delimiter (?)",
    unit: "count",
    threshold: 2,
    desc: "Multiple query splitters denote dynamic payload delivery or session tunneling."
  },
  count_equal: {
    label: "Assignment Operator (=)",
    unit: "count",
    threshold: 3,
    desc: "High parameter density correlates with tracking and credential exfiltration tokens."
  },
  count_slash: {
    label: "Path Slash Depth (/)",
    unit: "count",
    threshold: 5,
    desc: "Deep directory hierarchies (>5 slashes) are designed to obscure path origins."
  }
};

const indicatorLabels = {
  has_ip_address: "Direct IPv4 Hostname",
  has_ip: "Direct IPv4 Hostname",
  has_punycode: "Punycode (IDNA) Obfuscation",
  has_port: "Explicit Non-Standard Port Binding",
  has_suspicious_keyword: "Observed Security Keyword Pattern",
  suspicious_keyword_count: "Multiple Phishing Token Occurrences",
  suspicious_words: "Multiple Phishing Token Occurrences",
  has_url_shortener: "Identified URL Shortener Service",
  has_double_slash_redirect_pattern: "Double-Slash Path Redirect Signature",
  count_subdomains: "Deep Subdomain Hierarchy",
  url_length: "Excessive Overall String Length",
  uses_https: "TLS Encryption Scheme Present",
  has_https: "TLS Encryption Scheme Present",
  count_dot: "Elevated Dot Delimiter Count",
  count_hyphen: "Elevated Hyphen Character Count",
  count_at: "Credential Delimiter '@' Present",
  count_slash: "Deep Directory Tree Traversal"
};

// --- Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  loadModelInfo();
  renderHistory();
  setupEventListeners();
});

function setupEventListeners() {
  // Input tracking
  input.addEventListener("input", () => {
    const len = input.value.length;
    characterCount.textContent = `${len} / 2048`;
    clearUrlBtn.hidden = len === 0;
    errorBox.hidden = true;
  });

  clearUrlBtn.addEventListener("click", () => {
    input.value = "";
    characterCount.textContent = "0 / 2048";
    clearUrlBtn.hidden = true;
    errorBox.hidden = true;
    input.focus();
  });

  // Single scan form submit
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorBox.hidden = true;
    const url = input.value.trim();
    if (!url) {
      showError("Please enter a valid URL target for analysis.");
      input.focus();
      return;
    }
    await scanSingleUrl(url);
  });

  // Benchmark pills
  benchmarkPills.forEach((pill) => {
    pill.addEventListener("click", () => {
      const url = pill.getAttribute("data-url");
      input.value = url;
      characterCount.textContent = `${url.length} / 2048`;
      clearUrlBtn.hidden = false;
      errorBox.hidden = true;
      scanSingleUrl(url);
    });
  });

  // Tab switching
  tabSingleBtn?.addEventListener("click", () => switchTab("single"));
  tabBatchBtn?.addEventListener("click", () => switchTab("batch"));

  // Copy JSON report
  document.querySelector("#btn-copy-json")?.addEventListener("click", () => {
    if (!lastScanResult) return;
    navigator.clipboard.writeText(JSON.stringify(lastScanResult, null, 2)).then(() => {
      const btn = document.querySelector("#btn-copy-json");
      const orig = btn.innerHTML;
      btn.innerHTML = `✓ Telemetry Copied`;
      setTimeout(() => { btn.innerHTML = orig; }, 2000);
    });
  });

  // Scan again button
  document.querySelector("#btn-scan-again")?.addEventListener("click", () => {
    resultCard.hidden = true;
    input.value = "";
    characterCount.textContent = "0 / 2048";
    clearUrlBtn.hidden = true;
    input.focus();
    input.scrollIntoView({ behavior: "smooth", block: "center" });
  });

  // Batch actions
  btnBatchSample?.addEventListener("click", () => {
    batchTextarea.value = [
      "https://google.com",
      "https://github.com/security",
      "http://192.168.1.100/login-update-paypal-banking-verify",
      "http://secure-account-verification-support.net/confirm/password",
      "https://wikipedia.org",
      "http://bank-of-america-verify-credential-update.xyz/login"
    ].join("\n");
  });

  btnRunBatch?.addEventListener("click", runBatchScan);

  // History actions
  btnClearHistory?.addEventListener("click", () => {
    if (confirm("Purge local session audit ledger? This action cannot be undone.")) {
      localStorage.removeItem(STORAGE_KEY);
      renderHistory();
    }
  });

  btnExportHistory?.addEventListener("click", exportHistoryCSV);
}

function switchTab(mode) {
  if (mode === "single") {
    tabSingleBtn.classList.add("active");
    tabBatchBtn.classList.remove("active");
    panelSingle.hidden = false;
    panelBatch.hidden = true;
  } else {
    tabBatchBtn.classList.add("active");
    tabSingleBtn.classList.remove("active");
    panelBatch.hidden = false;
    panelSingle.hidden = true;
  }
}

// --- Single URL Scan ---
async function scanSingleUrl(url) {
  setLoading(true);
  resultCard.hidden = true;
  const startedAt = performance.now();

  try {
    const response = await fetch("/api/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "Analysis request rejected by server.");
    }
    const elapsedMs = performance.now() - startedAt;
    lastScanResult = payload;
    renderResult(payload, elapsedMs);
    saveToHistory(payload);
  } catch (err) {
    showError(err.message || "Failed to reach inference daemon. Confirm backend container is running.");
  } finally {
    setLoading(false);
  }
}

function setLoading(isLoading) {
  scanButton.disabled = isLoading;
  loadingState.hidden = !isLoading;
  form.setAttribute("aria-busy", String(isLoading));
  const label = scanButton.querySelector(".button-label");
  if (label) label.textContent = isLoading ? "Processing…" : "Execute Analysis";
}

function showError(msg) {
  errorBox.textContent = msg;
  errorBox.hidden = false;
}

// --- Render Result Card ---
function renderResult(data, elapsedMs) {
  const isPhishing = data.prediction === 1;
  const scorePercent = (data.model_score * 100).toFixed(1);

  // Verdict Lockup
  const badge = document.querySelector("#result-badge");
  badge.classList.toggle("is-phishing", isPhishing);
  badge.classList.toggle("is-legitimate", !isPhishing);

  document.querySelector("#result-symbol").textContent = isPhishing ? "!" : "✓";
  document.querySelector("#result-label").textContent = isPhishing ? "Phishing Threat Pattern Detected" : "Legitimate URL Characteristics";
  document.querySelector("#result-url").textContent = data.url;

  // Score & Gauge
  const scoreEl = document.querySelector("#result-score");
  scoreEl.textContent = `${scorePercent}%`;
  scoreEl.style.color = isPhishing ? "var(--threat-text)" : "var(--safe-text)";

  const bar = document.querySelector("#risk-progress-bar");
  bar.style.width = `${Math.min(100, Math.max(2, scorePercent))}%`;
  bar.classList.toggle("phish", isPhishing);

  // Telemetry Deck
  document.querySelector("#result-model").textContent = data.model_name || "RandomForest";
  document.querySelector("#result-threshold").textContent = Number(data.threshold).toFixed(3);
  document.querySelector("#result-time").textContent = `${Number(data.processing_time_ms ?? elapsedMs).toFixed(1)} ms`;

  const severityEl = document.querySelector("#result-severity");
  if (data.model_score >= 0.7) {
    severityEl.textContent = "High Probability Threat";
    severityEl.style.color = "var(--threat-text)";
  } else if (data.model_score >= 0.5) {
    severityEl.textContent = "Elevated Risk Margin";
    severityEl.style.color = "var(--amber)";
  } else {
    severityEl.textContent = "Nominal / Low Risk";
    severityEl.style.color = "var(--safe-text)";
  }

  // Render 11 Feature Matrix Ledger
  renderFeatureGrid(data.features || {});

  // Render Observed Indicators
  const indicatorList = document.querySelector("#indicator-list");
  indicatorList.replaceChildren();

  const active = (data.relevant_indicators || []).map((key) => {
    const li = document.createElement("li");
    li.textContent = indicatorLabels[key] || key.replaceAll("_", " ");
    return li;
  });

  if (!active.length) {
    const li = document.createElement("li");
    li.textContent = "Zero structural anomalies identified across observable dimensions.";
    active.push(li);
  }
  indicatorList.append(...active);

  resultCard.hidden = false;
  resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function renderFeatureGrid(features) {
  const container = document.querySelector("#feature-grid");
  if (!container) return;
  container.replaceChildren();

  Object.entries(FEATURE_META).forEach(([key, meta]) => {
    const val = features[key] ?? 0;
    let isWarn = false;

    if (meta.unit === "bool") {
      isWarn = meta.isReverse ? val === 0 : val === 1;
    } else {
      isWarn = val >= meta.threshold;
    }

    const card = document.createElement("div");
    card.className = `matrix-cell ${isWarn ? "anomalous" : ""}`;

    let displayVal = val;
    if (meta.unit === "bool") {
      displayVal = val === 1 ? "Present" : "Absent";
    }

    card.innerHTML = `
      <div class="cell-top">
        <span class="cell-name">${meta.label}</span>
        <span class="cell-tag ${isWarn ? "warn" : "normal"}">${isWarn ? "ANOMALOUS" : "NOMINAL"}</span>
      </div>
      <div class="cell-figure">${displayVal} <small style="font-size:10px;color:var(--text-muted);font-weight:normal">${meta.unit !== "bool" ? meta.unit : ""}</small></div>
      <div class="cell-desc">${meta.desc}</div>
    `;

    container.appendChild(card);
  });
}

// --- Batch URL Scanner ---
async function runBatchScan() {
  const text = batchTextarea.value.trim();
  if (!text) {
    alert("Please provide URL targets in the textarea.");
    return;
  }

  const urls = text.split("\n").map(s => s.trim()).filter(Boolean);
  if (!urls.length) return;

  btnRunBatch.disabled = true;
  batchSpinner.hidden = false;
  batchResultsWrap.hidden = false;
  batchTbody.replaceChildren();

  let safeCount = 0;
  let phishCount = 0;

  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><span class="status-badge" style="background:rgba(255,255,255,0.04)">Processing…</span></td>
      <td style="font-family:var(--font-mono);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(url)}</td>
      <td>—</td>
      <td>—</td>
      <td>—</td>
    `;
    batchTbody.appendChild(row);

    try {
      const response = await fetch("/api/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await response.json();

      if (response.ok) {
        const isPhish = data.prediction === 1;
        if (isPhish) phishCount++; else safeCount++;
        saveToHistory(data);

        row.innerHTML = `
          <td><span class="status-badge ${isPhish ? "threat" : "safe"}">${isPhish ? "THREAT" : "NOMINAL"}</span></td>
          <td style="font-family:var(--font-mono);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(data.url)}">${escapeHtml(data.url)}</td>
          <td style="font-weight:600;color:${isPhish ? "var(--threat-text)" : "var(--safe-text)"}">${data.label}</td>
          <td style="font-family:var(--font-mono)">${(data.model_score * 100).toFixed(1)}%</td>
          <td style="font-size:11.5px;color:var(--text-secondary)">${(data.relevant_indicators || []).join(", ") || "Clean"}</td>
        `;
      } else {
        row.innerHTML = `
          <td><span class="status-badge threat">REJECTED</span></td>
          <td style="font-family:var(--font-mono)">${escapeHtml(url)}</td>
          <td colspan="3" style="color:var(--threat-text)">${escapeHtml(data.detail || "Validation Error")}</td>
        `;
      }
    } catch (e) {
      row.innerHTML = `
        <td><span class="status-badge threat">FAILED</span></td>
        <td style="font-family:var(--font-mono)">${escapeHtml(url)}</td>
        <td colspan="3" style="color:var(--threat-text)">Transport Connection Failed</td>
      `;
    }

    batchTotal.textContent = urls.length;
    batchSafe.textContent = safeCount;
    batchPhish.textContent = phishCount;
    const ratio = Math.round((phishCount / (safeCount + phishCount || 1)) * 100);
    batchRatio.textContent = `${ratio}%`;
  }

  btnRunBatch.disabled = false;
  batchSpinner.hidden = true;
  renderHistory();
}

// --- Local Storage History ---
function getHistory() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveToHistory(item) {
  const list = getHistory();
  const entry = {
    id: Date.now() + Math.random().toString(36).substring(2, 7),
    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    url: item.url,
    label: item.label,
    prediction: item.prediction,
    score: (item.model_score * 100).toFixed(1),
    model: item.model_name || "RandomForest"
  };
  list.unshift(entry);
  if (list.length > 50) list.pop();
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  renderHistory();
}

function renderHistory() {
  const list = getHistory();
  if (!historyTbody) return;

  if (!list.length) {
    historyTbody.innerHTML = `<tr class="empty-state-row"><td colspan="5">No transactions recorded in this execution context. Run an analysis above to populate audit telemetry.</td></tr>`;
    return;
  }

  historyTbody.replaceChildren();
  list.slice(0, 15).forEach((item) => {
    const isPhish = item.prediction === 1;
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="color:var(--text-muted);font-family:var(--font-mono);font-size:12px">${item.timestamp}</td>
      <td style="font-family:var(--font-mono);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</td>
      <td><span class="status-badge ${isPhish ? "threat" : "safe"}">${item.label}</span></td>
      <td style="font-family:var(--font-mono);font-weight:700;color:${isPhish ? "var(--threat-text)" : "var(--safe-text)"}">${item.score}%</td>
      <td style="color:var(--text-secondary);font-size:12px">${item.model}</td>
    `;
    historyTbody.appendChild(tr);
  });
}

function exportHistoryCSV() {
  const list = getHistory();
  if (!list.length) {
    alert("Audit log is currently empty.");
    return;
  }
  const headers = ["Timestamp", "URL", "Verdict", "Threat Probability", "Model Architecture"];
  const rows = list.map(item => [
    `"${item.timestamp}"`,
    `"${item.url.replaceAll('"', '""')}"`,
    `"${item.label}"`,
    `"${item.score}%"`,
    `"${item.model}"`
  ]);
  const csvContent = [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishguard_audit_trail_${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// --- Model Info Fetcher ---
async function loadModelInfo() {
  try {
    const [infoRes, metricsRes] = await Promise.all([
      fetch("/api/model-info"),
      fetch("/api/metrics")
    ]);
    const info = await infoRes.json();
    const metrics = metricsRes.ok ? await metricsRes.json() : null;
    const ready = info.status === "ready";

    const heroStatus = document.querySelector("#hero-model-status");
    if (heroStatus) heroStatus.textContent = ready ? (info.model_name || "Random Forest Classifier") : "Model Offline";

    const light = document.querySelector("#model-status-light");
    if (light) light.classList.toggle("is-ready", ready);

    const statusText = document.querySelector("#model-status-text");
    if (statusText) statusText.textContent = ready ? "Operational • Ready" : "Classifier Offline";

    const modelName = document.querySelector("#model-name");
    if (modelName) modelName.textContent = ready ? info.model_name : "Classifier Unavailable";

    const featureCount = document.querySelector("#feature-count");
    if (featureCount) featureCount.textContent = String((info.feature_names || []).length || 11);

    if (metrics?.test_metrics) {
      const f1El = document.querySelector("#model-f1");
      if (f1El) f1El.textContent = Number(metrics.test_metrics.f1_score).toFixed(3);
    }
  } catch {
    const statusText = document.querySelector("#model-status-text");
    if (statusText) statusText.textContent = "Offline Mode";
  }
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
