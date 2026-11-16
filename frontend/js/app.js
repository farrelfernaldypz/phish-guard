const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const scanButton = document.querySelector("#scan-button");
const errorBox = document.querySelector("#form-error");
const loadingState = document.querySelector("#loading-state");
const resultCard = document.querySelector("#result-card");
const characterCount = document.querySelector("#char-count");
const indicatorLabels = {
  has_ip_address: "Hostname is an IP address",
  has_punycode: "Punycode appears in hostname",
  has_port: "Non-default or explicit port",
  has_suspicious_keyword: "Suspicious keyword in URL",
  suspicious_keyword_count: "Suspicious keyword occurrences",
  has_url_shortener: "Known URL shortener hostname",
  has_double_slash_redirect_pattern: "Double slash in URL path",
  count_subdomains: "Multiple subdomain labels",
  url_length: "Long URL structure",
  uses_https: "HTTPS scheme present"
};

input.addEventListener("input", () => {
  characterCount.textContent = `${input.value.length} / 2048`;
  errorBox.hidden = true;
});
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  resultCard.hidden = true;
  const url = input.value.trim();
  if (!url) {
    showError("Enter a URL before scanning.");
    input.focus();
    return;
  }
  setLoading(true);
  const startedAt = performance.now();
  try {
    const response = await fetch("/api/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "The scan could not be completed.");
    renderResult(payload, performance.now() - startedAt);
  } catch (error) {
    showError(error.message || "Could not reach PhishGuard. Try again in a moment.");
  } finally {
    setLoading(false);
  }
});

function setLoading(isLoading) {
  scanButton.disabled = isLoading;
  form.setAttribute("aria-busy", String(isLoading));
  loadingState.hidden = !isLoading;
  scanButton.querySelector(".button-label").textContent = isLoading ? "Scanning…" : "Scan URL";
}
function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}
function renderResult(data, elapsedMs) {
  const phishing = data.prediction === 1;
  const badge = document.querySelector("#result-badge");
  badge.classList.toggle("is-phishing", phishing);
  badge.classList.toggle("is-legitimate", !phishing);
  document.querySelector("#result-symbol").textContent = phishing ? "!" : "✓";
  document.querySelector("#result-label").textContent = data.label;
  document.querySelector("#result-url").textContent = data.url;
  document.querySelector("#result-score").textContent = `${(data.model_score * 100).toFixed(1)}%`;
  document.querySelector("#result-model").textContent = data.model_name || "—";
  document.querySelector("#result-threshold").textContent = Number(data.threshold).toFixed(3);
  document.querySelector("#result-time").textContent = `${Number(data.processing_time_ms ?? elapsedMs).toFixed(1)} ms`;
  const list = document.querySelector("#indicator-list");
  list.replaceChildren();
  const features = data.features || {};
  const active = (data.relevant_indicators || []).map((name) => {
    const item = document.createElement("li");
    item.textContent = indicatorLabels[name] || name.replaceAll("_", " ");
    if (name === "suspicious_keyword_count") item.textContent += `: ${features[name]}`;
    return item;
  });
  if (!active.length) {
    const item = document.createElement("li");
    item.textContent = "No listed structural indicator was triggered.";
    active.push(item);
  }
  list.append(...active);
  resultCard.hidden = false;
  resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
}
async function loadModelInfo() {
  try {
    const [infoResponse, metricsResponse] = await Promise.all([fetch("/api/model-info"), fetch("/api/metrics")]);
    const info = await infoResponse.json();
    const metrics = metricsResponse.ok ? await metricsResponse.json() : null;
    const ready = info.status === "ready";
    document.querySelector("#hero-model-status").textContent = ready ? info.model_name : "MODEL NOT TRAINED";
    document.querySelector("#model-status-text").textContent = ready ? "Ready for URL analysis" : "Model artifact not found";
    document.querySelector("#model-status-light").classList.toggle("is-ready", ready);
    document.querySelector("#model-name").textContent = ready ? info.model_name : "Model not trained yet";
    document.querySelector("#model-message").textContent = ready ? "A locally trained classifier is available for URL-only analysis." : "Add a labeled URL dataset and run the training pipeline to enable scanning.";
    document.querySelector("#feature-count").textContent = String((info.feature_names || []).length || 21);
    const datasetName = info.metadata?.dataset?.source_file || "Not available";
    document.querySelector("#model-dataset").textContent = datasetName;
    document.querySelector("#dataset-status").textContent = ready ? `Training dataset: ${datasetName}` : "Predictions are disabled until a valid model artifact is installed.";
    if (metrics?.test_metrics) {
      document.querySelector("#model-f1").textContent = Number(metrics.test_metrics.f1_score).toFixed(3);
      document.querySelector("#metrics-note").textContent = `Held-out test: precision ${Number(metrics.test_metrics.precision).toFixed(3)} · recall ${Number(metrics.test_metrics.recall).toFixed(3)} · F1 ${Number(metrics.test_metrics.f1_score).toFixed(3)}. Metrics are from the recorded training run.`;
    }
  } catch {
    document.querySelector("#model-status-text").textContent = "Status unavailable";
    document.querySelector("#dataset-status").textContent = "Could not load model metadata from the backend.";
  }
}
loadModelInfo();

