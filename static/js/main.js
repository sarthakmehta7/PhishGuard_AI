/**
 * PhishGuard AI — Frontend Logic
 * Authors: Sarthak Mehta, Prajwal Kumar, Divyansh Yadav
 */

"use strict";

let lastScanData = null;
let lastScanId   = null;

// ── Scan entry ────────────────────────────────────────────────
async function startScan() {
  const input = document.getElementById("urlInput");
  const url   = input.value.trim();
  if (!url) { showToast("Enter a URL first", "err"); input.focus(); return; }

  const btn = document.getElementById("scanBtn");
  btn.classList.add("scanning");
  document.getElementById("scanBtnText").textContent = "Scanning…";

  hideResult();
  showLoading();

  const steps = [
    "Extracting 30 URL features…",
    "Querying DNS records…",
    "Inspecting SSL certificate…",
    "Running WHOIS lookup…",
    "Checking HTTP response & headers…",
    "Running ensemble ML prediction…",
    "Generating report…",
  ];
  let si = 0;
  const stepsEl = document.getElementById("scanSteps");
  stepsEl.innerHTML = "";
  const stepTimer = setInterval(() => {
    if (si < steps.length) {
      const d = document.createElement("div");
      d.className = "scan-step";
      d.style.animationDelay = si * 0.06 + "s";
      d.innerHTML = `<span class="step-check">✓</span> ${steps[si++]}`;
      stepsEl.appendChild(d);
    } else clearInterval(stepTimer);
  }, 520);

  try {
    const res  = await fetch("/scan", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
    });
    const data = await res.json();
    clearInterval(stepTimer);

    if (data.error) {
      hideLoading();
      showToast("Error: " + data.error, "err");
    } else {
      lastScanData = data;
      lastScanId   = data.scan_id;
      hideLoading();
      renderResult(data);
    }
  } catch (e) {
    clearInterval(stepTimer);
    hideLoading();
    showToast("Network error — is the server running?", "err");
  } finally {
    btn.classList.remove("scanning");
    document.getElementById("scanBtnText").textContent = "Scan Now";
  }
}

// ── Keyboard shortcut ─────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const inp = document.getElementById("urlInput");
  if (inp) {
    inp.addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });
    inp.focus();
  }
});

function loadExample(url) {
  const inp = document.getElementById("urlInput");
  if (inp) { inp.value = url; inp.focus(); }
}

// ── Render Result ─────────────────────────────────────────────
function renderResult(data) {
  const section = document.getElementById("resultSection");
  section.style.display = "block";

  // Verdict card
  const cls   = data.prediction_class;
  const icons = { safe: "✅", suspicious: "⚠️", phishing: "🚨" };
  document.getElementById("verdictCard").className = `verdict-card ${cls}`;
  document.getElementById("verdictIcon").textContent = icons[cls] || "🔍";
  document.getElementById("verdictText").textContent = data.prediction.toUpperCase();
  document.getElementById("verdictUrl").textContent  = "🔗 " + data.url;

  // Risk ring
  const pct  = Math.min(data.risk_score, 99.9);
  const circ = 289; // 2πr ≈ 289 for r=46
  const off  = circ - (pct / 100) * circ;
  document.getElementById("riskPct").textContent = pct.toFixed(1) + "%";
  setTimeout(() => {
    document.getElementById("riskArc").style.strokeDashoffset = off;
  }, 100);

  // Probability bars
  const probs = data.probabilities;
  document.getElementById("probRow").innerHTML = [
    ["safe",       "Safe",       probs.safe],
    ["suspicious", "Suspicious", probs.suspicious],
    ["phishing",   "Phishing",   probs.phishing],
  ].map(([cls, label, pct]) => `
    <div class="prob-item prob-${cls}">
      <div class="prob-header">
        <span class="prob-name">${label}</span>
        <span class="prob-pct">${pct.toFixed(1)}%</span>
      </div>
      <div class="prob-bar">
        <div class="prob-fill" style="width:0%" data-target="${pct}%"></div>
      </div>
    </div>
  `).join("");
  setTimeout(() => {
    document.querySelectorAll(".prob-fill").forEach(el => {
      el.style.width = el.dataset.target;
    });
  }, 150);

  // Live checks grid
  renderChecks(data);

  // ML Features
  renderFeatures(data.features);

  // Findings
  document.getElementById("findingsList").innerHTML =
    (data.reasons || []).map(r => `
      <div class="finding-item ${r.severity}">
        <span class="fi-icon">${r.icon}</span>
        <span class="fi-text">${esc(r.text)}</span>
      </div>
    `).join("") || '<div class="finding-item info"><span class="fi-text">No findings.</span></div>';

  // Recommendations
  document.getElementById("recoList").innerHTML =
    (data.recommendations || []).map(r => `
      <div class="reco-item">
        <span class="reco-bullet">▸</span>
        <span>${esc(r)}</span>
      </div>
    `).join("");

  section.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderChecks(data) {
  const ssl   = data.ssl   || {};
  const dns   = data.dns   || {};
  const http  = data.http  || {};
  const whois = data.whois || {};
  const gsb   = data.gsb   || {};

  const sslDot   = ssl.valid  ? "dot-green"  : ssl.error ? "dot-red" : "dot-yellow";
  const dnsDot   = dns.resolves ? "dot-green" : "dot-red";
  const httpDot  = (http.status_code === 200) ? "dot-green" : http.status_code ? "dot-yellow" : "dot-gray";
  const ageDot   = whois.age_days == null ? "dot-gray" : whois.age_days < 30 ? "dot-red" : whois.age_days < 180 ? "dot-yellow" : "dot-green";
  const gsbDot   = gsb.flagged ? "dot-red" : "dot-green";

  document.getElementById("checksGrid").innerHTML = `
    <div class="check-card">
      <div class="check-title">SSL Certificate</div>
      <div class="check-val"><span class="check-dot ${sslDot}"></span>${ssl.valid ? "Valid" : ssl.error ? "Invalid" : "No HTTPS"}</div>
      <div class="check-sub">${ssl.issuer ? "Issuer: " + esc(ssl.issuer) : ""} ${ssl.expires ? "· Exp: " + ssl.expires : ""} ${ssl.days_left != null ? "· " + ssl.days_left + "d left" : ""}</div>
    </div>
    <div class="check-card">
      <div class="check-title">DNS Resolution</div>
      <div class="check-val"><span class="check-dot ${dnsDot}"></span>${dns.resolves ? "Resolves" : "Does Not Resolve"}</div>
      <div class="check-sub">${(dns.ip_addresses || []).slice(0,2).join(", ") || "No IPs found"}</div>
    </div>
    <div class="check-card">
      <div class="check-title">HTTP Response</div>
      <div class="check-val"><span class="check-dot ${httpDot}"></span>HTTP ${http.status_code || "N/A"}</div>
      <div class="check-sub">
        ${http.server ? "Server: " + esc(http.server) : ""}
        ${http.response_time_ms ? " · " + http.response_time_ms + "ms" : ""}
        ${http.has_hsts ? " · HSTS ✓" : ""}
        ${http.has_csp ? " · CSP ✓" : ""}
      </div>
    </div>
    <div class="check-card">
      <div class="check-title">Domain Age (WHOIS)</div>
      <div class="check-val"><span class="check-dot ${ageDot}"></span>${whois.age_days != null ? whois.age_days + " days old" : "Unknown"}</div>
      <div class="check-sub">${whois.registrar ? "Registrar: " + esc(whois.registrar).slice(0,40) : "No WHOIS data"} ${whois.country ? "· " + whois.country : ""}</div>
    </div>
    <div class="check-card">
      <div class="check-title">Threat Signals</div>
      <div class="check-val"><span class="check-dot ${gsbDot}"></span>${gsb.flagged ? "Flagged — Score " + gsb.score : "No Threats Found"}</div>
      <div class="check-sub">${(gsb.risk_signals || []).slice(0,2).map(s => esc(s)).join("<br>") || "Clean heuristic scan"}</div>
    </div>
    <div class="check-card">
      <div class="check-title">Security Headers</div>
      <div class="check-val"><span class="check-dot ${(http.has_hsts && http.has_csp) ? "dot-green" : "dot-yellow"}"></span>${[http.has_hsts && "HSTS", http.has_csp && "CSP", http.has_xframe && "X-Frame"].filter(Boolean).join(", ") || "None detected"}</div>
      <div class="check-sub">HTTP security headers protect against common attacks</div>
    </div>
  `;
}

function renderFeatures(features) {
  if (!features) return;
  const items = [
    ["HTTPS",         features.has_https        ? "YES ✓"    : "NO ✗",    features.has_https        ? "ok"  : "bad"],
    ["URL Length",    features.url_length,                                  features.url_length > 100 ? "bad" : features.url_length > 75 ? "warn" : "ok"],
    ["Domain Len",    features.domain_length,                               features.domain_length > 30 ? "warn" : "ok"],
    ["Subdomains",    features.subdomain_count,                             features.subdomain_count >= 3 ? "bad" : features.subdomain_count >= 2 ? "warn" : "ok"],
    ["Keywords",      features.phishing_keyword_count + " found",           features.phishing_keyword_count > 0 ? "bad" : "ok"],
    ["Has IP",        features.has_ip_address    ? "YES ✗"    : "NO ✓",   features.has_ip_address   ? "bad" : "ok"],
    ["Shortened",     features.is_shortened      ? "YES ✗"    : "NO ✓",   features.is_shortened     ? "warn" : "ok"],
    ["Susp. TLD",     features.suspicious_tld   ? "YES ✗"    : "NO ✓",   features.suspicious_tld   ? "bad" : "ok"],
    ["Brand Subd.",   features.brand_in_subdomain ? "YES ✗"   : "NO ✓",   features.brand_in_subdomain ? "bad" : "ok"],
    ["Brand Domain",  features.brand_in_domain   ? "YES ✗"    : "NO ✓",  features.brand_in_domain  ? "bad" : "ok"],
    ["@ Symbol",      features.num_at > 0        ? features.num_at + " ✗" : "NO ✓", features.num_at > 0 ? "bad" : "ok"],
    ["Dots",          features.num_dots,                                    features.num_dots > 5 ? "warn" : "ok"],
    ["Hyphens",       features.num_hyphens,                                 features.num_hyphens > 4 ? "warn" : "ok"],
    ["= Params",      features.num_equals,                                  features.num_equals > 3 ? "warn" : "ok"],
    ["Hex Encoded",   features.hex_chars         ? "YES ✗"    : "NO ✓",   features.hex_chars        ? "warn" : "ok"],
    ["Digit Ratio",   (features.ratio_digits * 100).toFixed(1) + "%",       features.ratio_digits > 0.2 ? "warn" : "ok"],
  ];
  document.getElementById("featureGrid").innerHTML = items.map(([name, val, cls]) => `
    <div class="feat-item">
      <div class="feat-name">${name}</div>
      <div class="feat-val feat-${cls}">${val}</div>
    </div>
  `).join("");
}

// ── Bulk Scanner ──────────────────────────────────────────────
async function runBulk() {
  const raw  = document.getElementById("bulkInput").value.trim();
  const urls = raw.split("\n").map(u => u.trim()).filter(Boolean).slice(0, 10);
  if (!urls.length) { showToast("Enter at least one URL", "err"); return; }

  const resultEl = document.getElementById("bulkResults");
  resultEl.style.display = "flex";
  resultEl.innerHTML = `<div style="font-family:var(--mono);font-size:13px;color:var(--text2)">Scanning ${urls.length} URL${urls.length > 1 ? "s" : ""}…</div>`;

  try {
    const res  = await fetch("/api/bulk-scan", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ urls }),
    });
    const data = await res.json();
    if (data.error) { showToast(data.error, "err"); return; }

    resultEl.innerHTML = data.results.map(r => `
      <div class="bulk-row">
        <span class="br-url">${esc(r.url)}</span>
        <span class="br-badge br-${r.prediction_class}">${r.prediction}</span>
        <span class="br-score">Risk: ${r.risk_score}%</span>
      </div>
    `).join("");
    showToast(`Scanned ${data.results.length} URL${data.results.length > 1 ? "s" : ""}`, "info");
  } catch (e) {
    showToast("Bulk scan failed", "err");
  }
}

// ── Actions ───────────────────────────────────────────────────
function resetScanner() {
  hideResult();
  const inp = document.getElementById("urlInput");
  if (inp) { inp.value = ""; inp.focus(); }
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function copyReport() {
  if (!lastScanData) return;
  const d = lastScanData;
  const lines = [
    "PhishGuard AI — Scan Report",
    "=".repeat(40),
    `URL:        ${d.url}`,
    `Verdict:    ${d.prediction}`,
    `Risk Score: ${d.risk_score}%`,
    `Scanned:    ${d.scanned_at}`,
    "",
    "Probabilities:",
    `  Safe:       ${d.probabilities.safe}%`,
    `  Suspicious: ${d.probabilities.suspicious}%`,
    `  Phishing:   ${d.probabilities.phishing}%`,
    "",
    "Detection Findings:",
    ...(d.reasons || []).map(r => `  ${r.icon} [${r.severity.toUpperCase()}] ${r.text}`),
    "",
    "Recommendations:",
    ...(d.recommendations || []).map(r => `  ▸ ${r}`),
    "",
    `Authors: Sarthak Mehta, Prajwal Kumar, Divyansh Yadav`,
  ];
  navigator.clipboard.writeText(lines.join("\n")).then(() => {
    showToast("Report copied to clipboard", "info");
  });
}

async function submitFeedback() {
  if (!lastScanId) return;
  const correct = confirm("Was the prediction WRONG?\nClick OK if the result was incorrect.");
  const comment = correct ? prompt("What should the correct result have been?") || "" : "";
  await fetch("/api/feedback", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ scan_id: lastScanId, url: lastScanData?.url, correct: !correct, comment }),
  });
  showToast("Feedback submitted — thank you!", "info");
}

// ── UI Helpers ────────────────────────────────────────────────
function showLoading() {
  document.getElementById("scanLoading").style.display = "block";
  document.getElementById("scanLoading").scrollIntoView({ behavior: "smooth", block: "center" });
}
function hideLoading() { document.getElementById("scanLoading").style.display = "none"; }
function hideResult()  { document.getElementById("resultSection").style.display = "none"; }

function showToast(msg, type = "info") {
  let wrap = document.querySelector(".toast-wrap");
  if (!wrap) {
    wrap = document.createElement("div");
    wrap.className = "toast-wrap";
    document.body.appendChild(wrap);
  }
  const t = document.createElement("div");
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  wrap.appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .4s"; setTimeout(() => t.remove(), 400); }, 3500);
}

function esc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
