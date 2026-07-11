const API_BASE = "http://127.0.0.1:5001";
let currentTabUrl = "";

function canonicalUrl(url) {
  try {
    const parsed = new URL(url);
    parsed.hash = "";
    if (parsed.pathname === "/") {
      parsed.pathname = "";
    }
    return parsed.toString().replace(/\/$/, "");
  } catch (error) {
    return url || "";
  }
}

function escapeHTML(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function riskTone(score) {
  if (score >= 80) return "danger";
  if (score >= 40) return "warning";
  return "safe";
}

function verdictText(data) {
  return data.prediction === "Safe" ? "SAFE WEBSITE" : "PHISHING DETECTED";
}

function renderResult(data) {
  const resultDiv = document.getElementById("result");
  const score = Number(data.risk_score || 0);
  const tone = riskTone(score);
  const explanations = data.layer3?.explanations || [];
  const contributions = data.layer2?.contributions || [];

  resultDiv.className = `result-card ${tone}`;
  resultDiv.innerHTML = `
    <div class="verdict-row">
      <div
        class="risk-ring"
        style="background: conic-gradient(var(--meter) ${score * 3.6}deg, rgba(148,163,184,0.14) 0deg);"
      >
        <div>
          <strong>${score}%</strong>
          <span>risk</span>
        </div>
      </div>
      <div>
        <span class="eyebrow">Final verdict</span>
        <h2>${escapeHTML(verdictText(data))}</h2>
        <p>${escapeHTML(data.layer3?.threat_type || "Safe Browsing")}</p>
      </div>
    </div>

    <div class="layer-grid">
      <div>
        <span>URL Layer</span>
        <strong>${escapeHTML(data.prediction || "Safe")}</strong>
      </div>
      <div>
        <span>ML Confidence</span>
        <strong>${escapeHTML(data.layer2?.confidence || 0)}%</strong>
      </div>
      <div>
        <span>Severity</span>
        <strong>${escapeHTML(data.layer3?.severity || "Low")}</strong>
      </div>
    </div>

    <h3>Why flagged</h3>
    <ul>
      ${
        explanations.length > 0
          ? explanations.slice(0, 4).map((item) => `<li>${escapeHTML(item)}</li>`).join("")
          : "<li>No strong phishing indicators detected</li>"
      }
    </ul>

    <h3>Top risk factors</h3>
    <div class="factor-list">
      ${
        contributions
          .filter((item) => Number(String(item.impact || "0").replace("+", "")) > 0)
          .slice(0, 4)
          .map((item) => {
            const impact = Number(String(item.impact || "0").replace("+", ""));
            return `
              <div class="factor">
                <span>${escapeHTML(item.name)}</span>
                <b>${escapeHTML(item.impact)}</b>
                <i style="width: ${Math.min(impact * 2, 100)}%"></i>
              </div>
            `;
          })
          .join("") || "<p class='safe-note'>No major risk factors detected</p>"
      }
    </div>
  `;
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });
  return tab;
}

async function getPageContent(tabId) {
  const fallback = {
    hasPasswordField: false,
    formCount: 0,
    suspiciousWords: 0,
    hasExternalFormAction: false,
    hasRedirectScript: false,
    detectedBrands: []
  };

  try {
    const response = await chrome.tabs.sendMessage(tabId, {
      action: "getPageContent"
    });
    return response || fallback;
  } catch (err) {
    return fallback;
  }
}

async function loadCurrentTab() {
  const tab = await getActiveTab();
  currentTabUrl = canonicalUrl(tab?.url || "");
  document.getElementById("current-url").innerText = currentTabUrl || "No active tab";

  try {
    const cached = await chrome.runtime.sendMessage({
      action: "getLatestResult",
      url: currentTabUrl
    });

    if (cached?.result) {
      renderResult(cached.result);
    }
  } catch (error) {
    // The popup can still run an explicit scan if no cached result is available.
  }
}

async function scanCurrentWebsite() {
  const resultDiv = document.getElementById("result");
  resultDiv.className = "result-empty";
  resultDiv.innerHTML = "<p>Scanning URL, ML model, content, and blacklist layers...</p>";

  try {
    const tab = await getActiveTab();
    currentTabUrl = canonicalUrl(tab?.url || currentTabUrl);
    const pageContent = await getPageContent(tab.id);

    const response = await fetch(`${API_BASE}/api/scan/url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        url: currentTabUrl,
        content_data: pageContent
      })
    });

    const data = await response.json();

    if (!response.ok || data.error) {
      throw new Error(data.error || "Scan failed");
    }

    renderResult(data);
  } catch (error) {
    resultDiv.className = "error-box";
    resultDiv.innerHTML = `
      <strong>Backend connection failed</strong>
      <span>${escapeHTML(error.message)}</span>
    `;
  }
}

document.getElementById("scanBtn").addEventListener("click", scanCurrentWebsite);

document.getElementById("dashboardBtn").addEventListener("click", () => {
  chrome.tabs.create({
    url: "http://localhost:3000"
  });
});

loadCurrentTab();
