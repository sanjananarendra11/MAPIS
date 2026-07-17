function extractPageContent() {
  const pageData = {
    hasPasswordField: false,
    formCount: 0,
    suspiciousWords: 0,
    hasExternalFormAction: false,
    hasRedirectScript: false,
    detectedBrands: []
  };

  try {
    // Safe body check
    if (!document.body) {
      return pageData;
    }

    // 1. Password fields
    const passwordFields = document.querySelectorAll(
      'input[type="password"]'
    );

    pageData.hasPasswordField = passwordFields.length > 0;

    // 2. Forms count
    const forms = document.querySelectorAll("form");
    pageData.formCount = forms.length;

    // 3. External form action
    forms.forEach(form => {
      const action = form.getAttribute("action");

      if (
        action &&
        action.startsWith("http") &&
        !action.includes(window.location.hostname)
      ) {
        pageData.hasExternalFormAction = true;
      }
    });

    // 4. Suspicious keywords
    const suspiciousKeywords = [
      "login",
      "verify",
      "password",
      "secure",
      "account",
      "confirm",
      "update",
      "bank",
      "payment",
      "signin",
      "wallet",
      "alert",
      "suspended"
    ];

    const bodyText = (
      document.body.innerText || ""
    ).toLowerCase();

    suspiciousKeywords.forEach(word => {
      if (bodyText.includes(word)) {
        pageData.suspiciousWords++;
      }
    });

    // 5. Redirect detection
    const scripts = document.querySelectorAll("script");

    scripts.forEach(script => {
      const text = (
        script.innerText || ""
      ).toLowerCase();

      if (
        text.includes("window.location") ||
        text.includes("location.href")
      ) {
        pageData.hasRedirectScript = true;
      }
    });

    // 6. Brand detection
    const knownBrands = [
      "google",
      "paypal",
      "amazon",
      "facebook",
      "microsoft",
      "apple",
      "icloud",
      "bank"
    ];

    knownBrands.forEach(brand => {
      if (bodyText.includes(brand)) {
        pageData.detectedBrands.push(brand);
      }
    });

  } catch (error) {
    console.log("Content extraction error:", error);
  }

  return pageData;
}

function showMapisWarning(payload) {
  const existing = document.getElementById("mapis-warning-overlay");

  if (existing) {
    existing.remove();
  }

  const score = Number(payload.risk_score || 0);
  const severity = String(payload.layer3?.severity || (score >= 80 ? "High" : "Medium")).toLowerCase();
  const isHighRisk = score >= 70 || payload.prediction === "Dangerous";
  const reasons = (payload.layer3?.explanations || [])
    .filter(Boolean)
    .slice(0, 3)
    .join(". ");

  const overlay = document.createElement("div");
  overlay.id = "mapis-warning-overlay";
  overlay.style.cssText = `
    position: fixed;
    inset: 0;
    z-index: 2147483647;
    display: grid;
    place-items: center;
    background: rgba(2, 6, 23, 0.84);
    backdrop-filter: blur(3px);
    font-family: Inter, Arial, sans-serif;
  `;

  const card = document.createElement("div");
  card.style.cssText = `
    width: min(520px, calc(100vw - 32px));
    border: 1px solid rgba(239, 68, 68, 0.55);
    border-radius: 8px;
    padding: 24px;
    color: #f8fafc;
    background: #0b1220;
    box-shadow: 0 24px 80px rgba(0, 0, 0, 0.5);
  `;

  const eyebrow = document.createElement("div");
  eyebrow.textContent = "MAPIS WARNING";
  eyebrow.style.cssText = `
    margin-bottom: 12px;
    color: #f87171;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 3px;
  `;

  const title = document.createElement("h2");
  title.textContent = isHighRisk
    ? "Dangerous phishing page detected"
    : "Suspicious phishing signals detected";
  title.style.cssText = `
    margin: 0 0 10px;
    color: #f8fafc;
    font-size: 28px;
    line-height: 1.15;
    font-weight: 700;
  `;

  const message = document.createElement("p");
  message.textContent = `Risk score ${score}/100. Threat level: ${severity}. ${reasons || "MAPIS found suspicious URL or webpage signals."}`;
  message.style.cssText = `
    margin: 0 0 20px;
    color: #cbd5e1;
    font-size: 16px;
    line-height: 1.55;
  `;

  const actions = document.createElement("div");
  actions.style.cssText = `
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
  `;

  const closeButton = document.createElement("button");
  closeButton.textContent = "Dismiss";
  closeButton.style.cssText = `
    min-height: 46px;
    border: 0;
    border-radius: 8px;
    padding: 0 18px;
    color: white;
    background: #ef4444;
    font-weight: 700;
    cursor: pointer;
  `;
  closeButton.addEventListener("click", () => overlay.remove());

  const backButton = document.createElement("button");
  backButton.textContent = "Go Back";
  backButton.style.cssText = `
    min-height: 46px;
    border: 1px solid rgba(148, 163, 184, 0.18);
    border-radius: 8px;
    padding: 0 18px;
    color: #e2e8f0;
    background: #111827;
    font-weight: 700;
    cursor: pointer;
  `;
  backButton.addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "about:blank";
    }
  });

  actions.append(closeButton, backButton);
  card.append(eyebrow, title, message, actions);
  overlay.appendChild(card);
  document.documentElement.appendChild(overlay);
}

window.addEventListener("message", (event) => {
  if (event.source !== window) {
    return;
  }

  const message = event.data || {};

  if (message.source !== "MAPIS_DASHBOARD") {
    return;
  }

  if (message.type === "MAPIS_AUTH_TOKEN") {
    chrome.runtime.sendMessage({
      action: "setAuthToken",
      token: message.token || ""
    });
  }

  if (message.type === "MAPIS_CLEAR_AUTH_TOKEN") {
    chrome.runtime.sendMessage({
      action: "clearAuthToken"
    });
  }
});

chrome.runtime.onMessage.addListener(
  function (request, sender, sendResponse) {
    if (request.action === "getPageContent") {
      sendResponse(extractPageContent());
      return true;
    }

    if (request.action === "showMapisWarning") {
      showMapisWarning(request.payload || {});
      sendResponse({ shown: true });
      return true;
    }
  }
);
