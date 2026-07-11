const API_BASE = "http://127.0.0.1:5001";
const lastScanned = new Map();
const lastResults = new Map();

chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeBackgroundColor({ color: "#3b82f6" });
});

function shouldScan(url) {
  return Boolean(
    url &&
    (url.startsWith("http://") || url.startsWith("https://"))
  );
}

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

async function scanTab(tabId, url) {
  if (!shouldScan(url)) return;

  const normalizedUrl = canonicalUrl(url);
  const previous = lastScanned.get(tabId);
  if (previous === normalizedUrl) return;

  lastScanned.set(tabId, normalizedUrl);

  try {
    let contentData = {
      hasPasswordField: false,
      formCount: 0,
      suspiciousWords: 0,
      hasExternalFormAction: false,
      hasRedirectScript: false,
      detectedBrands: []
    };

    try {
      const pageResponse = await chrome.tabs.sendMessage(tabId, {
        action: "getPageContent"
      });
      contentData = pageResponse || contentData;
    } catch (contentError) {
      // Content scripts are not available on every Chrome page.
    }

    const response = await fetch(`${API_BASE}/api/scan/url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        url: normalizedUrl,
        content_data: contentData
      })
    });

    const data = await response.json();
    const score = Number(data.risk_score || 0);
    const isDanger = data.prediction !== "Safe" || score >= 40;
    lastResults.set(normalizedUrl, data);

    chrome.action.setBadgeText({
      tabId,
      text: score ? String(score) : "OK"
    });

    chrome.action.setBadgeBackgroundColor({
      tabId,
      color: isDanger ? "#ef4444" : "#22c55e"
    });

    if (isDanger) {
      chrome.tabs.sendMessage(tabId, {
        action: "showMapisWarning",
        payload: data
      }).catch(() => {});
    }
  } catch (error) {
    chrome.action.setBadgeText({
      tabId,
      text: ""
    });
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    scanTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    scanTab(tabId, tab.url);
  } catch (error) {
    lastScanned.delete(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  lastScanned.delete(tabId);
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action !== "getLatestResult") {
    return false;
  }

  const normalizedUrl = canonicalUrl(request.url || "");
  sendResponse({
    result: lastResults.get(normalizedUrl) || null
  });
  return true;
});
