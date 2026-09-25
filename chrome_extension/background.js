// Background Service Worker - Handles API calls and message routing
const DEFAULT_API_BASE = "http://127.0.0.1:8000";

function normalizeApiBase(value) {
  const base = (value || DEFAULT_API_BASE).trim().replace(/\/+$/, "");
  if (base.includes("web-production-b7ac.up.railway.app")) return DEFAULT_API_BASE;
  let parsed;
  try {
    parsed = new URL(base);
  } catch (_) {
    throw new Error("Backend API base must be a valid URL.");
  }
  const localHost = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (parsed.username || parsed.password) {
    throw new Error("Backend API base must not contain embedded credentials.");
  }
  if (!localHost && parsed.protocol !== "https:") {
    throw new Error("Use HTTPS for hosted backends. HTTP is allowed only for localhost development.");
  }
  if (!localHost && parsed.port) {
    throw new Error("Hosted backend URLs must use their standard HTTPS port.");
  }
  return base;
}

// Store API key securely in extension storage
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.set({
    apiKey: "",
    apiBase: DEFAULT_API_BASE,
    autoAnalyze: true,
    highlightScams: true
  });
  console.log("🛡️ Scam Shield initialized");
});

function getConfig() {
  return new Promise((resolve, reject) => {
    chrome.storage.sync.get(["apiKey", "apiBase"], (items) => {
      try {
        resolve({
          apiKey: (items.apiKey || "").trim(),
          apiBase: normalizeApiBase(items.apiBase),
        });
      } catch (error) {
        reject(error);
      }
    });
  });
}

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeEmail") {
    analyzeEmail(request.data)
      .then(result => {
          console.log("✅ Analysis completed", {
            is_scam: result.is_scam,
            risk_score: result.risk?.risk_score,
            risk_level: result.risk?.risk_level
          });
        sendResponse({ success: true, data: result });
      })
      .catch(error => {
        console.error("❌ Analysis error:", error);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Will respond asynchronously
  }
  
  if (request.action === "getFlaggedStats") {
    getFlaggedStats()
      .then(stats => {
        sendResponse({ success: true, data: stats });
      })
      .catch(error => {
        sendResponse({ success: false, error: error.message });
      });
    return true;
  }

  if (request.action === "testConnection") {
    testConnection(request)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
});

async function testConnection(overrides = {}) {
  const stored = await getConfig();
  const apiKey = (overrides.apiKey || stored.apiKey || '').trim();
  const apiBase = normalizeApiBase(overrides.apiBase || stored.apiBase);
  if (!apiKey) throw new Error("API key is not configured.");
  const response = await fetch(`${apiBase}/health/details`, {
    headers: { "x-api-key": apiKey }
  });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) throw new Error("API key rejected by backend.");
    throw new Error(`Backend health check failed: ${response.status}`);
  }
  return { apiBase };
}

/**
 * Analyze email using backend API
 */
async function analyzeEmail(emailData) {
  const { apiKey, apiBase } = await getConfig();
  if (!apiKey) {
    throw new Error("API key is not configured. Open extension popup and set it in Settings.");
  }

  const { from_email, from_name, subject, message_text, links } = emailData;
  
  const payload = {
    from_email: from_email || "unknown@example.com",
    from_name: from_name || "Unknown",
    subject: subject || "",
    message_text: message_text || "",
    links: links || []
  };
  
  console.log("📤 Sending email analysis request", {
    sender_present: Boolean(payload.from_email),
    subject_present: Boolean(payload.subject),
    message_length: payload.message_text.length,
    link_count: payload.links.length
  });
  
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  let response;
  try {
    response = await fetch(`${apiBase}/analyze-email`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Analysis timed out after 30 seconds. Check that the backend is running.");
    throw new Error(`Cannot reach backend at ${apiBase}. Check the API base URL and server status.`);
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    let detail = "";
    try {
      const errorBody = await response.json();
      detail = errorBody.detail || "";
    } catch (_) {
      // The server may return an empty or non-JSON error response.
    }
    if (response.status === 404) {
      throw new Error(`Analysis endpoint not found at ${apiBase}. Deploy the updated backend or set API Base to http://localhost:8000 in the extension settings.`);
    }
    if (response.status === 401 || response.status === 403) {
      throw new Error(`API key rejected by ${apiBase}. Use the key configured for that backend in the extension settings.`);
    }
    throw new Error(`API error: ${response.status} ${response.statusText}${detail ? ` - ${detail}` : ""}`);
  }
  
  const result = await response.json();
  console.log("✅ API analysis completed", {
    is_scam: result.is_scam,
    risk_level: result.risk?.risk_level
  });
  return result;
}

/**
 * Get flagged intelligence statistics
 */
async function getFlaggedStats() {
  const { apiKey, apiBase } = await getConfig();
  if (!apiKey) {
    throw new Error("API key is not configured. Open extension popup and set it in Settings.");
  }

  const response = await fetch(`${apiBase}/admin/flagged-intelligence`, {
    method: "GET",
    headers: {
      "x-api-key": apiKey
    }
  });
  
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(`Stats endpoint not found at ${apiBase}. Check the API Base setting.`);
    }
    if (response.status === 401 || response.status === 403) {
      throw new Error(`API key rejected by ${apiBase}. Update the API key in the extension settings.`);
    }
    throw new Error(`Stats API error: ${response.status}`);
  }
  
  return await response.json();
}

// Log service worker is active
console.log("🔒 Scam Shield background worker loaded");
