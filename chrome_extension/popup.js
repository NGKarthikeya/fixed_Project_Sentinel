// Popup script - Handle popup UI events
console.log("📋 Popup initialized");

// Load settings on popup open
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  setupToggleButtons();
  setupApiSettings();
  setupConnectionTest();
  loadApiSettings(() => loadFlaggedStats());
});

/**
 * Load and display flagged intelligence stats
 */
function loadFlaggedStats() {
  chrome.runtime.sendMessage(
    { action: "getFlaggedStats" },
    (response) => {
      if (chrome.runtime.lastError || !response) {
        const message = chrome.runtime.lastError?.message || "Background service did not respond";
        console.error("Failed to load stats:", message);
        document.getElementById('stat-total').textContent = "Error";
        return;
      }
      if (response.success) {
        document.getElementById('api-warning').style.display = 'none';
        const stats = response.data;
        document.getElementById('stat-upi').textContent = stats.flagged_upi_ids_count || 0;
        document.getElementById('stat-accounts').textContent = stats.flagged_bank_accounts_count || 0;
        document.getElementById('stat-links').textContent = stats.flagged_phishing_links_count || 0;
        document.getElementById('stat-total').textContent = stats.total_flagged || 0;
      } else {
        console.error("Failed to load stats:", response.error);
        if (response.error && response.error.includes("API key is not configured")) {
          document.getElementById('api-warning').style.display = 'block';
        }
        // Show error but don't break the UI
        document.getElementById('stat-total').textContent = "Error";
      }
    }
  );
}

/**
 * Load settings from storage
 */
function loadSettings() {
  chrome.storage.sync.get(['autoAnalyze', 'highlightScams'], (items) => {
    const autoAnalyze = items.autoAnalyze !== false; // default true
    const highlight = items.highlightScams !== false; // default true
    
    setToggleState('toggle-auto-analyze', autoAnalyze);
    setToggleState('toggle-highlight', highlight);
  });
}

function loadApiSettings(onReady) {
  chrome.storage.sync.get(['apiBase', 'apiKey'], (items) => {
    const baseInput = document.getElementById('api-base');
    const keyInput = document.getElementById('api-key');
    const storedBase = items.apiBase || '';
    const apiBase = storedBase.includes('web-production-b7ac.up.railway.app')
      ? 'http://127.0.0.1:8000'
      : (storedBase || 'http://127.0.0.1:8000');
    if (baseInput) baseInput.value = apiBase;
    if (keyInput) keyInput.value = items.apiKey || '';

    if (storedBase !== apiBase) chrome.storage.sync.set({ apiBase });
    
    if (!items.apiKey) {
      document.getElementById('api-warning').style.display = 'block';
    }
    if (onReady) onReady();
  });
}

function setupApiSettings() {
  const saveButton = document.getElementById('save-api-settings');
  if (!saveButton) return;

  saveButton.addEventListener('click', () => {
    const apiBase = (document.getElementById('api-base')?.value || '').trim();
    const apiKey = (document.getElementById('api-key')?.value || '').trim();
    const status = document.getElementById('api-save-status');

    if (!apiBase || !apiKey) {
      if (status) {
        status.style.display = 'block';
        status.className = 'alert alert-error';
        status.textContent = 'Both API base and API key are required';
      }
      return;
    }

    chrome.storage.sync.set({ apiBase, apiKey }, () => {
      document.getElementById('api-warning').style.display = 'none';
      if (status) {
        status.style.display = 'block';
        status.className = 'alert alert-success';
        status.textContent = 'Settings saved';
      }
      setTimeout(() => {
        if (status) status.style.display = 'none';
      }, 2000);
      loadFlaggedStats();
    });
  });
}

function setupConnectionTest() {
  const button = document.getElementById('test-api-settings');
  if (!button) return;
  button.addEventListener('click', () => {
    const status = document.getElementById('api-save-status');
    button.disabled = true;
    if (status) {
      status.style.display = 'block';
      status.className = 'alert';
      status.textContent = 'Testing connection...';
    }
    const apiBase = document.getElementById('api-base')?.value.trim();
    const apiKey = document.getElementById('api-key')?.value.trim();
    chrome.runtime.sendMessage({ action: 'testConnection', apiBase, apiKey }, (response) => {
      button.disabled = false;
      const error = chrome.runtime.lastError?.message || response?.error;
      if (!response?.success || error) {
        if (status) {
          status.className = 'alert alert-error';
          status.textContent = error || 'Connection test failed';
        }
        return;
      }
      if (status) {
        status.className = 'alert alert-success';
        status.textContent = `Connected to ${response.data.apiBase}`;
      }
    });
  });
}

/**
 * Setup toggle button event listeners
 */
function setupToggleButtons() {
  const autoAnalyzeToggle = document.getElementById('toggle-auto-analyze');
  const highlightToggle = document.getElementById('toggle-highlight');
  
  autoAnalyzeToggle.addEventListener('click', () => {
    const isActive = autoAnalyzeToggle.classList.toggle('active');
    chrome.storage.sync.set({ autoAnalyze: isActive });
  });
  
  highlightToggle.addEventListener('click', () => {
    const isActive = highlightToggle.classList.toggle('active');
    chrome.storage.sync.set({ highlightScams: isActive });
  });
}

/**
 * Helper: Set toggle button state
 */
function setToggleState(elementId, isActive) {
  const element = document.getElementById(elementId);
  if (isActive) {
    element.classList.add('active');
  } else {
    element.classList.remove('active');
  }
}

// Auto-refresh stats every 30 seconds
setInterval(loadFlaggedStats, 30000);
