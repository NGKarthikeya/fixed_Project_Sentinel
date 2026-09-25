# 🛡️ Scam Shield - Chrome Extension

AI-powered scam detection for Gmail and web emails. Analyzes emails with Gemini LLM to detect phishing, fraud, and scams in real-time.

## 📋 Overview

Scam Shield integrates with your Gmail account to:
- ✅ **Analyze emails** in real-time for scam patterns
- ✅ **Detect UPI fraud** and payment requests
- ✅ **Track phishing links** and fake domains
- ✅ **Flag suspicious senders** and identity spoofing
- ✅ **Block repeat offenders** from the flagged database
- ✅ **Highlight dangerous content** like UPI IDs and malicious links

## 🚀 Installation

### Step 1: Get the Extension Files
The Chrome extension files are in: `chrome_extension/`
```
chrome_extension/
├── manifest.json          # Extension configuration
├── background.js          # API communication
├── content.js            # Gmail page analysis
├── content.css           # Styling
├── popup.html            # Extension popup UI
└── popup.js              # Popup logic
```

### Step 2: Load Extension in Chrome
1. Open Chrome and go to `chrome://extensions`
2. Enable **"Developer mode"** (top right toggle)
3. Click **"Load unpacked"**
4. Select the `chrome_extension` folder
5. ✅ Extension is now active!

### Step 3: Verify Installation
- You should see **🛡️ Scam Shield** icon in Chrome toolbar
- Click it to see the popup with stats
- Go to Gmail and open an email - it should analyze it automatically

## 🎯 How It Works

### Real-Time Email Analysis
1. **Open an email in Gmail**
2. **Scam Shield automatically extracts:**
   - Sender name & email
   - Subject line
   - Email body text
   - All links in the email

3. **Backend analyzes using Gemini LLM:**
   - Scam detection (confidence 0-100%)
   - UPI ID extraction
   - Phishing link detection
   - Bank account detection
   - Risk scoring (0-100)

4. **Results displayed as a banner:**
   - 🟢 Safe / 🔴 Scam Alert
   - Risk score and confidence
   - Detected UPI IDs, links, accounts
   - Reasons for flagging

### Flagged Intelligence Database
- **First time scam is seen:** Details added to flagged list
- **Next time same UPI/link/account appears:** ⚠️ **INSTANT BLOCK**
- Blocks across all conversations
- Persists in Redis database

## 🎨 UI Features

### Extension Popup
Shows:
- 📊 **Flagged Stats:**
  - Total UPI IDs flagged
  - Bank accounts flagged
  - Phishing links flagged
  
- ⚙️ **Settings:**
  - Auto-analyze emails (toggle)
  - Highlight suspicious content (toggle)

### Email Analysis Banner
Appears at top of Gmail email with:
- ✅/⚠️ Scam verdict
- 📈 Confidence percentage
- 🎯 Risk score (0-100)
- 🚨 Found UPI IDs
- 🔗 Suspicious links
- 📝 Detection reasons

### Content Highlighting
- UPI IDs: **Red background, bold text**
- Phishing links: **Red, strikethrough**
- Bank accounts: **Highlighted in email**

## 🔧 Configuration

### Default Settings
```javascript
{
  "autoAnalyze": true,           // Analyze emails automatically
  "highlightScams": true,        // Highlight suspicious content
  "maxEmailLength": 5000,        // Max characters to analyze
  "debounceMs": 1000             // Debounce analysis by 1 second
}
```

### Backend Configuration
- **API Base:** `http://127.0.0.1:8000` for local development
- **API Key:** Set your own key in extension settings
- **Endpoints:**
  - `POST /analyze-email` - Analyze single email
  - `GET /admin/flagged-intelligence` - Get flagged stats

### Local Troubleshooting

If scanning reports `404 Analysis endpoint not found`, verify that the configured backend contains the `/analyze-email` endpoint. For local development, set **API Base** in the extension settings to `http://127.0.0.1:8000`.

When using the local URL, the extension API key must exactly match the `API_KEY` configured for the local server. A `401` or `403` response means the key and backend do not match.

## 📱 API Integration

### Analyze Email Endpoint
```bash
POST http://127.0.0.1:8000/analyze-email

Headers:
  Content-Type: application/json
  x-api-key: YOUR_API_KEY_HERE

Body:
{
  "from_email": "sender@example.com",
  "from_name": "John Doe",
  "subject": "Urgent: Verify your account",
  "message_text": "Your account has been suspended...",
  "links": ["http://fake-bank.com", "http://verify.com"]
}

Response:
{
  "is_scam": true,
  "confidence": 0.95,
  "risk": {
    "risk_score": 85,
    "risk_level": "high"
  },
  "scam_type": "payment_fraud",
  "reasons": [
    "Urgency language detected",
    "Payment/account-verification intent detected",
    "Suspicious link/domain detected"
  ],
  "extracted_intelligence": {
    "upi_ids": ["criminal@paytm"],
    "bank_accounts": ["123456789"],
    "phishing_links": ["http://fake-bank.com"]
  }
}
```

### Flagged Intelligence Stats Endpoint
```bash
GET http://127.0.0.1:8000/admin/flagged-intelligence

Headers:
  x-api-key: YOUR_API_KEY_HERE

Response:
{
  "flagged_upi_ids_count": 15,
  "flagged_bank_accounts_count": 8,
  "flagged_phishing_links_count": 42,
  "total_flagged": 65
}
```

## 🧪 Testing the Extension

### Test 1: Detect UPI Fraud
1. Go to Gmail
2. Compose an email with: "Send Rs 5000 to fraud@paytm immediately"
3. Fill from email & click analyze
4. Should show: 🔴 Scam Alert, confidence ~95%

### Test 2: Detect Phishing
1. Email with: "Click http://verify-bank.com for identity verification"
2. Should extract: phishing link + detect scam

### Test 3: Instant Block (Flagged UPI)
1. After analyzing first email with fraudulent UPI
2. Send new email with same UPI
3. Should show: 🛑 BLOCKED - UPI ID already flagged

### Test 4: Safe Email
1. Normal email: "Let's meet for lunch tomorrow"
2. Should show: ✅ Looks Safe

## 🐛 Troubleshooting

### Extension not analyzing emails
✅ Check:
- Extension is enabled (chrome://extensions)
- Gmail page is fully loaded
- Check browser console (F12) for errors
- Try clicking on an email to trigger analysis

### "API error" shown
✅ Check:
- Internet connection is working
- Backend server is online
- API key is set in extension popup settings
- Rate limits aren't exceeded

### Popup shows no stats
✅ Check:
- Click refresh in popup
- Redis database is accessible
- API key has permission to `/admin/flagged-intelligence`

## 📊 Performance

- **Analysis latency:** ~500-2000ms per email
- **Memory usage:** ~20-50MB
- **CPU usage:** Minimal (event-driven)
- **Database queries:** 1-2 Redis calls per email

## 🔒 Privacy & Security

- ✅ All analysis is done server-side (Gemini API)
- ✅ Email content is only sent to your backend
- ✅ API key is stored locally in extension
- ✅ No data is shared with 3rd parties
- ✅ Flagged data is persistent and shared

## 🚀 Future Enhancements

- [ ] Gmail label integration (auto-label scams)
- [ ] Archive/delete suspicious emails
- [ ] Whitelist trusted senders
- [ ] Custom scam patterns
- [ ] Email filtering rules
- [ ] SMS scam detection
- [ ] Multiple email providers (Outlook, Yahoo)
- [ ] Advanced training from user feedback

## 📝 File Structure

```
chrome_extension/
├── manifest.json          # Extension metadata
├── background.js          # Service worker for API calls
├── content.js            # Gmail page interaction
├── content.css           # Email banner styles
├── popup.html            # Popup UI HTML
├── popup.js              # Popup interaction script
└── README.md             # This file
```

## 🤝 Contributing

To improve the extension:
1. Update Chrome extension files
2. Reload extension (chrome://extensions)
3. Test in Gmail
4. Report issues or improvements

## 📄 License

MIT License - See LICENSE file for details

---

**Version:** 1.0.0  
**Last Updated:** February 21, 2026  
**Authors:** Ayush Singh, Codex AI  
**Backend:** Configurable local or hosted FastAPI deployment
**Repository:** https://github.com/ayushmansingh0502-hub/HONEYPOT_API
