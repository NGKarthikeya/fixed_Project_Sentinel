# 🚀 Quick Start Guide - Deploy in 5 Minutes

## Prerequisites
- Python 3.8+ installed
- GitHub account
- Render account (free)

## Step 1: Get API Keys (2 minutes)

### Google AI Studio Key (FREE)
1. Go to https://aistudio.google.com/apikey
2. Sign in with Google
3. Click "Create API Key"
4. Copy your Google AI Studio API key

### Upstash Redis URL (FREE)
1. Go to https://console.upstash.com/
2. Sign up with GitHub
3. Click "Create Database" 
4. Select Regional, choose closest region
5. Copy Redis URL from dashboard

## Step 2: Test Locally (Optional)

```bash
# Create .env file
cp .env.example .env

# Edit .env and paste your keys:
# GOOGLE_AI_STUDIO_KEY=YOUR_GOOGLE_AI_STUDIO_KEY_HERE
# REDIS_URL=redis://...

# Install dependencies
pip install -r requirements.txt

# Run test
python test_local.py

# Should see: ✅ All tests passed!
```

## Step 3: Deploy to Render (3 minutes)

1. Push your code to GitHub
2. Go to https://render.com and login
3. Click "New +" → "Web Service"
4. Connect your GitHub repo
5. Fill in:
   - **Name**: honeypot-app
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`

6. Scroll to "Environment" and add variables:
   ```
   GOOGLE_AI_STUDIO_KEY=YOUR_GOOGLE_AI_STUDIO_KEY_HERE
   REDIS_URL=redis://...
   API_KEY=YOUR_API_KEY_HERE
   ```

7. Click "Deploy"

## Step 4: Test Production (1 minute)

Wait 2-3 minutes for deployment, then:

```bash
curl -X POST https://YOUR-APP.onrender.com/honeypot \
   -H "x-api-key: YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"conversation_id": "test-001", "message": "Your account is blocked"}'
```

You should get a response with a contextual reply!

## ✅ Success Checklist
- [ ] API keys obtained
- [ ] Code pushed to GitHub
- [ ] Deployed to Render
- [ ] Environment variables added
- [ ] Test endpoint responds
- [ ] Replies sound natural (not robotic)

## 🆘 Troubleshooting

**"Module not found"**
- Check Build Command in Render

**"API key error"**
- Verify GOOGLE_AI_STUDIO_KEY is set in Render environment

**"Connection refused"**
- Check REDIS_URL format: `redis://default:password@host:port`

**Still stuck?**
- See [deployment_guide.md](deployment_guide.md) for detailed help

---
**Done!** Your honeypot is live and free! 🎉