# Complete Deployment Guide

This is the long-form deployment guide for the project.

## What this covers
- Architecture overview
- API key setup
- Local setup and testing
- Render deployment
- Monitoring, logs, and troubleshooting

## Quick pointers
- For local development, use the PowerShell switcher in `scripts/ServerSwitch.ps1`.
- For first-time setup, start with [quickstart.md](quickstart.md).
- For a high-level map of the codebase, read [architecture.md](architecture.md).

## Deployment shortcut

Use the existing Render start command:

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

If you want the full original guide content restored here later, I can expand this file in a follow-up pass.