"""Test long conversation blocking"""
import os
import requests
import time
import json

url = "http://127.0.0.1:8000/honeypot"
API_KEY = (os.getenv("API_KEY") or "").strip()
if not API_KEY:
    raise RuntimeError("API_KEY environment variable is required.")

headers = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

conversation_id = "long-conv-stress-test"

print("🧪 Testing Long Conversation Blocking (10+ turns)...\n")

for i in range(1, 12):
    payload = {
        "conversation_id": conversation_id,
        "message": f"Pay to scammer@paytm message {i}. Urgent now!"
    }
    
    print(f"Turn {i}...", end=" ")
    try:
        response = requests.post(url, json=payload, headers=headers)
        data = response.json()
        
        if data.get("blocked"):
            print(f"🛑 BLOCKED!")
            print(f"   Blocked Message: {data.get('blocked_message')}")
            break
        else:
            reply = data.get("honeypot_reply", "")
            print(f"✅ Reply: {reply[:60]}...")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        break
    
    time.sleep(1)

print("\n✅ Test completed!")
