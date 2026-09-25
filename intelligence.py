# intelligence.py - UPDATED WITH GOOGLE AI STUDIO
import json
import os
import re
import importlib
from typing import NamedTuple
from schemas import ExtractedIntelligence

# Lazy/optional import of Google AI Studio to allow running without the SDK
API_KEY = os.getenv("GOOGLE_AI_STUDIO_KEY", "")
genai = None
model = None
if API_KEY:
    try:
        genai = importlib.import_module("google.generativeai")
        genai.configure(api_key=API_KEY)
        try:
            model = genai.GenerativeModel('models/gemma-3-4b-it')
        except Exception as e:
            print(f"⚠️ WARNING: Model initialization failed: {e}. Will use fallback.")
            model = None
    except Exception:
        genai = None
        model = None
        print("⚠️ WARNING: google.generativeai not available. Using fallback detection.")


class DetectionResult(NamedTuple):
    is_scam: bool
    confidence: float


def detect_scam(message: str) -> DetectionResult:
    """
    LLM-powered scam detection using Google AI Studio (Gemini)
    Falls back to keyword matching if API is unavailable.
    """
    
    # Try LLM detection first
    if model and API_KEY:
        try:
            # Escape message for JSON
            escaped_message = message.replace('"', '\\"')
            
            prompt = f"""Is this a scam? Respond with JSON. Answer yes=true or no=false.

Message: {escaped_message}

{{"is_scam": true, "confidence": 0.95}}"""

            response = model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=50
                )
            )
            
            if not response.text or not response.text.strip():
                raise ValueError("Empty response from LLM")
            
            # Parse JSON response
            result_text = response.text.strip()
            
            # Find JSON object in response
            start_idx = result_text.find('{')
            end_idx = result_text.rfind('}') + 1
            if start_idx < 0:
                raise ValueError(f"No JSON object found in response: {result_text}")
            
            result_text = result_text[start_idx:end_idx]
            result = json.loads(result_text)
            
            return DetectionResult(
                is_scam=bool(result.get("is_scam", False)),
                confidence=min(1.0, max(0.0, float(result.get("confidence", 0.5))))
            )
            
        except Exception as e:
            print(f"WARNING: LLM detection failed: {e}. Using fallback.")
    
    # Fallback: Keyword-based detection
    scam_keywords = [
        "pay", "upi", "urgent", "verify", "account", "blocked", 
        "kyc", "bank", "http", "www", "link", "₹", "rupees",
        "transfer", "debit", "credit", "expire", "suspend"
    ]
    
    message_lower = message.lower()
    score = sum(1 for word in scam_keywords if word in message_lower)
    
    # Improved confidence calculation: if 2+ keywords match, it's likely a scam
    if score >= 2:
        confidence = min((score / 5.0), 1.0)  # Scale by 5 instead of all keywords
    else:
        confidence = score / len(scam_keywords)
    
    return DetectionResult(
        is_scam=score >= 2,  # Require at least 2 keywords
        confidence=round(confidence, 2)
    )


def extract_intelligence(message: str) -> ExtractedIntelligence:
    """
    Extract fraud indicators from message using regex patterns.
    """
    intelligence = ExtractedIntelligence()
    
    # Extract UPI IDs (e.g., user@paytm, merchant@ybl)
    upi_pattern = r'\b[\w.-]+@(?:paytm|ybl|oksbi|okaxis|okicici|upi|axl|ibl|sbi|hdfc|icici|pnb)\b'
    upis = re.findall(upi_pattern, message, re.IGNORECASE)
    intelligence.upi_ids = list(set(upis))  # Remove duplicates
    
    # Extract bank account numbers (basic pattern)
    account_pattern = r'\b\d{9,18}\b'
    accounts = re.findall(account_pattern, message)
    intelligence.bank_accounts = list(set(accounts))
    
    # Extract links (multiple patterns for better coverage)
    links = []
    
    # Pattern 1: Full URLs with http/https
    links.extend(re.findall(r"https?://[^\s)\]}>\"']+", message))
    
    # Pattern 2: www. domains
    links.extend(re.findall(r"\bwww\.[^\s)\]}>\"']+", message, flags=re.IGNORECASE))
    
    # Pattern 3: Domain-like patterns
    links.extend(
        re.findall(
            r"\b[a-zA-Z0-9.-]+\.(?:com|in|net|org|io|co|xyz|biz|info|online|site)(?:/[^\s)\]}>\"']*)?",
            message,
            flags=re.IGNORECASE,
        )
    )
    
    # Clean and deduplicate links
    seen = set()
    for link in links:
        # Skip if it looks like an email (has @ but not UPI provider)
        if "@" in link and not any(p in link.lower() for p in ['@paytm', '@ybl', '@oksbi', '@upi']):
            continue
        
        link_lower = link.lower()
        if link_lower not in seen:
            seen.add(link_lower)
            intelligence.phishing_links.append(link)
    
    return intelligence
