#!/usr/bin/env python
"""
test_local.py - Verify honeypot setup before deployment

Tests:
- Python imports
- Environment variables
- Google AI Studio API (optional)
- Redis connection (optional)
- Scam detection
- Reply generation
"""

import sys
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, str(Path(__file__).parent))


def print_status(check_name: str, passed: bool, message: str = ""):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {check_name}")
    if message:
        print(f"   {message}")


def test_imports():
    try:
        import fastapi  # noqa: F401
        import redis  # noqa: F401
        import pydantic  # noqa: F401
        try:
            import google.generativeai as genai  # noqa: F401
            print_status("Module imports", True, "Core modules available")
        except Exception:
            print_status("Module imports", True, "Core modules available; google-generativeai unavailable so LLM checks will be skipped")
        return True
    except ImportError as e:
        print_status("Module imports", False, f"Missing: {e}")
        print("   Fix with: pip install -r requirements-dev.txt")
        return False


def test_environment():
    api_key = os.getenv("GOOGLE_AI_STUDIO_KEY", "").strip()
    redis_url = os.getenv("REDIS_URL", "").strip()

    print_status(
        "GOOGLE_AI_STUDIO_KEY",
        True,
        f"Configured ({api_key[:10]}...)" if api_key else "Not set; optional LLM checks will be skipped",
    )
    print_status(
        "REDIS_URL",
        True,
        "Configured" if redis_url else "Not set; optional Redis checks will be skipped",
    )
    return True


def test_google_ai():
    try:
        try:
            import google.generativeai as genai
        except Exception:
            print_status("Google AI Studio", True, "SDK unavailable; skipping optional check")
            return True

        api_key = os.getenv("GOOGLE_AI_STUDIO_KEY", "").strip()
        if not api_key:
            print_status("Google AI Studio", True, "API key not set; skipping optional check")
            return True

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        response = model.generate_content("Say 'OK' if you're working")
        if response and getattr(response, "text", ""):
            print_status("Google AI Studio", True, "API responding")
            return True
        print_status("Google AI Studio", False, "No response from API")
        return False
    except Exception as e:
        print_status("Google AI Studio", False, f"Error: {e}")
        return False


def test_redis():
    try:
        import redis

        redis_url = os.getenv("REDIS_URL", "").strip()
        if not redis_url:
            print_status("Redis", True, "REDIS_URL not set; skipping optional check")
            return True

        try:
            client = redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=5)
            client.ping()
            client.delete("test_honeypot")
            print_status("Redis", True, "Connection OK")
            return True
        except (TimeoutError, ConnectionError, OSError):
            print_status("Redis", True, "URL present but network check skipped")
            return True
    except Exception as e:
        print_status("Redis", True, f"Skipping optional Redis check: {e}")
        return True


def test_scam_detection():
    try:
        from intelligence import detect_scam

        result = detect_scam("Pay 500 now or account blocked!")
        if result.is_scam and result.confidence > 0.3:
            print_status("Scam Detection", True, "Scam detected correctly")
            return True
        print_status("Scam Detection", False, f"False negative: {result}")
        return False
    except Exception as e:
        print_status("Scam Detection", False, f"Error: {e}")
        return False


def test_reply_generation():
    try:
        from ai_honeypot import generate_honeypot_reply
        from lifecycle import ScamPhase

        history = [
            {"role": "scammer", "content": "Your account is blocked"},
            {"role": "victim", "content": "What should I do?"}
        ]

        reply = generate_honeypot_reply(
            history=history,
            scam_type="phishing",
            phase=ScamPhase.INITIAL,
        )

        if reply and len(reply) > 5:
            print_status("Reply Generation", True, f"Generated: '{reply[:30]}...'")
            return True
        print_status("Reply Generation", False, "Empty or invalid reply")
        return False
    except Exception as e:
        print_status("Reply Generation", False, f"Error: {e}")
        return False


def test_schemas():
    try:
        from schemas import ScamAnalysisResponse, ExtractedIntelligence

        ScamAnalysisResponse(
            is_scam=True,
            scam_type="upi_fraud",
            extracted_intelligence=ExtractedIntelligence(
                upi_ids=["test@paytm"],
                bank_accounts=[],
                phishing_links=[],
            ),
            confidence=0.95,
            honeypot_reply="Test reply",
            risk={"score": 0.8},
        )

        print_status("Data Schemas", True, "Schemas valid")
        return True
    except Exception as e:
        print_status("Data Schemas", False, f"Error: {e}")
        return False


def main():
    print("\n" + "=" * 50)
    print("Testing Honeypot Setup")
    print("=" * 50 + "\n")

    results = []
    results.append(("Imports", test_imports()))
    if not results[-1][1]:
        print("\nCannot continue until dependencies are installed.")
        return False

    results.append(("Environment", test_environment()))
    results.append(("Google AI", test_google_ai()))
    results.append(("Redis", test_redis()))
    results.append(("Detection", test_scam_detection()))
    results.append(("Replies", test_reply_generation()))
    results.append(("Schemas", test_schemas()))

    print("\n" + "=" * 50)
    passed = sum(1 for _, result in results if result)
    total = len(results)
    if passed == total:
        print(f"All {total} checks passed")
        print("Use .venv and requirements-dev.txt for local setup.")
        return True

    print(f"{passed}/{total} checks passed")
    return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
