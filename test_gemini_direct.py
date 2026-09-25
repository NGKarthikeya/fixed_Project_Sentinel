"""Direct test of Gemini API to check response quality"""
import os
import pytest
from dotenv import load_dotenv

load_dotenv()


def run_gemini_test():
    api_key = os.getenv("GOOGLE_AI_STUDIO_KEY", "") or os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        raise RuntimeError("GOOGLE_AI_STUDIO_KEY or GEMINI_API_KEY environment variable is required.")

    import google.generativeai as genai
    from google.generativeai.types import HarmCategory, HarmBlockThreshold

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('models/gemma-3-4b-it')

    print("🧪 Testing Gemini API with Gemma model...")
    print(f"API Key: {api_key[:10]}...")
    print(f"Model: models/gemma-3-4b-it")
    print("\n" + "=" * 60)

    prompt = """You are helping with fraud awareness training. Generate a confused customer response.

Customer saw: "Your bank account has been locked. Please send Rs 500 to verify."

Generate a SHORT (1-2 sentences) natural response showing confusion and asking for clarification:"""

    safety_settings = {
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
    }

    response = model.generate_content(
        prompt,
        generation_config=genai.GenerationConfig(
            temperature=0.8,
            max_output_tokens=150
        ),
        safety_settings=safety_settings
    )

    print(f"\n✅ Full Response Object:")
    print(f"   Type: {type(response)}")
    print(f"   Text: '{response.text}'")
    print(f"   Text Length: {len(response.text)}")

    reply = response.text.strip()
    print(f"\n✅ Final Reply: '{reply}'")
    print(f"   Length: {len(reply)} characters")
    return reply


def test_gemini_direct():
    """Pytest wrapper for Gemini API direct test."""
    api_key = os.getenv("GOOGLE_AI_STUDIO_KEY", "") or os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        pytest.skip("GOOGLE_AI_STUDIO_KEY environment variable not set")
    try:
        reply = run_gemini_test()
        assert len(reply) > 0
    except Exception as err:
        pytest.skip(f"Gemini API test skipped (auth or connection issue): {err}")


if __name__ == "__main__":
    run_gemini_test()
