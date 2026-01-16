import os
from google import genai
from dotenv import load_dotenv
import fastapi

load_dotenv()

print("✅ Testing backend setup...")
print(f"FastAPI version: {fastapi.__version__}")

# Test Gemini client
api_key = os.getenv("GEMINI_API_KEY")
if api_key:
    print(f"✅ Gemini API key found: {api_key[:10]}...")
    client = genai.Client(api_key=api_key)
    print("✅ Gemini client created successfully!")
else:
    print("⚠️  No Gemini API key found in .env file")
    print("   Add: GEMINI_API_KEY=your_key_here")

print("\n✅ Backend setup complete!")