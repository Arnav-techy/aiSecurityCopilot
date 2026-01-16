import os
from dotenv import load_dotenv

# Try loading .env from different locations
print("🔍 Testing .env file loading...")

# Method 1: Current directory
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
print(f"Method 1 (current dir): {api_key}")

# Method 2: Explicit path
from pathlib import Path
env_path = Path('.') / '.env'
print(f"Looking for .env at: {env_path.absolute()}")
print(f"File exists: {env_path.exists()}")

if env_path.exists():
    load_dotenv(dotenv_path=env_path)
    api_key = os.getenv("GEMINI_API_KEY")
    print(f"Method 2 (explicit path): {api_key[:10]}..." if api_key else "No key found")

# List all environment variables
print("\n📋 All env variables starting with GEMINI:")
for key, value in os.environ.items():
    if 'GEMINI' in key or 'API' in key:
        print(f"  {key}: {value[:10]}..." if value else f"  {key}: (empty)")