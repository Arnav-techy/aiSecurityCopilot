# backend/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes.scan import router as scan_router
import uvicorn

app = FastAPI(
    title="AI Security Copilot API",
    description="AI-powered security analysis and vulnerability detection",
    version="1.0.0"
)

# Configure CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Your Next.js frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan_router)

@app.get("/")
async def root():
    return {
        "message": "AI Security Copilot API",
        "docs": "/docs",
        "endpoints": {
            "analyze": "/scan/analyze",
            "analyze-code": "/scan/analyze-code",
            "history": "/scan/history",
            "health": "/scan/health"
        }
    }

if __name__ == "__main__":
    print("🚀 Starting AI Security Copilot Backend...")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔗 Frontend: http://localhost:3000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
