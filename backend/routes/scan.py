# backend/routes/scan.py
from fastapi import APIRouter, HTTPException
from services.gemini import AISecurityCopilot
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/scan", tags=["security"])

class ScanRequest(BaseModel):
    issue: str
    app_type: Optional[str] = "Web Application"
    tech_stack: Optional[str] = "Unknown"
    environment: Optional[str] = "Production"

class CodeScanRequest(BaseModel):
    code: str
    language: str = "python"

# Initialize the copilot once
copilot = AISecurityCopilot()

@router.post("/analyze")
async def analyze_issue(request: ScanRequest):
    """Analyze a security issue"""
    try:
        context = {
            "app_type": request.app_type,
            "tech_stack": request.tech_stack,
            "environment": request.environment
        }
        
        result = copilot.analyze_security_issue(request.issue, context)
        return {
            "success": True,
            "data": result,
            "timestamp": result.get("timestamp")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze-code")
async def analyze_code(request: CodeScanRequest):
    """Analyze code for vulnerabilities"""
    try:
        result = copilot.analyze_code_snippet(request.code, request.language)
        return {
            "success": True,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/history")
async def get_history(limit: int = 10):
    """Get analysis history"""
    try:
        history = copilot.get_analysis_history(limit)
        return {
            "success": True,
            "count": len(history),
            "data": history
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "AI Security Copilot",
        "version": "1.0.0"
    }