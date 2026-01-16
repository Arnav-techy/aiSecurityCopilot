import os
import json
from typing import Dict, List, Optional, Tuple
from enum import Enum
from datetime import datetime
import logging
from google import genai
from dotenv import load_dotenv
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

class SecuritySeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFORMATIONAL"

class AttackVector(Enum):
    NETWORK = "NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"
    ADJACENT = "ADJACENT_NETWORK"

class SecurityIssue:
    def __init__(self, title: str, description: str, severity: SecuritySeverity):
        self.title = title
        self.description = description
        self.severity = severity
        self.timestamp = datetime.now()
        self.recommendations = []
        self.references = []
        self.cvss_score = 0.0
        self.attack_vectors = []
    
    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "recommendations": self.recommendations,
            "references": self.references,
            "cvss_score": self.cvss_score,
            "attack_vectors": [av.value for av in self.attack_vectors]
        }

class AISecurityCopilot:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment variables")
        
        self.client = genai.Client(api_key=api_key)
        self.analysis_history = []
        logger.info("AI Security Copilot initialized")
    
    def analyze_security_issue(self, issue: str, context: Optional[Dict] = None) -> Dict:
        """
        Comprehensive security issue analysis with multiple perspectives
        """
        try:
            # Build enhanced prompt with context
            prompt = self._build_analysis_prompt(issue, context)
            
            # Generate AI response
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            
            # Parse and structure the response
            analysis = self._parse_ai_response(response.text, issue)
            
            # Store in history
            self.analysis_history.append(analysis)
            
            logger.info(f"Analysis completed for issue: {issue[:50]}...")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing security issue: {str(e)}")
            return self._generate_fallback_analysis(issue)
    
    def _build_analysis_prompt(self, issue: str, context: Optional[Dict]) -> str:
        """Build comprehensive analysis prompt"""
        prompt_template = """
        You are an AI Security Copilot with expertise in:
        - Application Security (OWASP Top 10)
        - Cloud Security (AWS, Azure, GCP)
        - Network Security
        - Cryptography
        - Compliance (GDPR, HIPAA, PCI-DSS)
        - Threat Intelligence
        
        Analyze this security issue with extreme detail:
        
        ISSUE: {issue}
        
        {context_str}
        
        Provide analysis in this EXACT JSON format:
        {{
            "title": "Brief descriptive title",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
            "cvss_score": 0.0-10.0,
            "risk_explanation": "Detailed risk analysis",
            "attack_scenario": "How attackers could exploit this",
            "attack_vectors": ["NETWORK", "LOCAL", etc],
            "vulnerability_type": "SQLi, XSS, Misconfiguration, etc",
            "impact": "What could be compromised",
            "affected_components": ["API", "Database", "Network"],
            "secure_fix": "Step-by-step remediation",
            "immediate_actions": ["Action 1", "Action 2"],
            "long_term_recommendations": ["Rec 1", "Rec 2"],
            "references": [
                "CWE-123",
                "https://owasp.org/..."
            ],
            "compliance_implications": ["GDPR", "PCI-DSS"]
        }}
        
        Be specific about:
        1. Attack techniques (MITRE ATT&CK IDs if applicable)
        2. Real-world exploit examples
        3. Code snippets for fixes
        4. Monitoring recommendations
        5. False positive analysis
        """
        
        context_str = ""
        if context:
            context_str = f"CONTEXT:\n- Application Type: {context.get('app_type', 'Unknown')}\n"
            context_str += f"- Tech Stack: {context.get('tech_stack', 'Unknown')}\n"
            context_str += f"- Environment: {context.get('environment', 'Production')}\n"
        
        return prompt_template.format(issue=issue, context_str=context_str)
    
    def _parse_ai_response(self, response_text: str, original_issue: str) -> Dict:
        """Parse AI response and extract structured data"""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
            else:
                # Fallback parsing
                analysis = self._parse_unstructured_response(response_text)
            
            # Create SecurityIssue object
            severity = SecuritySeverity(analysis.get("severity", "MEDIUM"))
            security_issue = SecurityIssue(
                title=analysis.get("title", "Security Issue"),
                description=original_issue,
                severity=severity
            )
            
            # Populate additional fields
            security_issue.cvss_score = float(analysis.get("cvss_score", 5.0))
            security_issue.recommendations = analysis.get("long_term_recommendations", [])
            security_issue.references = analysis.get("references", [])
            
            # Parse attack vectors
            for av in analysis.get("attack_vectors", []):
                try:
                    security_issue.attack_vectors.append(AttackVector(av))
                except ValueError:
                    continue
            
            # Combine structured and unstructured data
            result = security_issue.to_dict()
            result.update({
                "ai_analysis": {
                    "risk_explanation": analysis.get("risk_explanation", ""),
                    "attack_scenario": analysis.get("attack_scenario", ""),
                    "secure_fix": analysis.get("secure_fix", ""),
                    "immediate_actions": analysis.get("immediate_actions", []),
                    "compliance_implications": analysis.get("compliance_implications", [])
                },
                "detection_rules": self._generate_detection_rules(analysis),
                "testing_guidelines": self._generate_testing_guidelines(analysis),
                "raw_response": response_text
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing AI response: {str(e)}")
            return self._generate_fallback_analysis(original_issue)
    
    def _generate_detection_rules(self, analysis: Dict) -> List[Dict]:
        """Generate detection rules based on analysis"""
        vuln_type = analysis.get("vulnerability_type", "").lower()
        rules = []
        
        # Example rule generation based on vulnerability type
        if "sqli" in vuln_type:
            rules.append({
                "type": "WAF_RULE",
                "description": "SQL Injection Detection",
                "rule": "detectSQLi"
            })
        
        return rules
    
    def _generate_testing_guidelines(self, analysis: Dict) -> List[str]:
        """Generate testing guidelines"""
        guidelines = []
        severity = analysis.get("severity", "MEDIUM")
        
        if severity in ["CRITICAL", "HIGH"]:
            guidelines.append("Perform immediate penetration testing")
            guidelines.append("Conduct code review of affected components")
        
        return guidelines
    
    def analyze_code_snippet(self, code: str, language: str = "python") -> Dict:
        """Analyze code snippets for security vulnerabilities"""
        prompt = f"""
        Analyze this {language} code for security vulnerabilities:
        
        ```{language}
        {code}
        ```
        
        Focus on:
        1. Injection vulnerabilities
        2. Authentication/Authorization issues
        3. Data exposure
        4. Cryptography weaknesses
        5. Input validation
        
        Provide line-by-line analysis.
        """
        
        response = self.client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        
        return {
            "code_analysis": response.text,
            "language": language,
            "timestamp": datetime.now().isoformat()
        }
    
    def threat_modeling_assistant(self, system_description: str) -> Dict:
        """Assist with threat modeling"""
        prompt = f"""
        Perform threat modeling for this system:
        
        {system_description}
        
        Identify:
        1. Data flows
        2. Trust boundaries
        3. Potential threats
        4. Security controls needed
        5. Risk assessment
        """
        
        response = self.client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        
        return {
            "threat_model": response.text,
            "system": system_description,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_analysis_history(self, limit: int = 10) -> List[Dict]:
        """Get recent analysis history"""
        return self.analysis_history[-limit:]
    
    def generate_security_report(self, issues: List[str]) -> str:
        """Generate comprehensive security report"""
        analyses = [self.analyze_security_issue(issue) for issue in issues]
        
        report = "# Security Assessment Report\n\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        critical_count = sum(1 for a in analyses if a.get('severity') == 'CRITICAL')
        high_count = sum(1 for a in analyses if a.get('severity') == 'HIGH')
        
        report += f"## Executive Summary\n"
        report += f"- Critical Issues: {critical_count}\n"
        report += f"- High Issues: {high_count}\n"
        report += f"- Total Issues Analyzed: {len(issues)}\n\n"
        
        for i, analysis in enumerate(analyses, 1):
            report += f"## Issue {i}: {analysis.get('title')}\n"
            report += f"**Severity**: {analysis.get('severity')}\n"
            report += f"**CVSS Score**: {analysis.get('cvss_score')}\n\n"
            report += f"### Description\n{analysis.get('description')}\n\n"
            report += f"### Risk Explanation\n{analysis['ai_analysis']['risk_explanation']}\n\n"
            report += f"### Remediation\n{analysis['ai_analysis']['secure_fix']}\n\n"
        
        return report
    
    def _parse_unstructured_response(self, response_text: str) -> Dict:
        """Parse unstructured text response"""
        # Simple parsing logic for non-JSON responses
        return {
            "title": "Security Analysis",
            "severity": "MEDIUM",
            "cvss_score": 5.0,
            "risk_explanation": response_text,
            "attack_scenario": "Extracted from analysis",
            "secure_fix": "Review the detailed analysis above",
            "immediate_actions": ["Isolate affected systems", "Review logs"],
            "references": []
        }
    
    def _generate_fallback_analysis(self, issue: str) -> Dict:
        """Generate fallback analysis when AI fails"""
        return {
            "title": "Security Issue Analysis",
            "severity": "MEDIUM",
            "description": issue,
            "ai_analysis": {
                "risk_explanation": "Unable to generate detailed analysis. Please review manually.",
                "attack_scenario": "Manual investigation required",
                "secure_fix": "1. Review code/configurations\n2. Apply security patches\n3. Monitor for anomalies",
                "immediate_actions": ["Manual review needed"],
                "compliance_implications": []
            },
            "timestamp": datetime.now().isoformat()
        }


# Example usage
if __name__ == "__main__":
    # Initialize the copilot
    copilot = AISecurityCopilot()
    
    # Example 1: Analyze a security issue
    issue = "User input is directly concatenated into SQL query without sanitization"
    context = {
        "app_type": "Web Application",
        "tech_stack": "Python, PostgreSQL, Flask",
        "environment": "Production"
    }
    
    analysis = copilot.analyze_security_issue(issue, context)
    print(json.dumps(analysis, indent=2))
    
    # Example 2: Analyze code snippet
    code = """
    import sqlite3
    def get_user(username):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        return cursor.fetchone()
    """
    
    code_analysis = copilot.analyze_code_snippet(code, "python")
    print("\nCode Analysis:", code_analysis)
    
    # Example 3: Generate report
    issues = [
        "SQL injection vulnerability in login endpoint",
        "Hardcoded API keys in source code",
        "Missing CORS headers on API"
    ]
    
    report = copilot.generate_security_report(issues)
    print("\nSecurity Report generated")