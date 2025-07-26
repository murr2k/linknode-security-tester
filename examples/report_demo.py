#!/usr/bin/env python3
"""
Demo script showing the enhanced report generation capabilities.
"""

import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.report_generator import ReportGenerator

# Sample project data
project_data = {
    "id": "demo-project-123",
    "name": "ACME Corp Security Audit",
    "client": "ACME Corporation",
    "url": "https://example.acme.com",
    "description": "Quarterly security assessment"
}

# Sample scan metadata
scan_metadata = {
    "id": "scan-456",
    "type": "full",
    "date": "2024-01-26T10:30:00",
    "duration": 3672.5,
    "risk_score": 67.5,
    "vulnerabilities": {
        "High": 3,
        "Medium": 12,
        "Low": 25,
        "Informational": 8
    }
}

# Sample scan results (ZAP format)
scan_results = {
    "alerts": [
        {
            "name": "SQL Injection",
            "risk": "High",
            "confidence": "High",
            "desc": "SQL injection vulnerabilities allow attackers to execute arbitrary SQL commands.",
            "solution": "Use parameterized queries and input validation",
            "reference": "https://owasp.org/www-project-top-ten/",
            "cweid": 89,
            "wascid": 19,
            "instances": [
                {"uri": "https://example.acme.com/api/users?id=1"},
                {"uri": "https://example.acme.com/api/products?search=test"}
            ]
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "risk": "High",
            "confidence": "Medium",
            "desc": "XSS vulnerabilities allow attackers to inject malicious scripts into web pages.",
            "solution": "Implement proper output encoding and Content Security Policy",
            "reference": "https://owasp.org/www-community/attacks/xss/",
            "cweid": 79,
            "wascid": 8,
            "instances": [
                {"uri": "https://example.acme.com/comments"},
                {"uri": "https://example.acme.com/profile"}
            ]
        },
        {
            "name": "Missing Security Headers",
            "risk": "Medium",
            "confidence": "High",
            "desc": "Important security headers are missing from HTTP responses.",
            "solution": "Add security headers like X-Frame-Options, X-Content-Type-Options, etc.",
            "reference": "https://securityheaders.com",
            "cweid": 16,
            "wascid": 15,
            "instances": [
                {"uri": "https://example.acme.com/"},
                {"uri": "https://example.acme.com/login"}
            ]
        },
        {
            "name": "Insecure Cookie Configuration",
            "risk": "Medium",
            "confidence": "High",
            "desc": "Cookies are not properly secured with HttpOnly and Secure flags.",
            "solution": "Set HttpOnly and Secure flags on all sensitive cookies",
            "reference": "https://owasp.org/www-community/controls/SecureCookieAttribute",
            "cweid": 614,
            "wascid": 13,
            "instances": [
                {"uri": "https://example.acme.com/login"},
                {"uri": "https://example.acme.com/api/auth"}
            ]
        }
    ],
    "spider": {
        "urls": ["https://example.acme.com/" + path for path in [
            "", "about", "contact", "login", "register", "api/users",
            "api/products", "dashboard", "profile", "settings"
        ]]
    }
}

def demo_report_generation():
    """Demonstrate report generation in different formats."""
    
    # Create output directory
    output_dir = Path("examples/sample_reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize report generator
    generator = ReportGenerator(project_data, scan_metadata, scan_results)
    
    print("Generating sample reports...")
    
    # Generate JSON report
    json_path = output_dir / "security_report.json"
    generator.generate("json", json_path)
    print(f"✓ JSON report: {json_path}")
    
    # Generate HTML report
    html_path = output_dir / "security_report.html"
    generator.generate("html", html_path)
    print(f"✓ HTML report: {html_path}")
    
    # Generate PDF report (if WeasyPrint is available)
    pdf_path = output_dir / "security_report.pdf"
    result_path = generator.generate("pdf", pdf_path)
    if result_path.suffix == '.pdf':
        print(f"✓ PDF report: {pdf_path}")
    else:
        print(f"✓ PDF generation not available, saved as HTML: {result_path}")
    
    print(f"\nReports generated in: {output_dir.absolute()}")
    print(f"Open HTML report: file://{html_path.absolute()}")

if __name__ == "__main__":
    demo_report_generation()