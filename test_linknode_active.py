#!/usr/bin/env python3
"""
Active Security Test for linknode.com
Performs comprehensive vulnerability scanning including active probing
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.core.orchestrator import ScanOrchestrator
from src.integrations.zap_client import ZAPClient
from src.scanners.security import SecurityScanner

def run_active_security_test():
    """Run comprehensive security test with active scanning enabled"""
    
    print(f"Starting ACTIVE security test for linknode.com at {datetime.now()}")
    print("=" * 70)
    
    target_url = "https://linknode.com"
    
    # Initialize orchestrator
    orchestrator = ScanOrchestrator()
    
    try:
        orchestrator.initialize()
        print("✓ Scanner initialized successfully")
    except Exception as e:
        print(f"✗ Failed to initialize: {e}")
        print("\nMake sure OWASP ZAP is running:")
        print("  docker-compose up -d zap")
        return False
    
    # Configuration for active scanning with OWASP Top 10 testing
    scan_config = {
        'spider': True,
        'ajax_spider': True,  # Enable for thorough JavaScript testing
        'passive_scan': True,
        'active_scan': True,  # Enable active vulnerability probing
        'attack_strength': 'MEDIUM',  # Can be LOW, MEDIUM, HIGH, or INSANE
        'alert_threshold': 'LOW'  # Report even low-risk findings
    }
    
    print("\nTest Configuration:")
    print(f"- Target: {target_url}")
    print(f"- Spider: {'Enabled' if scan_config['spider'] else 'Disabled'}")
    print(f"- AJAX Spider: {'Enabled' if scan_config['ajax_spider'] else 'Disabled'}")
    print(f"- Passive Scan: {'Enabled' if scan_config['passive_scan'] else 'Disabled'}")
    print(f"- Active Scan: {'Enabled' if scan_config['active_scan'] else 'Disabled'}")
    print(f"- Attack Strength: {scan_config.get('attack_strength', 'MEDIUM')}")
    print(f"- Alert Threshold: {scan_config.get('alert_threshold', 'LOW')}")
    print("\n" + "=" * 70)
    
    try:
        # Run the security test
        security_scanner = orchestrator.security_scanner
        results = security_scanner.scan(target_url, scan_config)
        
        # Save detailed results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"linknode_active_scan_results_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nDetailed results saved to: {results_file}")
        
        # Display summary
        if 'summary' in results:
            summary = results['summary']
            print("\nSECURITY TEST SUMMARY")
            print("=" * 50)
            print(f"Total Issues: {summary.get('total_issues', 0)}")
            print(f"Risk Score: {summary.get('risk_score', 0)}/100")
            print(f"\nBreakdown:")
            print(f"  - Critical: {summary.get('critical_count', 0)}")
            print(f"  - High: {summary.get('high_count', 0)}")
            print(f"  - Medium: {summary.get('medium_count', 0)}")
            print(f"  - Low: {summary.get('low_count', 0)}")
            print(f"  - Informational: {summary.get('info_count', 0)}")
            
            # Check for OWASP Top 10 vulnerabilities
            if 'owasp_top10' in results:
                print("\nOWASP TOP 10 VULNERABILITIES CHECK:")
                print("-" * 50)
                for vuln in results['owasp_top10']:
                    status = "✗ FOUND" if vuln['found'] else "✓ Not Found"
                    print(f"{vuln['category']}: {status}")
                    if vuln['found'] and 'details' in vuln:
                        print(f"  Details: {vuln['details']}")
            
            # Display critical findings
            if 'alerts' in results:
                critical_alerts = [a for a in results['alerts'] if a.get('risk') in ['Critical', 'High']]
                if critical_alerts:
                    print("\nCRITICAL/HIGH RISK FINDINGS:")
                    print("-" * 50)
                    for alert in critical_alerts[:5]:  # Show top 5
                        print(f"\n• {alert.get('name', 'Unknown')} ({alert.get('risk', 'Unknown')} Risk)")
                        print(f"  URL: {alert.get('url', 'N/A')}")
                        print(f"  Description: {alert.get('description', 'N/A')[:200]}...")
                        if 'solution' in alert:
                            print(f"  Solution: {alert.get('solution', 'N/A')[:200]}...")
            
            # Test specific endpoints
            print("\nENDPOINT SECURITY ANALYSIS:")
            print("-" * 50)
            endpoints = ['/admin/', '/api/', '/private/']
            for endpoint in endpoints:
                endpoint_alerts = [a for a in results.get('alerts', []) 
                                 if endpoint in a.get('url', '')]
                if endpoint_alerts:
                    print(f"\n{endpoint}:")
                    for alert in endpoint_alerts[:3]:
                        print(f"  - {alert.get('name')} ({alert.get('risk')})")
        
        # Generate report
        report_file = f"LINKNODE_ACTIVE_SCAN_REPORT_{timestamp}.md"
        generate_detailed_report(results, report_file)
        print(f"\nDetailed report generated: {report_file}")
        
        # Cleanup
        orchestrator.cleanup()
        print("\n✓ Test completed successfully!")
        
    except Exception as e:
        print(f"\nError during security test: {str(e)}")
        orchestrator.cleanup()
        return False
    
    return True

def generate_detailed_report(results, filename):
    """Generate a detailed markdown report"""
    with open(filename, 'w') as f:
        f.write(f"# Linknode.com Active Security Scan Report\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Scan Type:** Active Security Scan with OWASP Top 10 Testing\n\n")
        
        # Executive Summary
        if 'summary' in results:
            summary = results['summary']
            f.write("## Executive Summary\n\n")
            f.write(f"- **Risk Score:** {summary.get('risk_score', 0)}/100\n")
            f.write(f"- **Total Issues:** {summary.get('total_issues', 0)}\n")
            f.write(f"- **Critical/High Risk:** {summary.get('critical_count', 0) + summary.get('high_count', 0)}\n\n")
        
        # OWASP Top 10 Status
        f.write("## OWASP Top 10 Compliance\n\n")
        if 'owasp_top10' in results:
            for vuln in results['owasp_top10']:
                status = "❌" if vuln['found'] else "✅"
                f.write(f"{status} **{vuln['category']}**\n")
                if vuln['found'] and 'details' in vuln:
                    f.write(f"   - {vuln['details']}\n")
        
        # Detailed Findings
        f.write("\n## Detailed Findings\n\n")
        if 'alerts' in results:
            # Group by risk level
            for risk in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
                risk_alerts = [a for a in results['alerts'] if a.get('risk') == risk]
                if risk_alerts:
                    f.write(f"### {risk} Risk ({len(risk_alerts)} issues)\n\n")
                    for alert in risk_alerts[:10]:  # Limit to 10 per category
                        f.write(f"#### {alert.get('name', 'Unknown')}\n")
                        f.write(f"- **URL:** {alert.get('url', 'N/A')}\n")
                        f.write(f"- **Description:** {alert.get('description', 'N/A')}\n")
                        f.write(f"- **Solution:** {alert.get('solution', 'N/A')}\n\n")
        
        # Recommendations
        f.write("## Recommendations\n\n")
        f.write("1. **Immediate Actions (24 hours):**\n")
        f.write("   - Address all Critical and High risk vulnerabilities\n")
        f.write("   - Implement security headers (CSP, X-Frame-Options, etc.)\n\n")
        f.write("2. **Short-term (1 week):**\n")
        f.write("   - Fix CORS misconfigurations\n")
        f.write("   - Secure administrative endpoints\n")
        f.write("   - Implement input validation\n\n")
        f.write("3. **Long-term:**\n")
        f.write("   - Establish regular security testing schedule\n")
        f.write("   - Implement security monitoring\n")
        f.write("   - Security awareness training\n")

if __name__ == "__main__":
    run_active_security_test()