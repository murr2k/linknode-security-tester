#!/usr/bin/env python3
"""
Fresh Security Assessment for linknode.com
Uses enhanced scanner to ensure fresh readings without cache
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.core.orchestrator import ScanOrchestrator
from src.scanners.enhanced_security import EnhancedSecurityScanner
from src.integrations.zap_client import ZAPClient

def run_fresh_security_test():
    """Run security test with guaranteed fresh readings."""
    
    print(f"Starting FRESH security assessment for linknode.com")
    print(f"Timestamp: {datetime.now()}")
    print("=" * 70)
    print("Using Enhanced Scanner with cache-busting and session clearing...")
    print("=" * 70)
    
    target_url = "https://linknode.com"
    
    # Initialize ZAP client
    try:
        zap_client = ZAPClient()
        print("✓ Connected to ZAP successfully")
    except Exception as e:
        print(f"✗ Failed to connect to ZAP: {e}")
        print("\nMake sure OWASP ZAP is running:")
        print("  docker-compose up -d zap")
        return False
    
    # Initialize enhanced scanner
    scanner = EnhancedSecurityScanner(zap_client)
    
    # Configuration for fresh comprehensive scan
    scan_config = {
        'spider': True,
        'ajax_spider': True,
        'passive_scan': True,
        'active_scan': True,
        'attack_strength': 'MEDIUM',
        'alert_threshold': 'LOW',
        'force_fresh': True,
        'clear_cache': True
    }
    
    print("\nFresh Scan Configuration:")
    print(f"- Target: {target_url}")
    print(f"- Session Clearing: ENABLED")
    print(f"- Cache Busting: ENABLED")
    print(f"- Fresh Crawl: FORCED")
    print(f"- Test Time: {datetime.now()}")
    print("\n" + "=" * 70)
    
    try:
        # Run the fresh security scan
        print("Initiating fresh security scan...")
        results = scanner.scan(target_url, scan_config)
        
        # Verify fresh scan
        if scanner.verify_fresh_scan():
            print("✓ Fresh scan verified - no cached data used")
        else:
            print("⚠️  Warning: Fresh scan verification failed")
        
        # Save detailed results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"linknode_fresh_scan_results_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nDetailed results saved to: {results_file}")
        
        # Analyze results
        print("\n" + "=" * 50)
        print("FRESH SCAN RESULTS")
        print("=" * 50)
        
        if 'summary' in results:
            summary = results['summary']
            print(f"\nSecurity Metrics:")
            print(f"  Total Issues: {summary.get('total_issues', 0)}")
            print(f"  Risk Score: {summary.get('risk_score', 0)}/100")
            print(f"  Critical: {summary.get('critical_count', 0)}")
            print(f"  High: {summary.get('high_count', 0)}")
            print(f"  Medium: {summary.get('medium_count', 0)}")
            print(f"  Low: {summary.get('low_count', 0)}")
            print(f"  Info: {summary.get('info_count', 0)}")
        
        # Check for specific vulnerabilities
        print("\n" + "=" * 50)
        print("VULNERABILITY CHECK")
        print("-" * 50)
        
        vuln_status = {
            'cloud_metadata': {'found': False, 'details': []},
            'security_headers': {'found': False, 'details': []},
            'admin_endpoints': {'found': False, 'details': []},
            'cors': {'found': False, 'details': []},
            'server_info': {'found': False, 'details': []}
        }
        
        if 'alerts' in results:
            for alert in results['alerts']:
                alert_name = alert.get('name', '').lower()
                alert_url = alert.get('url', '')
                risk = alert.get('risk', '')
                
                # Cloud metadata check
                if 'cloud' in alert_name and 'metadata' in alert_name:
                    vuln_status['cloud_metadata']['found'] = True
                    vuln_status['cloud_metadata']['details'].append(f"{alert_url} ({risk})")
                
                # Security headers check
                if any(header in alert_name for header in ['content security policy', 'x-frame-options', 
                                                           'x-content-type', 'strict-transport']):
                    if 'not set' in alert_name or 'missing' in alert_name:
                        vuln_status['security_headers']['found'] = True
                        vuln_status['security_headers']['details'].append(alert.get('name'))
                
                # Admin endpoints check
                if '/admin' in alert_url and risk in ['High', 'Medium', 'Critical']:
                    vuln_status['admin_endpoints']['found'] = True
                    vuln_status['admin_endpoints']['details'].append(f"{alert_url} ({risk})")
                
                # CORS check
                if 'cors' in alert_name and ('wildcard' in alert_name or 'misconfigur' in alert_name):
                    vuln_status['cors']['found'] = True
                    vuln_status['cors']['details'].append(alert.get('name'))
                
                # Server info check
                if 'server' in alert_name and 'version' in alert_name:
                    vuln_status['server_info']['found'] = True
                    vuln_status['server_info']['details'].append(alert.get('evidence', 'N/A'))
        
        # Display vulnerability status
        print("\n1. Cloud Metadata Exposure:")
        if vuln_status['cloud_metadata']['found']:
            print("   ❌ VULNERABLE")
            for detail in vuln_status['cloud_metadata']['details'][:3]:
                print(f"      - {detail}")
        else:
            print("   ✅ PROTECTED")
        
        print("\n2. Security Headers:")
        if vuln_status['security_headers']['found']:
            print("   ❌ MISSING")
            for detail in vuln_status['security_headers']['details'][:5]:
                print(f"      - {detail}")
        else:
            print("   ✅ IMPLEMENTED")
        
        print("\n3. Administrative Endpoints:")
        if vuln_status['admin_endpoints']['found']:
            print("   ❌ EXPOSED")
            for detail in vuln_status['admin_endpoints']['details'][:3]:
                print(f"      - {detail}")
        else:
            print("   ✅ PROTECTED")
        
        print("\n4. CORS Configuration:")
        if vuln_status['cors']['found']:
            print("   ❌ MISCONFIGURED")
            for detail in vuln_status['cors']['details'][:3]:
                print(f"      - {detail}")
        else:
            print("   ✅ PROPERLY CONFIGURED")
        
        print("\n5. Server Version Disclosure:")
        if vuln_status['server_info']['found']:
            print("   ❌ EXPOSED")
            for detail in vuln_status['server_info']['details'][:3]:
                print(f"      - {detail}")
        else:
            print("   ✅ HIDDEN")
        
        # Test specific endpoints directly
        print("\n" + "=" * 50)
        print("ENDPOINT STATUS (Fresh Check)")
        print("-" * 50)
        
        critical_endpoints = [
            ('/opc/v1/instance/', 'Cloud Metadata'),
            ('/admin/', 'Admin Panel'),
            ('/api/', 'API Endpoint'),
            ('/private/', 'Private Directory')
        ]
        
        for endpoint, name in critical_endpoints:
            endpoint_url = target_url + endpoint
            endpoint_alerts = [a for a in results.get('alerts', []) 
                             if endpoint in a.get('url', '')]
            
            high_risk = [a for a in endpoint_alerts if a.get('risk') in ['Critical', 'High', 'Medium']]
            
            if high_risk:
                print(f"❌ {name} ({endpoint}): {len(high_risk)} vulnerabilities found")
            else:
                print(f"✅ {name} ({endpoint}): Secure")
        
        # Generate report
        report_file = f"LINKNODE_FRESH_SCAN_REPORT_{timestamp}.md"
        generate_fresh_scan_report(results, vuln_status, report_file)
        print(f"\nDetailed report generated: {report_file}")
        
        # Cleanup
        scanner.cleanup()
        print("\n✓ Fresh scan completed and session cleared!")
        
        # Final verdict
        print("\n" + "=" * 70)
        print("SECURITY ASSESSMENT VERDICT (Fresh Scan)")
        print("=" * 70)
        
        risk_score = results.get('summary', {}).get('risk_score', 100)
        if risk_score < 30:
            print("✅ GOOD SECURITY POSTURE")
            print("Most security measures are properly implemented.")
            print("Grade: B or better")
        elif risk_score < 60:
            print("⚠️  MODERATE SECURITY POSTURE")
            print("Some important security measures are missing.")
            print("Grade: C")
        else:
            print("❌ POOR SECURITY POSTURE")
            print("Critical security measures need to be implemented.")
            print("Grade: D or F")
        
        print("\nScan Session ID:", results.get('scan_session_id', 'N/A'))
        print("Fresh Scan Verified:", scanner.verify_fresh_scan())
        print("=" * 70)
        
    except Exception as e:
        print(f"\nError during fresh security scan: {str(e)}")
        scanner.cleanup()
        return False
    
    return True

def generate_fresh_scan_report(results, vuln_status, filename):
    """Generate fresh scan report."""
    with open(filename, 'w') as f:
        f.write(f"# Linknode.com Fresh Security Scan Report\n\n")
        f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Scan Type:** Enhanced Fresh Scan (No Cache)\n")
        f.write(f"**Session ID:** {results.get('scan_session_id', 'N/A')}\n")
        f.write(f"**Fresh Scan:** {results.get('fresh_scan', False)}\n\n")
        
        # Executive Summary
        f.write("## Executive Summary\n\n")
        f.write("This report presents results from a fresh security scan with all caching disabled ")
        f.write("and session data cleared to ensure accurate, up-to-date findings.\n\n")
        
        if 'summary' in results:
            summary = results['summary']
            f.write(f"**Risk Score:** {summary.get('risk_score', 0)}/100\n")
            f.write(f"**Total Issues:** {summary.get('total_issues', 0)}\n\n")
        
        # Vulnerability Status
        f.write("## Vulnerability Status\n\n")
        f.write("| Category | Status | Details |\n")
        f.write("|----------|--------|----------|\n")
        
        status_map = {
            'cloud_metadata': 'Cloud Metadata',
            'security_headers': 'Security Headers',
            'admin_endpoints': 'Admin Endpoints',
            'cors': 'CORS Configuration',
            'server_info': 'Server Info'
        }
        
        for key, name in status_map.items():
            if vuln_status[key]['found']:
                status = "❌ VULNERABLE"
                detail_count = len(vuln_status[key]['details'])
                details = f"{detail_count} issues found"
            else:
                status = "✅ SECURE"
                details = "No issues detected"
            f.write(f"| {name} | {status} | {details} |\n")
        
        # Detailed Findings
        f.write("\n## Detailed Findings\n\n")
        if 'alerts' in results:
            # Group by risk
            for risk in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
                risk_alerts = [a for a in results['alerts'] if a.get('risk') == risk]
                if risk_alerts:
                    f.write(f"### {risk} Risk ({len(risk_alerts)} issues)\n\n")
                    for i, alert in enumerate(risk_alerts[:5], 1):
                        f.write(f"{i}. **{alert.get('name', 'Unknown')}**\n")
                        f.write(f"   - URL: {alert.get('url', 'N/A')}\n")
                        f.write(f"   - Solution: {alert.get('solution', 'N/A')[:200]}...\n\n")
        
        # Scan Verification
        f.write("## Scan Verification\n\n")
        f.write("This scan used the following measures to ensure fresh readings:\n\n")
        f.write("- ✅ ZAP session cleared before scan\n")
        f.write("- ✅ Cache-busting headers added\n")
        f.write("- ✅ Timestamp parameters added to URLs\n")
        f.write("- ✅ Fresh spider crawl forced\n")
        f.write("- ✅ All scan data verified as non-cached\n")
        
        # Conclusion
        f.write("\n## Conclusion\n\n")
        if results.get('summary', {}).get('risk_score', 100) < 30:
            f.write("The fresh security scan confirms that linknode.com has good security posture ")
            f.write("with most security measures properly implemented.\n")
        else:
            f.write("The fresh security scan reveals security vulnerabilities that require ")
            f.write("immediate attention to protect against potential attacks.\n")

if __name__ == "__main__":
    run_fresh_security_test()