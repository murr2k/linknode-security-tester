#!/usr/bin/env python3
"""
Post-Fix Security Assessment for linknode.com
Verifies if security vulnerabilities have been properly remediated
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

def run_postfix_security_test():
    """Run comprehensive security test to verify fixes"""
    
    print(f"Starting POST-FIX security assessment for linknode.com at {datetime.now()}")
    print("=" * 70)
    print("Verifying security remediation efforts...")
    print("=" * 70)
    
    target_url = "https://linknode.com"
    
    # Initialize orchestrator
    orchestrator = ScanOrchestrator()
    
    try:
        orchestrator.initialize()
        print("✓ Scanner initialized successfully")
    except Exception as e:
        print(f"✗ Failed to initialize: {e}")
        return False
    
    # Configuration for comprehensive post-fix testing
    scan_config = {
        'spider': True,
        'ajax_spider': True,
        'passive_scan': True,
        'active_scan': True,
        'attack_strength': 'HIGH',  # More thorough testing
        'alert_threshold': 'LOW'
    }
    
    print("\nPost-Fix Test Configuration:")
    print(f"- Target: {target_url}")
    print(f"- Attack Strength: HIGH (thorough verification)")
    print(f"- Testing all previously vulnerable endpoints")
    print("\n" + "=" * 70)
    
    try:
        # Run the security test
        security_scanner = orchestrator.security_scanner
        results = security_scanner.scan(target_url, scan_config)
        
        # Save detailed results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"linknode_postfix_scan_results_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nDetailed results saved to: {results_file}")
        
        # Analyze fixes
        print("\n" + "=" * 50)
        print("REMEDIATION VERIFICATION")
        print("=" * 50)
        
        # Check specific vulnerabilities that were previously found
        previous_issues = {
            'cloud_metadata': False,
            'missing_csp': False,
            'missing_security_headers': False,
            'admin_exposed': False,
            'cors_misconfigured': False,
            'server_version_exposed': False
        }
        
        if 'alerts' in results:
            for alert in results['alerts']:
                alert_name = alert.get('name', '').lower()
                alert_url = alert.get('url', '')
                
                # Check cloud metadata
                if 'cloud metadata' in alert_name or '/opc/' in alert_url:
                    previous_issues['cloud_metadata'] = True
                    print(f"❌ Cloud Metadata Exposure: STILL VULNERABLE at {alert_url}")
                
                # Check CSP headers
                if 'content security policy' in alert_name or 'csp' in alert_name:
                    previous_issues['missing_csp'] = True
                    
                # Check other security headers
                if any(header in alert_name.lower() for header in ['x-frame-options', 'x-content-type', 'strict-transport']):
                    previous_issues['missing_security_headers'] = True
                
                # Check admin endpoints
                if '/admin' in alert_url and alert.get('risk') in ['High', 'Medium']:
                    previous_issues['admin_exposed'] = True
                
                # Check CORS
                if 'cors' in alert_name.lower() or 'cross-origin' in alert_name.lower():
                    previous_issues['cors_misconfigured'] = True
                
                # Check server version
                if 'server' in alert_name.lower() and 'version' in alert_name.lower():
                    previous_issues['server_version_exposed'] = True
        
        # Display verification results
        print("\nVULNERABILITY REMEDIATION STATUS:")
        print("-" * 50)
        
        fixes = {
            'cloud_metadata': "Cloud Metadata Exposure",
            'missing_csp': "Content Security Policy Headers",
            'missing_security_headers': "Security Headers (X-Frame-Options, etc)",
            'admin_exposed': "Administrative Endpoint Protection",
            'cors_misconfigured': "CORS Configuration",
            'server_version_exposed': "Server Version Disclosure"
        }
        
        fixed_count = 0
        for key, description in fixes.items():
            if previous_issues[key]:
                print(f"❌ {description}: NOT FIXED")
            else:
                print(f"✅ {description}: FIXED")
                fixed_count += 1
        
        # Summary statistics
        if 'summary' in results:
            summary = results['summary']
            print("\n" + "=" * 50)
            print("CURRENT SECURITY POSTURE")
            print("=" * 50)
            print(f"Total Issues: {summary.get('total_issues', 0)} (was 108)")
            print(f"Risk Score: {summary.get('risk_score', 0)}/100 (was 74.56)")
            print(f"\nBreakdown:")
            print(f"  - Critical: {summary.get('critical_count', 0)} (was 0)")
            print(f"  - High: {summary.get('high_count', 0)} (was 1)")
            print(f"  - Medium: {summary.get('medium_count', 0)} (was 23)")
            print(f"  - Low: {summary.get('low_count', 0)} (was 29)")
            print(f"  - Informational: {summary.get('info_count', 0)} (was 55)")
            
            # Calculate improvement
            if summary.get('total_issues', 0) < 108:
                improvement = 108 - summary.get('total_issues', 0)
                print(f"\n🎉 Improvement: {improvement} issues fixed!")
            else:
                print(f"\n⚠️  No improvement detected")
        
        # Test specific critical endpoints
        print("\n" + "=" * 50)
        print("CRITICAL ENDPOINT VERIFICATION")
        print("-" * 50)
        
        # Test cloud metadata endpoint
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
            if endpoint_alerts:
                high_risk = [a for a in endpoint_alerts if a.get('risk') in ['Critical', 'High']]
                if high_risk:
                    print(f"❌ {name} ({endpoint}): HIGH RISK vulnerabilities found")
                else:
                    print(f"⚠️  {name} ({endpoint}): Low/Medium risk issues remain")
            else:
                print(f"✅ {name} ({endpoint}): No vulnerabilities detected")
        
        # Generate detailed report
        report_file = f"LINKNODE_POSTFIX_VERIFICATION_REPORT_{timestamp}.md"
        generate_verification_report(results, previous_issues, fixed_count, report_file)
        print(f"\nDetailed verification report generated: {report_file}")
        
        # Cleanup
        orchestrator.cleanup()
        print("\n✓ Post-fix assessment completed!")
        
        # Final recommendation
        print("\n" + "=" * 70)
        if fixed_count >= 4:
            print("✅ SIGNIFICANT SECURITY IMPROVEMENTS DETECTED")
            print("Most critical vulnerabilities have been addressed.")
        elif fixed_count >= 2:
            print("⚠️  PARTIAL SECURITY IMPROVEMENTS")
            print("Some fixes applied, but critical issues remain.")
        else:
            print("❌ MINIMAL SECURITY IMPROVEMENTS")
            print("Most vulnerabilities remain unaddressed.")
        print("=" * 70)
        
    except Exception as e:
        print(f"\nError during security test: {str(e)}")
        orchestrator.cleanup()
        return False
    
    return True

def generate_verification_report(results, previous_issues, fixed_count, filename):
    """Generate a detailed verification report"""
    with open(filename, 'w') as f:
        f.write(f"# Linknode.com Post-Fix Security Verification Report\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Purpose:** Verify security fixes after remediation efforts\n\n")
        
        # Executive Summary
        f.write("## Executive Summary\n\n")
        f.write(f"This report verifies the security fixes applied to linknode.com following the previous security assessment.\n\n")
        f.write(f"**Fixes Verified:** {fixed_count}/6 critical issues\n\n")
        
        # Remediation Status
        f.write("## Remediation Status\n\n")
        f.write("| Vulnerability | Previous Status | Current Status | Fixed |\n")
        f.write("|--------------|-----------------|----------------|-------|\n")
        
        status_map = {
            'cloud_metadata': ('Cloud Metadata Exposure', 'HIGH RISK'),
            'missing_csp': ('Missing CSP Headers', 'MEDIUM RISK'),
            'missing_security_headers': ('Missing Security Headers', 'MEDIUM RISK'),
            'admin_exposed': ('Admin Endpoints Exposed', 'MEDIUM RISK'),
            'cors_misconfigured': ('CORS Misconfiguration', 'MEDIUM RISK'),
            'server_version_exposed': ('Server Version Disclosure', 'LOW RISK')
        }
        
        for key, (name, risk) in status_map.items():
            if previous_issues[key]:
                f.write(f"| {name} | {risk} | STILL PRESENT | ❌ |\n")
            else:
                f.write(f"| {name} | {risk} | FIXED | ✅ |\n")
        
        # Current Security Posture
        if 'summary' in results:
            summary = results['summary']
            f.write("\n## Current Security Posture\n\n")
            f.write(f"- **Risk Score:** {summary.get('risk_score', 0)}/100 (was 74.56)\n")
            f.write(f"- **Total Issues:** {summary.get('total_issues', 0)} (was 108)\n")
            f.write(f"- **High Risk Issues:** {summary.get('high_count', 0)} (was 1)\n\n")
        
        # Remaining Critical Issues
        f.write("## Remaining Critical Issues\n\n")
        if 'alerts' in results:
            critical_alerts = [a for a in results['alerts'] if a.get('risk') in ['Critical', 'High']]
            if critical_alerts:
                for alert in critical_alerts[:5]:
                    f.write(f"### {alert.get('name', 'Unknown')}\n")
                    f.write(f"- **URL:** {alert.get('url', 'N/A')}\n")
                    f.write(f"- **Risk:** {alert.get('risk', 'Unknown')}\n")
                    f.write(f"- **Solution:** {alert.get('solution', 'N/A')}\n\n")
            else:
                f.write("No critical or high-risk issues found.\n\n")
        
        # Recommendations
        f.write("## Recommendations\n\n")
        if fixed_count < 3:
            f.write("### Priority Actions Required:\n\n")
            f.write("1. **Immediately address remaining HIGH risk vulnerabilities**\n")
            f.write("2. **Implement all security headers as specified in previous report**\n")
            f.write("3. **Secure administrative endpoints with proper authentication**\n\n")
        else:
            f.write("### Next Steps:\n\n")
            f.write("1. **Address any remaining medium/low risk issues**\n")
            f.write("2. **Implement continuous security monitoring**\n")
            f.write("3. **Schedule regular security assessments**\n\n")
        
        f.write("## Conclusion\n\n")
        if fixed_count >= 4:
            f.write("Significant progress has been made in addressing the security vulnerabilities. ")
            f.write("Continue with the remaining fixes to achieve a robust security posture.\n")
        else:
            f.write("Limited progress has been made in addressing the security vulnerabilities. ")
            f.write("Immediate action is required to fix the remaining critical issues.\n")

if __name__ == "__main__":
    run_postfix_security_test()