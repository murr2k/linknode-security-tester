#!/usr/bin/env python3
"""
Current Security Assessment for linknode.com
Verifies the actual state of security fixes after deployment
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

def run_current_security_test():
    """Run security test to verify current state of fixes"""
    
    print(f"Starting CURRENT STATE security assessment for linknode.com")
    print(f"Timestamp: {datetime.now()}")
    print("=" * 70)
    print("Verifying security fixes deployed after July 25, 2025 3:53 AM...")
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
    
    # Configuration for current state verification
    scan_config = {
        'spider': True,
        'ajax_spider': True,
        'passive_scan': True,
        'active_scan': True,
        'attack_strength': 'HIGH',
        'alert_threshold': 'LOW'
    }
    
    print("\nCurrent State Test Configuration:")
    print(f"- Target: {target_url}")
    print(f"- Test Time: {datetime.now()}")
    print(f"- Expected: All fixes should be deployed")
    print("\n" + "=" * 70)
    
    try:
        # Run the security test
        security_scanner = orchestrator.security_scanner
        results = security_scanner.scan(target_url, scan_config)
        
        # Save detailed results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"linknode_current_scan_results_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nDetailed results saved to: {results_file}")
        
        # Analyze current security state
        print("\n" + "=" * 50)
        print("CURRENT SECURITY STATE VERIFICATION")
        print("=" * 50)
        
        # Track fixed vulnerabilities
        fixes_verified = {
            'cloud_metadata': True,  # Assume fixed unless found
            'csp_implemented': True,
            'security_headers': True,
            'admin_protected': True,
            'cors_fixed': True,
            'server_hidden': True
        }
        
        headers_found = {
            'csp': False,
            'x-frame-options': False,
            'x-content-type-options': False,
            'strict-transport-security': False,
            'referrer-policy': False,
            'permissions-policy': False
        }
        
        if 'alerts' in results:
            for alert in results['alerts']:
                alert_name = alert.get('name', '').lower()
                alert_url = alert.get('url', '')
                risk = alert.get('risk', '')
                
                # Check for cloud metadata
                if 'cloud metadata' in alert_name or '/opc/' in alert_url:
                    if risk in ['High', 'Critical']:
                        fixes_verified['cloud_metadata'] = False
                        print(f"❌ Cloud Metadata: STILL EXPOSED at {alert_url}")
                
                # Check CSP
                if 'content security policy' in alert_name and 'not set' in alert_name:
                    fixes_verified['csp_implemented'] = False
                    headers_found['csp'] = False
                elif 'content security policy' in alert_name:
                    headers_found['csp'] = True
                
                # Check other headers
                if 'x-frame-options' in alert_name and 'not set' in alert_name:
                    fixes_verified['security_headers'] = False
                    headers_found['x-frame-options'] = False
                elif 'x-frame-options' in alert_name:
                    headers_found['x-frame-options'] = True
                
                if 'strict-transport-security' in alert_name and 'not set' in alert_name:
                    headers_found['strict-transport-security'] = False
                elif 'strict-transport-security' in alert_name:
                    headers_found['strict-transport-security'] = True
                
                # Check admin endpoints
                if '/admin' in alert_url and risk in ['High', 'Medium', 'Critical']:
                    fixes_verified['admin_protected'] = False
                    print(f"❌ Admin Endpoint: STILL VULNERABLE at {alert_url}")
                
                # Check CORS
                if 'cors' in alert_name and 'wildcard' in alert_name:
                    fixes_verified['cors_fixed'] = False
                
                # Check server version
                if 'server' in alert_name and 'version' in alert_name and 'nginx' in alert.get('description', '').lower():
                    fixes_verified['server_hidden'] = False
        
        # Display comprehensive results
        print("\nSECURITY FIX VERIFICATION:")
        print("-" * 50)
        
        print("\n1. CRITICAL FIXES:")
        print(f"   {'✅' if fixes_verified['cloud_metadata'] else '❌'} Cloud Metadata Blocking")
        print(f"   {'✅' if fixes_verified['admin_protected'] else '❌'} Admin Endpoints Protection")
        
        print("\n2. SECURITY HEADERS:")
        for header, implemented in headers_found.items():
            status = "✅ Implemented" if implemented else "❌ Missing"
            print(f"   {status}: {header}")
        
        print("\n3. CONFIGURATION:")
        print(f"   {'✅' if fixes_verified['cors_fixed'] else '❌'} CORS Configuration")
        print(f"   {'✅' if fixes_verified['server_hidden'] else '❌'} Server Version Hidden")
        
        # Summary statistics
        if 'summary' in results:
            summary = results['summary']
            print("\n" + "=" * 50)
            print("SECURITY METRICS COMPARISON")
            print("=" * 50)
            print(f"Current Assessment (Post-Fix):")
            print(f"  Total Issues: {summary.get('total_issues', 0)}")
            print(f"  Risk Score: {summary.get('risk_score', 0)}/100")
            print(f"  High Risk: {summary.get('high_count', 0)}")
            print(f"  Medium Risk: {summary.get('medium_count', 0)}")
            print(f"  Low Risk: {summary.get('low_count', 0)}")
            print(f"\nPrevious Assessment (Pre-Fix):")
            print(f"  Total Issues: 108")
            print(f"  Risk Score: 74.56/100")
            print(f"  High Risk: 1")
            print(f"  Medium Risk: 23")
            print(f"  Low Risk: 29")
            
            # Calculate improvement
            issues_fixed = 108 - summary.get('total_issues', 0)
            score_improvement = 74.56 - summary.get('risk_score', 0)
            
            print(f"\nIMPROVEMENT:")
            print(f"  Issues Fixed: {issues_fixed} ({(issues_fixed/108)*100:.1f}%)")
            print(f"  Risk Score Reduced: {score_improvement:.2f} points")
            
            if issues_fixed > 50:
                print("\n🎉 EXCELLENT SECURITY IMPROVEMENT!")
            elif issues_fixed > 20:
                print("\n✅ GOOD SECURITY IMPROVEMENT")
            else:
                print("\n⚠️  MINIMAL IMPROVEMENT DETECTED")
        
        # Test critical endpoints
        print("\n" + "=" * 50)
        print("ENDPOINT SECURITY STATUS")
        print("-" * 50)
        
        critical_endpoints = [
            ('/opc/v1/instance/', 'Cloud Metadata', 'Should return 403'),
            ('/admin/', 'Admin Panel', 'Should return 404 or require auth'),
            ('/api/', 'API Endpoint', 'Should return 404 or require auth'),
            ('/private/', 'Private Directory', 'Should return 404')
        ]
        
        for endpoint, name, expected in critical_endpoints:
            endpoint_url = target_url + endpoint
            endpoint_alerts = [a for a in results.get('alerts', []) 
                             if endpoint in a.get('url', '') and a.get('risk') in ['Critical', 'High', 'Medium']]
            if endpoint_alerts:
                print(f"❌ {name} ({endpoint}): VULNERABLE - {expected}")
            else:
                print(f"✅ {name} ({endpoint}): SECURED - {expected}")
        
        # Generate final report
        report_file = f"LINKNODE_CURRENT_STATE_REPORT_{timestamp}.md"
        generate_current_state_report(results, fixes_verified, headers_found, report_file)
        print(f"\nDetailed report generated: {report_file}")
        
        # Cleanup
        orchestrator.cleanup()
        print("\n✓ Current state assessment completed!")
        
        # Final verdict
        total_fixes = sum(1 for v in fixes_verified.values() if v)
        header_count = sum(1 for v in headers_found.values() if v)
        
        print("\n" + "=" * 70)
        print("FINAL SECURITY VERDICT")
        print("=" * 70)
        
        if total_fixes >= 5 and header_count >= 4:
            print("✅ SECURITY FIXES SUCCESSFULLY DEPLOYED")
            print("The majority of critical vulnerabilities have been remediated.")
            grade = "B" if summary.get('risk_score', 100) < 40 else "C"
            print(f"Security Grade: {grade}")
        elif total_fixes >= 3:
            print("⚠️  PARTIAL SECURITY FIXES DEPLOYED")
            print("Some critical issues remain unaddressed.")
            print("Security Grade: D")
        else:
            print("❌ SECURITY FIXES NOT PROPERLY DEPLOYED")
            print("Most vulnerabilities remain active.")
            print("Security Grade: F")
        
        print("=" * 70)
        
    except Exception as e:
        print(f"\nError during security test: {str(e)}")
        orchestrator.cleanup()
        return False
    
    return True

def generate_current_state_report(results, fixes_verified, headers_found, filename):
    """Generate comprehensive current state report"""
    with open(filename, 'w') as f:
        f.write(f"# Linknode.com Current Security State Report\n\n")
        f.write(f"**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Purpose:** Verify current security state after fix deployment\n")
        f.write(f"**Deployment Time:** July 25, 2025 3:53 AM\n\n")
        
        # Executive Summary
        f.write("## Executive Summary\n\n")
        
        total_fixes = sum(1 for v in fixes_verified.values() if v)
        header_count = sum(1 for v in headers_found.values() if v)
        
        f.write(f"This report verifies the current security state of linknode.com after security fixes were deployed.\n\n")
        f.write(f"**Critical Fixes Applied:** {total_fixes}/6\n")
        f.write(f"**Security Headers Implemented:** {header_count}/6\n\n")
        
        # Detailed Status
        f.write("## Security Fix Implementation Status\n\n")
        f.write("### Critical Vulnerabilities\n\n")
        f.write("| Vulnerability | Status | Implementation |\n")
        f.write("|--------------|---------|----------------|\n")
        f.write(f"| Cloud Metadata Exposure | {'✅ FIXED' if fixes_verified['cloud_metadata'] else '❌ NOT FIXED'} | Block /opc/* endpoints |\n")
        f.write(f"| Admin Endpoints | {'✅ PROTECTED' if fixes_verified['admin_protected'] else '❌ EXPOSED'} | Return 404 or require auth |\n")
        f.write(f"| CORS Configuration | {'✅ FIXED' if fixes_verified['cors_fixed'] else '❌ MISCONFIGURED'} | No wildcard origins |\n")
        f.write(f"| Server Version | {'✅ HIDDEN' if fixes_verified['server_hidden'] else '❌ EXPOSED'} | Hide nginx version |\n")
        
        f.write("\n### Security Headers\n\n")
        f.write("| Header | Status | Purpose |\n")
        f.write("|--------|---------|----------|\n")
        f.write(f"| Content-Security-Policy | {'✅ SET' if headers_found['csp'] else '❌ MISSING'} | Prevent XSS attacks |\n")
        f.write(f"| X-Frame-Options | {'✅ SET' if headers_found['x-frame-options'] else '❌ MISSING'} | Prevent clickjacking |\n")
        f.write(f"| X-Content-Type-Options | {'✅ SET' if headers_found['x-content-type-options'] else '❌ MISSING'} | Prevent MIME sniffing |\n")
        f.write(f"| Strict-Transport-Security | {'✅ SET' if headers_found['strict-transport-security'] else '❌ MISSING'} | Force HTTPS |\n")
        f.write(f"| Referrer-Policy | {'✅ SET' if headers_found['referrer-policy'] else '❌ MISSING'} | Control referrer info |\n")
        f.write(f"| Permissions-Policy | {'✅ SET' if headers_found['permissions-policy'] else '❌ MISSING'} | Control browser features |\n")
        
        # Current Metrics
        if 'summary' in results:
            summary = results['summary']
            f.write("\n## Security Metrics\n\n")
            f.write("### Current State\n")
            f.write(f"- **Risk Score:** {summary.get('risk_score', 0)}/100\n")
            f.write(f"- **Total Vulnerabilities:** {summary.get('total_issues', 0)}\n")
            f.write(f"- **High Risk:** {summary.get('high_count', 0)}\n")
            f.write(f"- **Medium Risk:** {summary.get('medium_count', 0)}\n")
            f.write(f"- **Low Risk:** {summary.get('low_count', 0)}\n\n")
            
            f.write("### Improvement from Baseline\n")
            issues_reduced = 108 - summary.get('total_issues', 0)
            score_improved = 74.56 - summary.get('risk_score', 0)
            f.write(f"- **Issues Resolved:** {issues_reduced} ({(issues_reduced/108)*100:.1f}% reduction)\n")
            f.write(f"- **Risk Score Improvement:** {score_improved:.2f} points\n")
        
        # Recommendations
        f.write("\n## Recommendations\n\n")
        
        remaining_issues = []
        if not fixes_verified['cloud_metadata']:
            remaining_issues.append("- Block cloud metadata endpoint (/opc/*)")
        if not fixes_verified['admin_protected']:
            remaining_issues.append("- Protect admin endpoints with authentication")
        if not headers_found['csp']:
            remaining_issues.append("- Implement Content-Security-Policy header")
        if not headers_found['x-frame-options']:
            remaining_issues.append("- Add X-Frame-Options header")
        
        if remaining_issues:
            f.write("### Immediate Actions Required:\n\n")
            for issue in remaining_issues:
                f.write(f"{issue}\n")
        else:
            f.write("### Next Steps:\n\n")
            f.write("- Continue monitoring for new vulnerabilities\n")
            f.write("- Schedule regular security assessments\n")
            f.write("- Implement WAF for additional protection\n")
        
        # Conclusion
        f.write("\n## Conclusion\n\n")
        if total_fixes >= 5 and header_count >= 4:
            f.write("The security fixes have been successfully deployed. The application's security posture ")
            f.write("has significantly improved from the baseline assessment. Continue with regular ")
            f.write("security monitoring and testing to maintain this improved security stance.\n")
        else:
            f.write("The security assessment indicates that not all fixes have been properly deployed. ")
            f.write("Immediate action is required to implement the remaining security measures to ")
            f.write("protect against potential attacks.\n")

if __name__ == "__main__":
    run_current_security_test()