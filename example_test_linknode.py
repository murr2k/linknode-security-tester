#!/usr/bin/env python3
"""Example script to test linknode.com security."""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.core.orchestrator import ScanOrchestrator
from src.integrations.zap_client import ZAPClient
from src.scanners.security import SecurityScanner


def test_linknode():
    """Run security test on linknode.com."""
    print("=" * 60)
    print("Linknode Security Test Example")
    print("=" * 60)
    
    target_url = "https://linknode.com"
    
    # Initialize components
    print("\n1. Initializing security scanner...")
    orchestrator = ScanOrchestrator()
    
    try:
        orchestrator.initialize()
        print("   ✓ Scanner initialized successfully")
    except Exception as e:
        print(f"   ✗ Failed to initialize: {e}")
        print("\nMake sure OWASP ZAP is running:")
        print("  docker-compose up -d zap")
        return
    
    # Run basic security scan
    print(f"\n2. Running security scan on {target_url}...")
    security_scanner = orchestrator.security_scanner
    
    # Configure scan (reduced scope for demo)
    scan_config = {
        'spider': True,
        'ajax_spider': False,  # Skip for faster demo
        'passive_scan': True,
        'active_scan': False   # Skip for faster demo
    }
    
    results = security_scanner.scan(target_url, scan_config)
    
    # Display results
    print("\n3. Scan Results:")
    print(f"   • URLs discovered: {results['phases'].get('spider', {}).get('urls_found', 0)}")
    print(f"   • Total alerts: {results.get('total_alerts', 0)}")
    print(f"   • Risk score: {results.get('risk_score', 0)}/100")
    
    if 'alerts_by_risk' in results:
        print("\n   Alerts by Risk Level:")
        for risk, count in results['alerts_by_risk'].items():
            print(f"     - {risk}: {count}")
    
    # Show top vulnerabilities
    if results.get('alerts'):
        print("\n4. Top Security Findings:")
        for i, alert in enumerate(results['alerts'][:5], 1):
            print(f"\n   {i}. {alert['name']}")
            print(f"      Risk: {alert['risk']}")
            print(f"      URL: {alert['url']}")
            print(f"      Solution: {alert['solution'][:100]}...")
    
    # Generate remediation plan
    print("\n5. Generating remediation plan...")
    remediation = security_scanner.generate_remediation_plan()
    
    if remediation.get('high_priority'):
        print(f"\n   High Priority Issues: {len(remediation['high_priority'])}")
        for issue in remediation['high_priority'][:3]:
            print(f"     • {issue['vulnerability']}")
    
    print(f"\n   Estimated remediation effort: {remediation['estimated_effort']['total_hours']} hours")
    
    # Save detailed results
    output_file = "linknode_security_test_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n6. Detailed results saved to: {output_file}")
    
    # Cleanup
    orchestrator.cleanup()
    print("\n✓ Test completed successfully!")
    
    # Summary recommendations
    print("\n" + "=" * 60)
    print("RECOMMENDATIONS FOR LINKNODE.COM:")
    print("=" * 60)
    
    if results.get('risk_score', 0) < 30:
        print("✓ Overall security posture is GOOD")
    elif results.get('risk_score', 0) < 60:
        print("⚠ Overall security posture is MODERATE - some improvements needed")
    else:
        print("✗ Overall security posture needs IMMEDIATE ATTENTION")
    
    print("\nKey Actions:")
    print("1. Review and fix any high-risk vulnerabilities")
    print("2. Implement security headers (CSP, HSTS, etc.)")
    print("3. Regular security scanning (monthly minimum)")
    print("4. Consider full penetration testing for critical assets")


if __name__ == "__main__":
    test_linknode()