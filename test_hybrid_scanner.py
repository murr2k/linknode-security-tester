#!/usr/bin/env python3
"""
Test script for Hybrid Security Scanner
Demonstrates combining local ZAP with cloud HostedScan
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.integrations.zap_client import ZAPClient
from src.scanners.hybrid_scanner import HybridSecurityScanner

def test_hybrid_scanner():
    """Test the hybrid scanner with both local and cloud scanning."""
    
    print("=" * 70)
    print("HYBRID SECURITY SCANNER TEST")
    print("Combining Local ZAP + Cloud HostedScan")
    print("=" * 70)
    
    # Get HostedScan API key from environment
    hostedscan_api_key = os.environ.get('HOSTEDSCAN_API_KEY')
    if not hostedscan_api_key:
        print("\n⚠️  WARNING: HOSTEDSCAN_API_KEY not set")
        print("Set your API key: export HOSTEDSCAN_API_KEY='your-key-here'")
        print("Continuing with local-only scanning...\n")
    
    # Target URL
    target_url = "https://linknode.com"
    
    # Initialize ZAP client
    try:
        zap_client = ZAPClient()
        print("✓ Connected to local ZAP instance")
    except Exception as e:
        print(f"✗ Failed to connect to ZAP: {e}")
        print("\nMake sure OWASP ZAP is running:")
        print("  docker-compose up -d zap")
        return
    
    # Initialize hybrid scanner
    scanner = HybridSecurityScanner(
        zap_client=zap_client,
        hostedscan_api_key=hostedscan_api_key
    )
    
    # Test different scan modes
    print(f"\nTarget: {target_url}")
    print("-" * 70)
    
    # 1. Quick local-only scan
    print("\n1. Testing LOCAL-ONLY scan mode...")
    local_config = {
        'mode': 'local_only',
        'local_spider': True,
        'local_passive_scan': True,
        'local_active_scan': False  # Skip for speed
    }
    
    local_results = scanner.scan(target_url, local_config)
    
    if local_results.get('local_results'):
        summary = local_results.get('summary', {})
        print(f"   ✓ Local scan completed")
        print(f"   - Vulnerabilities found: {summary.get('total_vulnerabilities', 0)}")
        print(f"   - Risk score: {summary.get('risk_score', 0)}/100")
    
    # 2. Cloud-only scan (if API key available)
    if hostedscan_api_key:
        print("\n2. Testing CLOUD-ONLY scan mode...")
        cloud_config = {
            'mode': 'cloud_only',
            'cloud_scan_type': 'quick',
            'wait_for_cloud': False  # Don't wait for completion
        }
        
        cloud_results = scanner.scan(target_url, cloud_config)
        
        if cloud_results.get('cloud_results'):
            cloud_data = cloud_results['cloud_results']
            if cloud_data.get('status') == 'running':
                print(f"   ✓ Cloud scan started")
                print(f"   - Scan ID: {cloud_data.get('scan_id')}")
                print(f"   - Status: Running in background")
            else:
                print(f"   ✓ Cloud scan completed")
                summary = cloud_data.get('summary', {})
                print(f"   - Vulnerabilities found: {summary.get('total_risks', 0)}")
    
    # 3. Hybrid scan (parallel execution)
    print("\n3. Testing HYBRID scan mode (parallel execution)...")
    hybrid_config = {
        'mode': 'hybrid',
        'local_spider': True,
        'local_passive_scan': True,
        'local_active_scan': False,
        'cloud_scan_type': 'quick',
        'wait_for_cloud': hostedscan_api_key is not None,
        'merge_results': True
    }
    
    print("   Running local and cloud scans in parallel...")
    hybrid_results = scanner.scan(target_url, hybrid_config)
    
    # Display results
    print("\n" + "=" * 70)
    print("HYBRID SCAN RESULTS")
    print("=" * 70)
    
    summary = hybrid_results.get('summary', {})
    print(f"\nScan Mode: {summary.get('scan_mode')}")
    print(f"Scanners Used: {', '.join(summary.get('scanners_used', []))}")
    print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    print(f"Risk Score: {summary.get('risk_score', 0)}/100")
    print(f"Confidence Level: {summary.get('confidence_level', 'unknown')}")
    
    # Show merged results if available
    if hybrid_results.get('merged_results'):
        merged = hybrid_results['merged_results']
        print("\nMERGED VULNERABILITY ANALYSIS:")
        print("-" * 50)
        print(f"Confirmed by both scanners: {len(merged.get('confirmed_findings', []))}")
        print(f"Found by ZAP only: {len(merged.get('local_only_findings', []))}")
        print(f"Found by HostedScan only: {len(merged.get('cloud_only_findings', []))}")
        
        # Risk breakdown
        risk_summary = merged.get('risk_summary', {})
        print("\nRisk Distribution:")
        for risk, count in risk_summary.items():
            if count > 0:
                print(f"  - {risk.upper()}: {count}")
        
        # Show top confirmed vulnerabilities
        confirmed = merged.get('confirmed_findings', [])
        if confirmed:
            print("\nTOP CONFIRMED VULNERABILITIES (found by both scanners):")
            for i, finding in enumerate(confirmed[:5], 1):
                print(f"\n{i}. {finding.get('name')}")
                print(f"   Risk: {finding.get('risk').upper()}")
                print(f"   URL: {finding.get('url')}")
                print(f"   Confidence: HIGH (confirmed by multiple scanners)")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"hybrid_scan_results_{timestamp}.json"
    
    with open(results_file, 'w') as f:
        json.dump(hybrid_results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {results_file}")
    
    # Recommendations
    print("\n" + "=" * 70)
    print("HYBRID SCANNING RECOMMENDATIONS")
    print("=" * 70)
    
    print("\n1. For Development:")
    print("   - Use local-only mode for quick feedback")
    print("   - Run during CI/CD pipeline")
    
    print("\n2. For Staging:")
    print("   - Use hybrid mode for comprehensive coverage")
    print("   - Schedule daily scans")
    
    print("\n3. For Production:")
    print("   - Use cloud-only mode for non-intrusive scanning")
    print("   - Enable continuous monitoring")
    
    print("\n4. For Compliance:")
    print("   - Use hybrid mode with full scanning")
    print("   - Generate reports from both scanners")
    
    # Configuration example
    print("\n" + "=" * 70)
    print("EXAMPLE CONFIGURATION")
    print("=" * 70)
    
    print("\nEnvironment Setup:")
    print("  export HOSTEDSCAN_API_KEY='your-api-key'")
    print("  docker-compose up -d zap")
    
    print("\nPython Integration:")
    print("""
from src.scanners.hybrid_scanner import HybridSecurityScanner

scanner = HybridSecurityScanner(
    hostedscan_api_key=os.environ.get('HOSTEDSCAN_API_KEY')
)

# Quick local scan
results = scanner.scan(target_url, {'mode': 'local_only'})

# Cloud scan with authentication
scanner.configure_cloud_auth(target_url, 'bearer', {
    'token': 'your-api-token'
})
results = scanner.scan(target_url, {'mode': 'cloud_only'})

# Full hybrid scan
results = scanner.scan(target_url, {
    'mode': 'hybrid',
    'wait_for_cloud': True,
    'merge_results': True
})
""")
    
    print("\n✓ Hybrid scanner test completed!")

if __name__ == "__main__":
    test_hybrid_scanner()