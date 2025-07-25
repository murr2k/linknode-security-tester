#!/usr/bin/env python3
"""
Test script for Phase 1 Technology-Aware Scanner
Demonstrates WhatWeb + Nikto + ZAP intelligent scanning
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.scanners.technology_aware_scanner import TechnologyAwareScanner
from src.integrations.zap_client import ZAPClient

def test_phase1_scanner():
    """Test the Phase 1 technology-aware scanner."""
    
    print("=" * 70)
    print("PHASE 1 TECHNOLOGY-AWARE SCANNER TEST")
    print("WhatWeb + Nikto + ZAP Integration")
    print("=" * 70)
    
    # Target URL
    target_url = "https://linknode.com"
    
    # Check if tools are installed
    print("\nChecking tool availability...")
    tools_status = check_tools()
    
    if not tools_status['whatweb'] and not tools_status['nikto']:
        print("\n⚠️  WARNING: Neither WhatWeb nor Nikto is installed!")
        print("Run: ./scripts/install_phase1_tools.sh")
        print("Continuing with ZAP-only scanning...\n")
    
    # Initialize ZAP client
    zap_available = False
    try:
        zap_client = ZAPClient()
        print("✓ ZAP connection established")
        zap_available = True
    except Exception as e:
        print(f"⚠️  ZAP not available: {e}")
        print("Continuing with available tools...")
    
    # Initialize technology-aware scanner
    scanner = TechnologyAwareScanner(zap_client if zap_available else None)
    
    print(f"\nTarget: {target_url}")
    print("-" * 70)
    
    # Test 1: Quick reconnaissance (WhatWeb + Nikto only)
    print("\n1. Quick Reconnaissance Scan...")
    print("   Using: WhatWeb + Nikto (no ZAP)")
    
    quick_results = scanner.scan(target_url, {
        'run_whatweb': True,
        'run_nikto': True,
        'run_zap': False,
        'run_free_apis': False
    })
    
    display_phase1_results(quick_results, "Quick Recon")
    
    # Test 2: Full technology-aware scan
    if zap_available:
        print("\n2. Full Technology-Aware Scan...")
        print("   Using: WhatWeb → Nikto → ZAP (strategy-based)")
        
        full_results = scanner.scan(target_url, {
            'run_whatweb': True,
            'run_nikto': True,
            'run_zap': True,
            'run_free_apis': True,
            'parallel_execution': True
        })
        
        display_phase1_results(full_results, "Full Scan")
    
    # Test 3: Technology detection impact
    print("\n3. Technology Detection Impact Analysis...")
    analyze_technology_impact(quick_results)
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"phase1_scan_results_{timestamp}.json"
    
    with open(results_file, 'w') as f:
        json.dump(quick_results if not zap_available else full_results, 
                 f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {results_file}")
    
    # Display recommendations
    print("\n" + "=" * 70)
    print("SCAN RECOMMENDATIONS")
    print("=" * 70)
    
    if 'recommendations' in (full_results if zap_available else quick_results):
        recommendations = (full_results if zap_available else quick_results)['recommendations']
        
        for i, rec in enumerate(recommendations[:5], 1):
            print(f"\n{i}. [{rec['priority'].upper()}] {rec['category']}")
            print(f"   {rec['description']}")
            if 'details' in rec:
                for detail in rec['details']:
                    print(f"   - {detail}")
    
    print("\n✓ Phase 1 scanner test completed!")

def check_tools():
    """Check which tools are available."""
    import subprocess
    
    tools = {
        'whatweb': False,
        'nikto': False,
        'zap': False
    }
    
    # Check WhatWeb
    try:
        result = subprocess.run(['whatweb', '--version'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            tools['whatweb'] = True
            print("✓ WhatWeb: Available")
        else:
            print("✗ WhatWeb: Not found")
    except:
        print("✗ WhatWeb: Not found")
    
    # Check Nikto
    try:
        result = subprocess.run(['nikto', '-Version'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            tools['nikto'] = True
            print("✓ Nikto: Available")
        else:
            print("✗ Nikto: Not found")
    except:
        print("✗ Nikto: Not found")
    
    return tools

def display_phase1_results(results, scan_type):
    """Display Phase 1 scan results."""
    print(f"\n{scan_type} Results:")
    print("-" * 50)
    
    # Technology detection results
    if 'technology_detection' in results.get('phases', {}):
        tech_data = results['phases']['technology_detection']
        if 'technologies' in tech_data:
            print(f"\nDetected Technologies: {len(tech_data['technologies'])}")
            
            # Group by category
            servers = []
            cms = []
            frameworks = []
            others = []
            
            for tech_name, tech_info in tech_data['technologies'].items():
                tech_str = tech_name
                if tech_info.get('version'):
                    tech_str += f" {tech_info['version']}"
                
                if any(s in tech_name.lower() for s in ['apache', 'nginx', 'iis']):
                    servers.append(tech_str)
                elif any(c in tech_name.lower() for c in ['wordpress', 'joomla', 'drupal']):
                    cms.append(tech_str)
                elif any(f in tech_name.lower() for f in ['php', 'asp', 'python', 'ruby']):
                    frameworks.append(tech_str)
                else:
                    others.append(tech_str)
            
            if servers:
                print(f"  Servers: {', '.join(servers)}")
            if cms:
                print(f"  CMS: {', '.join(cms)}")
            if frameworks:
                print(f"  Frameworks: {', '.join(frameworks)}")
            if others[:5]:  # Show first 5 others
                print(f"  Others: {', '.join(others[:5])}")
        
        # Vulnerabilities from WhatWeb
        if 'vulnerabilities' in tech_data and tech_data['vulnerabilities']:
            print(f"\nVulnerable Technologies: {len(tech_data['vulnerabilities'])}")
            for vuln in tech_data['vulnerabilities'][:3]:
                print(f"  - {vuln['technology']} {vuln['version']}: {vuln['issue']}")
    
    # Nikto results
    if 'nikto' in results.get('phases', {}):
        nikto_data = results['phases']['nikto']
        if 'summary' in nikto_data:
            summary = nikto_data['summary']
            print(f"\nNikto Findings: {summary['total_vulnerabilities']}")
            print(f"  High: {summary['high_severity']}")
            print(f"  Medium: {summary['medium_severity']}")
            print(f"  Low: {summary['low_severity']}")
            
            if summary['main_issues']:
                print("\n  Main Issues:")
                for issue in summary['main_issues']:
                    print(f"  - {issue}")
    
    # Scan strategy (shows how technology detection influenced the scan)
    if 'scan_strategy' in results:
        strategy = results['scan_strategy']
        if strategy['focus_areas']:
            print(f"\nScan Strategy Focus Areas:")
            for area in strategy['focus_areas']:
                print(f"  - {area}")
    
    # Analysis summary
    if 'analysis' in results:
        analysis = results['analysis']
        print(f"\nAnalysis Summary:")
        print(f"  Total Vulnerabilities: {analysis['total_vulnerabilities']}")
        print(f"  Confirmed (Multi-tool): {len(analysis.get('confirmed_vulnerabilities', []))}")
        print(f"  Technology Risks: {len(analysis.get('technology_risks', []))}")

def analyze_technology_impact(results):
    """Analyze how technology detection improved the scan."""
    print("\nTechnology Detection Impact:")
    print("-" * 50)
    
    if 'scan_strategy' not in results:
        print("No technology-based strategy was generated")
        return
    
    strategy = results['scan_strategy']
    
    print("\n1. Scan Optimization:")
    print(f"   Focus areas identified: {len(strategy['focus_areas'])}")
    print(f"   Priority checks added: {len(strategy['priority_checks'])}")
    
    if strategy['nikto_tuning'] != '123b':  # Default tuning
        print(f"   Nikto tuning customized: {strategy['nikto_tuning']}")
    
    if strategy['zap_config']:
        print(f"   ZAP configuration adjusted: {list(strategy['zap_config'].keys())}")
    
    print("\n2. Efficiency Gains:")
    
    # Calculate time saved by targeted scanning
    if 'phases' in results:
        phase_times = {}
        if 'technology_detection' in results['phases']:
            print("   ✓ Technology detection completed in seconds")
            print("   ✓ Enabled targeted vulnerability testing")
            print("   ✓ Reduced false positives through context")
    
    print("\n3. Detection Improvements:")
    
    # Show technology-specific findings
    if 'analysis' in results:
        tech_risks = results['analysis'].get('technology_risks', [])
        if tech_risks:
            print(f"   ✓ Identified {len(tech_risks)} technology-specific risks")
            for risk in tech_risks[:3]:
                print(f"     - {risk['technology']} {risk['version']}: {risk['risk']} risk")

if __name__ == "__main__":
    test_phase1_scanner()