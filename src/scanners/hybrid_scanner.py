"""Hybrid Security Scanner combining ZAP and HostedScan capabilities."""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
from concurrent.futures import ThreadPoolExecutor

from ..integrations.zap_client import ZAPClient
from ..integrations.hostedscan_client import HostedScanClient
from ..integrations.free_apis import FreeAPIAggregator
from .enhanced_security import EnhancedSecurityScanner
from ..core.config import settings

logger = logging.getLogger(__name__)


class HybridSecurityScanner:
    """Combines local ZAP scanning with cloud-based HostedScan for comprehensive coverage."""
    
    def __init__(self, zap_client: Optional[ZAPClient] = None, 
                 hostedscan_api_key: Optional[str] = None):
        """Initialize hybrid scanner.
        
        Args:
            zap_client: Optional ZAP client instance
            hostedscan_api_key: HostedScan API key
        """
        self.zap_scanner = EnhancedSecurityScanner(zap_client)
        self.hostedscan = None
        self.free_apis = None
        
        if hostedscan_api_key:
            self.hostedscan = HostedScanClient(hostedscan_api_key)
            logger.info("HostedScan integration enabled")
        else:
            logger.warning("HostedScan API key not provided - using free APIs instead")
            self.free_apis = FreeAPIAggregator()
            logger.info("Free API integration enabled (Mozilla Observatory, SSL Labs, etc.)")
    
    def scan(self, target_url: str, scan_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run hybrid security scan using both local and cloud scanners.
        
        Args:
            target_url: URL to scan
            scan_config: Scan configuration options
            
        Returns:
            Combined scan results
        """
        logger.info(f"Starting hybrid security scan for {target_url}")
        start_time = datetime.now()
        
        config = {
            'mode': 'hybrid',  # hybrid, local_only, cloud_only
            'local_scan': True,
            'cloud_scan': True,
            'merge_results': True,
            'wait_for_cloud': False,
            'cloud_scan_type': 'full',
            **((scan_config or {}))
        }
        
        results = {
            'target_url': target_url,
            'scan_type': 'hybrid',
            'scan_start': start_time.isoformat(),
            'scan_config': config,
            'local_results': None,
            'cloud_results': None,
            'merged_results': None
        }
        
        # Determine scan mode
        if config['mode'] == 'local_only':
            results['local_results'] = self._run_local_scan(target_url, config)
        elif config['mode'] == 'cloud_only':
            results['cloud_results'] = self._run_cloud_scan(target_url, config)
        else:  # hybrid mode
            # Run scans in parallel
            local_results, cloud_results = self._run_parallel_scans(target_url, config)
            results['local_results'] = local_results
            results['cloud_results'] = cloud_results
            
            # Merge results if requested
            if config['merge_results'] and local_results and cloud_results:
                results['merged_results'] = self._merge_scan_results(
                    local_results, 
                    cloud_results
                )
        
        # Calculate summary
        results['summary'] = self._calculate_summary(results)
        
        end_time = datetime.now()
        results['scan_end'] = end_time.isoformat()
        results['scan_duration'] = (end_time - start_time).total_seconds()
        
        return results
    
    def _run_local_scan(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run local ZAP scan."""
        logger.info("Running local ZAP scan")
        
        local_config = {
            'spider': config.get('local_spider', True),
            'ajax_spider': config.get('local_ajax_spider', True),
            'passive_scan': config.get('local_passive_scan', True),
            'active_scan': config.get('local_active_scan', True),
            'force_fresh': True,
            'clear_cache': True
        }
        
        try:
            return self.zap_scanner.scan(target_url, local_config)
        except Exception as e:
            logger.error(f"Local scan failed: {e}")
            return {'error': str(e), 'status': 'failed'}
    
    def _run_cloud_scan(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run cloud scan using HostedScan or free APIs."""
        if self.hostedscan:
            logger.info("Running cloud HostedScan scan")
            try:
                # Quick scan returns immediately, full scan waits
                if config.get('wait_for_cloud', False):
                    return self.hostedscan.run_quick_scan(
                        target_url, 
                        wait=True
                    )
                else:
                    # Start scan and return immediately
                    scan_info = self.hostedscan.run_quick_scan(
                        target_url, 
                        wait=False
                    )
                    return {
                        'scan_id': scan_info.get('id'),
                        'status': 'running',
                        'message': 'Cloud scan started - check back later for results'
                    }
            except Exception as e:
                logger.error(f"HostedScan failed: {e}")
                return {'error': str(e), 'status': 'failed'}
        
        elif self.free_apis:
            logger.info("Running free API scans")
            try:
                # Run all free API scans
                results = self.free_apis.scan_all(target_url)
                
                # Convert to standard format
                return {
                    'status': 'completed',
                    'scan_type': 'free_apis',
                    'summary': results.get('summary', {}),
                    'mozilla_observatory': results.get('mozilla_observatory'),
                    'ssl_labs': results.get('ssl_labs'),
                    'security_headers': results.get('security_headers'),
                    'risks': self._convert_free_api_results_to_risks(results)
                }
            except Exception as e:
                logger.error(f"Free API scan failed: {e}")
                return {'error': str(e), 'status': 'failed'}
        
        else:
            logger.warning("No cloud scanning configured")
            return {'error': 'No cloud scanning available', 'status': 'skipped'}
    
    def _run_parallel_scans(self, target_url: str, config: Dict[str, Any]) -> tuple:
        """Run local and cloud scans in parallel."""
        logger.info("Running scans in parallel")
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Submit both scans
            local_future = executor.submit(self._run_local_scan, target_url, config)
            cloud_future = executor.submit(self._run_cloud_scan, target_url, config)
            
            # Get results
            local_results = local_future.result()
            cloud_results = cloud_future.result()
            
        return local_results, cloud_results
    
    def _merge_scan_results(self, local_results: Dict[str, Any], 
                           cloud_results: Dict[str, Any]) -> Dict[str, Any]:
        """Merge and deduplicate results from both scanners."""
        logger.info("Merging scan results")
        
        merged = {
            'total_findings': 0,
            'deduplicated_findings': [],
            'local_only_findings': [],
            'cloud_only_findings': [],
            'confirmed_findings': [],  # Found by both scanners
            'risk_summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Extract findings
        local_alerts = local_results.get('alerts', [])
        cloud_risks = []
        
        # Handle cloud results based on format
        if 'risks' in cloud_results:
            cloud_risks = cloud_results['risks']
        elif 'summary' in cloud_results and 'top_risks' in cloud_results:
            cloud_risks = cloud_results.get('top_risks', [])
        
        # Create finding signatures for deduplication
        local_signatures = {}
        for alert in local_alerts:
            signature = self._create_finding_signature(alert, 'zap')
            local_signatures[signature] = alert
        
        cloud_signatures = {}
        for risk in cloud_risks:
            signature = self._create_finding_signature(risk, 'hostedscan')
            cloud_signatures[signature] = risk
        
        # Find confirmed vulnerabilities (in both)
        confirmed_sigs = set(local_signatures.keys()) & set(cloud_signatures.keys())
        for sig in confirmed_sigs:
            finding = self._merge_findings(
                local_signatures[sig], 
                cloud_signatures[sig]
            )
            finding['confidence'] = 'high'  # Both scanners found it
            merged['confirmed_findings'].append(finding)
        
        # Find local-only vulnerabilities
        local_only_sigs = set(local_signatures.keys()) - set(cloud_signatures.keys())
        for sig in local_only_sigs:
            finding = self._normalize_finding(local_signatures[sig], 'zap')
            finding['confidence'] = 'medium'
            merged['local_only_findings'].append(finding)
        
        # Find cloud-only vulnerabilities  
        cloud_only_sigs = set(cloud_signatures.keys()) - set(local_signatures.keys())
        for sig in cloud_only_sigs:
            finding = self._normalize_finding(cloud_signatures[sig], 'hostedscan')
            finding['confidence'] = 'medium'
            merged['cloud_only_findings'].append(finding)
        
        # Combine all findings
        all_findings = (
            merged['confirmed_findings'] + 
            merged['local_only_findings'] + 
            merged['cloud_only_findings']
        )
        
        # Sort by risk level
        risk_priority = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        all_findings.sort(key=lambda x: risk_priority.get(x.get('risk', 'info'), 5))
        
        merged['deduplicated_findings'] = all_findings
        merged['total_findings'] = len(all_findings)
        
        # Calculate risk summary
        for finding in all_findings:
            risk = finding.get('risk', 'info').lower()
            if risk in merged['risk_summary']:
                merged['risk_summary'][risk] += 1
        
        return merged
    
    def _create_finding_signature(self, finding: Dict[str, Any], source: str) -> str:
        """Create a signature for deduplication."""
        if source == 'zap':
            # ZAP alert signature
            name = finding.get('name', '').lower()
            url = finding.get('url', '').split('?')[0]  # Remove query params
            param = finding.get('param', '')
            return f"{name}|{url}|{param}"
        else:
            # HostedScan risk signature
            title = finding.get('title', '').lower()
            url = finding.get('url', '').split('?')[0]
            return f"{title}|{url}"
    
    def _normalize_finding(self, finding: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Normalize finding format from different sources."""
        if source == 'zap':
            return {
                'source': 'zap',
                'name': finding.get('name'),
                'risk': finding.get('risk', 'info').lower(),
                'url': finding.get('url'),
                'description': finding.get('description'),
                'solution': finding.get('solution'),
                'evidence': finding.get('evidence'),
                'param': finding.get('param'),
                'original': finding
            }
        else:
            # Map HostedScan severity to risk levels
            severity_map = {
                'critical': 'critical',
                'high': 'high',
                'medium': 'medium',
                'low': 'low',
                'informational': 'info'
            }
            
            return {
                'source': 'hostedscan',
                'name': finding.get('title', finding.get('name')),
                'risk': severity_map.get(finding.get('severity', 'info').lower(), 'info'),
                'url': finding.get('url'),
                'description': finding.get('description'),
                'solution': finding.get('remediation', finding.get('solution')),
                'evidence': finding.get('evidence'),
                'original': finding
            }
    
    def _merge_findings(self, local: Dict[str, Any], cloud: Dict[str, Any]) -> Dict[str, Any]:
        """Merge two findings that represent the same vulnerability."""
        normalized_local = self._normalize_finding(local, 'zap')
        normalized_cloud = self._normalize_finding(cloud, 'hostedscan')
        
        # Combine information from both sources
        return {
            'source': 'both',
            'name': normalized_local['name'],  # Prefer local name
            'risk': normalized_local['risk'],  # Should be same
            'url': normalized_local['url'],
            'description': normalized_local['description'] or normalized_cloud['description'],
            'solution': normalized_local['solution'] or normalized_cloud['solution'],
            'evidence': {
                'zap': normalized_local.get('evidence'),
                'hostedscan': normalized_cloud.get('evidence')
            },
            'param': normalized_local.get('param'),
            'sources': ['zap', 'hostedscan']
        }
    
    def _calculate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall summary from all results."""
        summary = {
            'scan_mode': results.get('scan_config', {}).get('mode', 'unknown'),
            'scanners_used': [],
            'total_vulnerabilities': 0,
            'risk_score': 0,
            'confidence_level': 'low'
        }
        
        # Check which scanners were used
        if results.get('local_results') and 'error' not in results['local_results']:
            summary['scanners_used'].append('zap')
        if results.get('cloud_results') and 'error' not in results['cloud_results']:
            summary['scanners_used'].append('hostedscan')
        
        # Calculate totals based on available results
        if results.get('merged_results'):
            merged = results['merged_results']
            summary['total_vulnerabilities'] = merged['total_findings']
            summary['risk_breakdown'] = merged['risk_summary']
            
            # Higher confidence if both scanners agree
            confirmed_count = len(merged.get('confirmed_findings', []))
            if confirmed_count > 0:
                summary['confidence_level'] = 'high'
            elif len(summary['scanners_used']) > 1:
                summary['confidence_level'] = 'medium'
        else:
            # Single scanner results
            if results.get('local_results') and 'summary' in results['local_results']:
                local_summary = results['local_results']['summary']
                summary['total_vulnerabilities'] = local_summary.get('total_issues', 0)
                summary['risk_score'] = local_summary.get('risk_score', 0)
            
            if results.get('cloud_results') and 'summary' in results['cloud_results']:
                cloud_summary = results['cloud_results']['summary']
                # If we have both, take the higher risk score
                cloud_total = cloud_summary.get('total_risks', 0)
                if summary['total_vulnerabilities'] == 0:
                    summary['total_vulnerabilities'] = cloud_total
        
        # Calculate combined risk score
        if 'risk_breakdown' in summary:
            # Weight: critical=20, high=10, medium=5, low=1
            risk_weights = {'critical': 20, 'high': 10, 'medium': 5, 'low': 1, 'info': 0.1}
            
            weighted_score = 0
            for risk, count in summary['risk_breakdown'].items():
                weighted_score += risk_weights.get(risk, 0) * count
            
            summary['risk_score'] = min(100, weighted_score)
        
        return summary
    
    def _convert_free_api_results_to_risks(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert free API results to standard risk format."""
        risks = []
        
        # Convert security header findings
        if results.get('security_headers'):
            headers_data = results['security_headers']
            for missing_header in headers_data.get('headers_missing', []):
                risks.append({
                    'title': f"Missing Security Header: {missing_header['name']}",
                    'severity': 'medium',
                    'description': missing_header['description'],
                    'url': results['target_url'],
                    'source': 'security_headers_check'
                })
            
            for warning in headers_data.get('warnings', []):
                risks.append({
                    'title': warning['issue'],
                    'severity': 'low',
                    'description': f"{warning['header']}: {warning['value']}",
                    'url': results['target_url'],
                    'source': 'security_headers_check'
                })
        
        # Convert SSL Labs findings
        if results.get('ssl_labs') and 'endpoints' in results['ssl_labs']:
            for endpoint in results['ssl_labs']['endpoints']:
                for issue in endpoint.get('issues', []):
                    risks.append({
                        'title': issue,
                        'severity': 'high' if 'vulnerability' in issue.lower() else 'medium',
                        'description': f"SSL/TLS issue on {endpoint['ip']}",
                        'url': results['target_url'],
                        'source': 'ssl_labs'
                    })
        
        # Convert Mozilla Observatory findings
        if results.get('mozilla_observatory'):
            mozilla_data = results['mozilla_observatory']
            if mozilla_data.get('grade', 'F') <= 'D':
                risks.append({
                    'title': 'Poor Security Header Configuration',
                    'severity': 'medium',
                    'description': f"Mozilla Observatory grade: {mozilla_data.get('grade')}",
                    'url': results['target_url'],
                    'source': 'mozilla_observatory'
                })
        
        return risks
    
    # Utility methods
    def check_cloud_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Check status of a cloud scan."""
        if not self.hostedscan:
            return {'error': 'HostedScan not configured'}
        
        try:
            return self.hostedscan.get_scan_summary(scan_id)
        except Exception as e:
            logger.error(f"Failed to check scan status: {e}")
            return {'error': str(e)}
    
    def configure_cloud_auth(self, target_url: str, auth_type: str, 
                           auth_config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure authentication for cloud scanning."""
        if not self.hostedscan:
            return {'error': 'HostedScan not configured'}
        
        try:
            # Find or create target
            targets = self.hostedscan.list_targets()
            target = next((t for t in targets if t["url"] == target_url), None)
            
            if not target:
                target = self.hostedscan.create_target(
                    target_url, 
                    f"Hybrid scan target - {target_url}"
                )
            
            # Configure authentication
            return self.hostedscan.configure_auth(
                target["id"], 
                auth_type, 
                auth_config
            )
        except Exception as e:
            logger.error(f"Failed to configure auth: {e}")
            return {'error': str(e)}