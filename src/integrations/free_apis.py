"""Free security API integrations for cost-effective scanning."""

import logging
import requests
import time
import json
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class MozillaObservatoryClient:
    """Mozilla Observatory API client for free security header analysis."""
    
    def __init__(self):
        self.base_url = "https://http-observatory.security.mozilla.org/api/v1"
        self.session = requests.Session()
    
    def scan(self, target_url: str, rescan: bool = False) -> Dict[str, Any]:
        """Run Mozilla Observatory scan.
        
        Args:
            target_url: URL to scan
            rescan: Force a fresh scan
            
        Returns:
            Scan results with security header analysis
        """
        # Extract hostname
        parsed = urlparse(target_url)
        hostname = parsed.netloc or parsed.path
        
        logger.info(f"Starting Mozilla Observatory scan for {hostname}")
        
        # Start or retrieve scan
        params = {
            'host': hostname,
            'hidden': 'true',
            'rescan': 'true' if rescan else 'false'
        }
        
        try:
            # Initiate scan
            response = self.session.post(f"{self.base_url}/analyze", params=params)
            response.raise_for_status()
            scan_data = response.json()
            
            # Wait for scan to complete
            scan_id = scan_data.get('scan_id')
            state = scan_data.get('state')
            
            while state in ['PENDING', 'RUNNING']:
                time.sleep(2)
                response = self.session.get(
                    f"{self.base_url}/analyze",
                    params={'host': hostname}
                )
                scan_data = response.json()
                state = scan_data.get('state')
            
            # Get detailed results
            results = {
                'scan_data': scan_data,
                'grade': scan_data.get('grade'),
                'score': scan_data.get('score'),
                'tests': self._get_test_results(hostname)
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Mozilla Observatory scan failed: {e}")
            return {'error': str(e)}
    
    def _get_test_results(self, hostname: str) -> Dict[str, Any]:
        """Get detailed test results."""
        try:
            response = self.session.get(
                f"{self.base_url}/getScanResults",
                params={'scan': hostname}
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get test results: {e}")
            return {}


class SSLLabsClient:
    """SSL Labs API client for free SSL/TLS analysis."""
    
    def __init__(self):
        self.base_url = "https://api.ssllabs.com/api/v3"
        self.session = requests.Session()
    
    def scan(self, target_url: str, publish: bool = False) -> Dict[str, Any]:
        """Run SSL Labs scan.
        
        Args:
            target_url: URL to scan
            publish: Whether to publish results on SSL Labs
            
        Returns:
            SSL/TLS analysis results
        """
        # Extract hostname
        parsed = urlparse(target_url)
        hostname = parsed.netloc or parsed.path
        
        logger.info(f"Starting SSL Labs scan for {hostname}")
        
        params = {
            'host': hostname,
            'publish': 'on' if publish else 'off',
            'all': 'on'
        }
        
        try:
            # Start new scan
            response = self.session.get(
                f"{self.base_url}/analyze",
                params={**params, 'startNew': 'on'}
            )
            response.raise_for_status()
            
            # Poll for results
            while True:
                response = self.session.get(
                    f"{self.base_url}/analyze",
                    params=params
                )
                data = response.json()
                
                status = data.get('status')
                if status == 'READY':
                    return self._process_results(data)
                elif status == 'ERROR':
                    return {'error': data.get('statusMessage', 'Unknown error')}
                
                # Wait before next poll
                time.sleep(10)
                
        except Exception as e:
            logger.error(f"SSL Labs scan failed: {e}")
            return {'error': str(e)}
    
    def _process_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process SSL Labs results."""
        results = {
            'host': data.get('host'),
            'grade': None,
            'endpoints': []
        }
        
        for endpoint in data.get('endpoints', []):
            endpoint_data = {
                'ip': endpoint.get('ipAddress'),
                'grade': endpoint.get('grade'),
                'has_warnings': endpoint.get('hasWarnings', False),
                'issues': []
            }
            
            # Extract key issues
            details = endpoint.get('details', {})
            
            # Check for vulnerabilities
            if details.get('heartbleed'):
                endpoint_data['issues'].append('Heartbleed vulnerability')
            if details.get('poodle'):
                endpoint_data['issues'].append('POODLE vulnerability')
            if details.get('freak'):
                endpoint_data['issues'].append('FREAK vulnerability')
            
            # Check protocol support
            protocols = details.get('protocols', [])
            for protocol in protocols:
                if protocol.get('name') == 'SSL' and protocol.get('version') in ['2.0', '3.0']:
                    endpoint_data['issues'].append(f"Insecure {protocol.get('name')} {protocol.get('version')} supported")
            
            results['endpoints'].append(endpoint_data)
            
            # Use first endpoint grade as overall grade
            if not results['grade'] and endpoint_data['grade']:
                results['grade'] = endpoint_data['grade']
        
        return results


class SecurityHeadersClient:
    """SecurityHeaders.com unofficial API client."""
    
    def __init__(self):
        self.base_url = "https://securityheaders.com"
        self.session = requests.Session()
    
    def scan(self, target_url: str) -> Dict[str, Any]:
        """Check security headers.
        
        Args:
            target_url: URL to check
            
        Returns:
            Security header analysis
        """
        logger.info(f"Checking security headers for {target_url}")
        
        try:
            # Make direct request to check headers
            response = requests.get(target_url, timeout=10)
            headers = dict(response.headers)
            
            # Analyze headers
            results = {
                'url': target_url,
                'grade': self._calculate_grade(headers),
                'headers_present': [],
                'headers_missing': [],
                'warnings': []
            }
            
            # Check for security headers
            security_headers = {
                'Content-Security-Policy': 'CSP protects against XSS attacks',
                'X-Frame-Options': 'Prevents clickjacking attacks',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'Strict-Transport-Security': 'Forces HTTPS connections',
                'Referrer-Policy': 'Controls referrer information',
                'Permissions-Policy': 'Controls browser features',
                'X-XSS-Protection': 'Legacy XSS protection (deprecated)'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    results['headers_present'].append({
                        'name': header,
                        'value': headers[header],
                        'description': description
                    })
                else:
                    results['headers_missing'].append({
                        'name': header,
                        'description': description
                    })
            
            # Check for problematic headers
            if 'Server' in headers:
                results['warnings'].append({
                    'header': 'Server',
                    'value': headers['Server'],
                    'issue': 'Server version disclosure'
                })
            
            if 'X-Powered-By' in headers:
                results['warnings'].append({
                    'header': 'X-Powered-By',
                    'value': headers['X-Powered-By'],
                    'issue': 'Technology disclosure'
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Security headers check failed: {e}")
            return {'error': str(e)}
    
    def _calculate_grade(self, headers: Dict[str, str]) -> str:
        """Calculate security grade based on headers."""
        score = 0
        
        # Critical headers (20 points each)
        critical_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'Strict-Transport-Security'
        ]
        
        for header in critical_headers:
            if header in headers:
                score += 20
        
        # Important headers (10 points each)
        important_headers = [
            'X-Content-Type-Options',
            'Referrer-Policy',
            'Permissions-Policy'
        ]
        
        for header in important_headers:
            if header in headers:
                score += 10
        
        # Deduct for bad headers
        if 'Server' in headers:
            score -= 5
        if 'X-Powered-By' in headers:
            score -= 5
        
        # Convert to grade
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'


class FreeAPIAggregator:
    """Aggregates results from multiple free security APIs."""
    
    def __init__(self):
        self.mozilla = MozillaObservatoryClient()
        self.ssl_labs = SSLLabsClient()
        self.security_headers = SecurityHeadersClient()
    
    def scan_all(self, target_url: str) -> Dict[str, Any]:
        """Run all free security scans.
        
        Args:
            target_url: URL to scan
            
        Returns:
            Aggregated results from all free APIs
        """
        logger.info(f"Running free API security scans for {target_url}")
        
        results = {
            'target_url': target_url,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'mozilla_observatory': None,
            'ssl_labs': None,
            'security_headers': None,
            'summary': {}
        }
        
        # Run scans (could be parallelized)
        results['security_headers'] = self.security_headers.scan(target_url)
        results['mozilla_observatory'] = self.mozilla.scan(target_url)
        
        # SSL Labs only for HTTPS
        if target_url.startswith('https://'):
            results['ssl_labs'] = self.ssl_labs.scan(target_url)
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary from all scan results."""
        summary = {
            'overall_grade': 'F',
            'main_issues': [],
            'security_headers': {
                'present': 0,
                'missing': 0
            },
            'ssl_grade': None
        }
        
        # Process Mozilla Observatory results
        if results.get('mozilla_observatory') and 'grade' in results['mozilla_observatory']:
            mozilla_grade = results['mozilla_observatory']['grade']
            summary['mozilla_grade'] = mozilla_grade
        
        # Process security headers
        if results.get('security_headers') and 'headers_present' in results['security_headers']:
            headers_data = results['security_headers']
            summary['security_headers']['present'] = len(headers_data.get('headers_present', []))
            summary['security_headers']['missing'] = len(headers_data.get('headers_missing', []))
            summary['headers_grade'] = headers_data.get('grade', 'F')
        
        # Process SSL Labs
        if results.get('ssl_labs') and 'grade' in results['ssl_labs']:
            summary['ssl_grade'] = results['ssl_labs']['grade']
        
        # Calculate overall grade (simple average)
        grades = []
        if 'mozilla_grade' in summary:
            grades.append(summary['mozilla_grade'])
        if 'headers_grade' in summary:
            grades.append(summary['headers_grade'])
        if summary['ssl_grade']:
            grades.append(summary['ssl_grade'])
        
        if grades:
            # Simple grade averaging (could be improved)
            grade_values = {'A+': 4.3, 'A': 4.0, 'B': 3.0, 'C': 2.0, 'D': 1.0, 'F': 0.0}
            avg_value = sum(grade_values.get(g, 0) for g in grades) / len(grades)
            
            if avg_value >= 4.0:
                summary['overall_grade'] = 'A'
            elif avg_value >= 3.0:
                summary['overall_grade'] = 'B'
            elif avg_value >= 2.0:
                summary['overall_grade'] = 'C'
            elif avg_value >= 1.0:
                summary['overall_grade'] = 'D'
            else:
                summary['overall_grade'] = 'F'
        
        # Compile main issues
        if summary['security_headers']['missing'] > 3:
            summary['main_issues'].append(f"{summary['security_headers']['missing']} security headers missing")
        
        if summary.get('ssl_grade', 'A') < 'B':
            summary['main_issues'].append("SSL/TLS configuration needs improvement")
        
        return summary