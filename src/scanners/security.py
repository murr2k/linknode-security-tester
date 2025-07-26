"""Security scanner using OWASP ZAP."""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urlparse

from ..integrations.zap_client import ZAPClient
from ..core.config import settings

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Security vulnerability scanner."""
    
    def __init__(self, zap_client: Optional[ZAPClient] = None):
        """Initialize security scanner."""
        self.zap = zap_client or ZAPClient()
        self.scan_results = {}
        self.start_time = None
        self.end_time = None
    
    def scan(self, target_url: str, scan_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run comprehensive security scan."""
        logger.info(f"Starting security scan for {target_url}")
        self.start_time = datetime.now()
        
        # Default scan configuration
        config = {
            'spider': True,
            'ajax_spider': True,
            'passive_scan': True,
            'active_scan': True,
            'authentication': None,
            **((scan_config or {}))
        }
        
        results = {
            'target_url': target_url,
            'scan_start': self.start_time.isoformat(),
            'scan_config': config,
            'phases': {}
        }
        
        try:
            # Phase 1: Spider scan
            if config['spider']:
                logger.info("Phase 1: Running spider scan")
                spider_results = self.zap.spider_scan(
                    target_url,
                    max_depth=settings.scanning.max_depth
                )
                results['phases']['spider'] = spider_results
            
            # Phase 2: AJAX spider (for JavaScript-heavy sites)
            if config['ajax_spider']:
                logger.info("Phase 2: Running AJAX spider scan")
                # Use shorter timeout for AJAX spider to prevent hanging
                ajax_results = self.zap.ajax_spider_scan(target_url, max_duration=30)
                results['phases']['ajax_spider'] = ajax_results
                if ajax_results.get('timed_out'):
                    logger.warning("AJAX spider timed out, continuing with scan...")
            
            # Phase 3: Passive scan
            if config['passive_scan']:
                logger.info("Phase 3: Running passive scan")
                passive_results = self.zap.passive_scan(target_url)
                results['phases']['passive_scan'] = passive_results
            
            # Phase 4: Active scan
            if config['active_scan']:
                logger.info("Phase 4: Running active scan")
                active_results = self.zap.active_scan(target_url)
                results['phases']['active_scan'] = active_results
            
            # Compile all alerts
            all_alerts = self.zap.get_alerts(target_url)
            results['total_alerts'] = len(all_alerts)
            results['alerts_by_risk'] = self._categorize_alerts_by_risk(all_alerts)
            results['alerts'] = all_alerts
            
            # Calculate risk score
            results['risk_score'] = self._calculate_risk_score(all_alerts)
            
        except Exception as e:
            logger.error(f"Security scan failed: {e}")
            results['error'] = str(e)
        finally:
            self.end_time = datetime.now()
            results['scan_end'] = self.end_time.isoformat()
            results['scan_duration'] = (self.end_time - self.start_time).total_seconds()
            self.scan_results = results
        
        return results
    
    def _categorize_alerts_by_risk(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize alerts by risk level."""
        categories = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }
        
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            categories[risk] = categories.get(risk, 0) + 1
        
        return categories
    
    def _calculate_risk_score(self, alerts: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score (0-100)."""
        risk_weights = {
            'High': 10,
            'Medium': 5,
            'Low': 1,
            'Informational': 0.1
        }
        
        total_score = 0
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            confidence = alert.get('confidence', 'Medium')
            
            # Adjust weight based on confidence
            confidence_multiplier = {
                'High': 1.0,
                'Medium': 0.7,
                'Low': 0.4
            }.get(confidence, 0.5)
            
            weight = risk_weights.get(risk, 0)
            total_score += weight * confidence_multiplier
        
        # Normalize to 0-100 scale
        # Assuming 10 high-risk vulnerabilities = 100 score
        normalized_score = min(100, (total_score / 100) * 100)
        
        return round(normalized_score, 2)
    
    def scan_api(self, api_url: str, api_spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Scan REST API endpoints."""
        logger.info(f"Starting API security scan for {api_url}")
        
        results = {
            'api_url': api_url,
            'scan_type': 'api',
            'endpoints_tested': 0,
            'vulnerabilities': []
        }
        
        # If OpenAPI/Swagger spec provided, import it
        if api_spec:
            logger.info("Importing API specification")
            # TODO: Implement OpenAPI import
        
        # Run standard scan with API-specific rules
        scan_results = self.scan(api_url, {
            'spider': True,
            'ajax_spider': False,  # Not needed for APIs
            'passive_scan': True,
            'active_scan': True
        })
        
        # Filter for API-specific vulnerabilities
        api_alerts = []
        for alert in scan_results.get('alerts', []):
            # Check if alert is relevant to APIs
            if self._is_api_vulnerability(alert):
                api_alerts.append(alert)
        
        results['vulnerabilities'] = api_alerts
        results['total_vulnerabilities'] = len(api_alerts)
        
        return results
    
    def _is_api_vulnerability(self, alert: Dict[str, Any]) -> bool:
        """Check if vulnerability is API-specific."""
        api_relevant_alerts = [
            'SQL Injection',
            'Cross Site Scripting',
            'Path Traversal',
            'Remote File Inclusion',
            'Server Side Include',
            'Authentication Credentials Captured',
            'Weak Authentication Method',
            'Session ID in URL Rewrite',
            'Private IP Disclosure',
            'Sensitive Information in URL',
            'Information Disclosure',
            'Missing Anti-clickjacking Header',
            'X-Content-Type-Options Header Missing',
            'Strict-Transport-Security Header Not Set',
            'Content Security Policy (CSP) Header Not Set',
            'Missing CORS Header',
            'Insecure HTTP Method',
            'HTTP Parameter Pollution'
        ]
        
        alert_name = alert.get('name', '')
        return any(relevant in alert_name for relevant in api_relevant_alerts)
    
    def check_owasp_top_10(self, target_url: str) -> Dict[str, Any]:
        """Check for OWASP Top 10 vulnerabilities."""
        logger.info(f"Checking OWASP Top 10 for {target_url}")
        
        # Run comprehensive scan
        scan_results = self.scan(target_url)
        
        # Map alerts to OWASP Top 10 categories
        owasp_mapping = {
            'A01:2021 - Broken Access Control': [
                'Path Traversal', 'Directory Browsing', 'IDOR'
            ],
            'A02:2021 - Cryptographic Failures': [
                'Weak SSL', 'Insecure Hash', 'Cleartext Transmission'
            ],
            'A03:2021 - Injection': [
                'SQL Injection', 'Command Injection', 'LDAP Injection'
            ],
            'A04:2021 - Insecure Design': [
                'Business Logic', 'Design Flaw'
            ],
            'A05:2021 - Security Misconfiguration': [
                'Information Disclosure', 'Default Credentials', 'Verbose Error'
            ],
            'A06:2021 - Vulnerable Components': [
                'Vulnerable Library', 'Outdated Software'
            ],
            'A07:2021 - Authentication Failures': [
                'Weak Password', 'Session Fixation', 'Brute Force'
            ],
            'A08:2021 - Software and Data Integrity': [
                'Insecure Deserialization', 'Code Injection'
            ],
            'A09:2021 - Security Logging Failures': [
                'Insufficient Logging', 'Log Injection'
            ],
            'A10:2021 - SSRF': [
                'Server Side Request Forgery', 'SSRF'
            ]
        }
        
        results = {
            'target_url': target_url,
            'owasp_top_10_results': {}
        }
        
        # Categorize findings
        for category, patterns in owasp_mapping.items():
            category_alerts = []
            for alert in scan_results.get('alerts', []):
                alert_name = alert.get('name', '')
                if any(pattern.lower() in alert_name.lower() for pattern in patterns):
                    category_alerts.append(alert)
            
            results['owasp_top_10_results'][category] = {
                'found': len(category_alerts) > 0,
                'count': len(category_alerts),
                'alerts': category_alerts
            }
        
        return results
    
    def generate_remediation_plan(self) -> Dict[str, Any]:
        """Generate remediation plan based on scan results."""
        if not self.scan_results:
            return {'error': 'No scan results available'}
        
        alerts = self.scan_results.get('alerts', [])
        
        # Group alerts by type for remediation
        remediation_groups = {}
        for alert in alerts:
            alert_name = alert.get('name', 'Unknown')
            if alert_name not in remediation_groups:
                remediation_groups[alert_name] = {
                    'alerts': [],
                    'risk': alert.get('risk'),
                    'solution': alert.get('solution'),
                    'reference': alert.get('reference')
                }
            remediation_groups[alert_name]['alerts'].append(alert)
        
        # Prioritize by risk
        high_priority = []
        medium_priority = []
        low_priority = []
        
        for group_name, group_data in remediation_groups.items():
            priority_item = {
                'vulnerability': group_name,
                'occurrences': len(group_data['alerts']),
                'risk': group_data['risk'],
                'solution': group_data['solution'],
                'reference': group_data['reference'],
                'affected_urls': [alert['url'] for alert in group_data['alerts'][:5]]  # First 5
            }
            
            if group_data['risk'] == 'High':
                high_priority.append(priority_item)
            elif group_data['risk'] == 'Medium':
                medium_priority.append(priority_item)
            else:
                low_priority.append(priority_item)
        
        return {
            'high_priority': high_priority,
            'medium_priority': medium_priority,
            'low_priority': low_priority,
            'total_issues': len(alerts),
            'estimated_effort': self._estimate_remediation_effort(
                len(high_priority),
                len(medium_priority),
                len(low_priority)
            )
        }
    
    def _estimate_remediation_effort(self, high: int, medium: int, low: int) -> Dict[str, Any]:
        """Estimate remediation effort in hours."""
        # Rough estimates per issue type
        hours_per_issue = {
            'high': 8,
            'medium': 4,
            'low': 1
        }
        
        total_hours = (
            high * hours_per_issue['high'] +
            medium * hours_per_issue['medium'] +
            low * hours_per_issue['low']
        )
        
        return {
            'total_hours': total_hours,
            'total_days': round(total_hours / 8, 1),
            'breakdown': {
                'high_risk_hours': high * hours_per_issue['high'],
                'medium_risk_hours': medium * hours_per_issue['medium'],
                'low_risk_hours': low * hours_per_issue['low']
            }
        }