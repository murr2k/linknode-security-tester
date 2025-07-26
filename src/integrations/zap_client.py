"""OWASP ZAP API client integration."""

import time
import requests
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import logging

from zapv2 import ZAPv2

from ..core.config import settings

logger = logging.getLogger(__name__)


class ZAPClient:
    """OWASP ZAP API client wrapper."""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize ZAP client."""
        self.api_key = api_key or settings.zap.api_key
        self.host = settings.zap.host
        self.port = settings.zap.port
        # Connect directly to ZAP API without proxy
        self.zap = ZAPv2(
            apikey=self.api_key,
            proxies={'http': settings.zap.base_url, 'https': settings.zap.base_url}
        )
        self._verify_connection()
    
    def _verify_connection(self):
        """Verify ZAP daemon is accessible."""
        try:
            version = self.zap.core.version
            logger.info(f"Connected to ZAP version: {version}")
        except Exception as e:
            logger.error(f"Failed to connect to ZAP: {e}")
            raise ConnectionError(
                f"Cannot connect to ZAP at {settings.zap.base_url}. "
                "Ensure ZAP daemon is running."
            )
    
    def spider_scan(self, target_url: str, max_depth: Optional[int] = None) -> Dict[str, Any]:
        """Run spider scan on target URL."""
        logger.info(f"Starting spider scan for {target_url}")
        
        # Configure spider
        if max_depth:
            self.zap.spider.set_option_max_depth(max_depth)
        
        # Start spider
        scan_id = self.zap.spider.scan(target_url)
        logger.info(f"Spider scan started with ID: {scan_id}")
        
        # Wait for spider to complete
        while int(self.zap.spider.status(scan_id)) < 100:
            progress = self.zap.spider.status(scan_id)
            logger.debug(f"Spider progress: {progress}%")
            time.sleep(2)
        
        # Get results
        urls = self.zap.spider.results(scan_id)
        logger.info(f"Spider found {len(urls)} URLs")
        
        return {
            'scan_id': scan_id,
            'urls_found': len(urls),
            'urls': urls
        }
    
    def ajax_spider_scan(self, target_url: str, max_duration: int = 60) -> Dict[str, Any]:
        """Run AJAX spider scan for JavaScript-heavy sites with timeout.
        
        Args:
            target_url: URL to scan
            max_duration: Maximum duration in seconds (default: 60)
        """
        logger.info(f"Starting AJAX spider scan for {target_url} (max {max_duration}s)")
        
        # Start AJAX spider
        self.zap.ajaxSpider.scan(target_url)
        
        # Wait for AJAX spider to complete with timeout
        start_time = time.time()
        while self.zap.ajaxSpider.status == 'running':
            elapsed = time.time() - start_time
            if elapsed > max_duration:
                logger.warning(f"AJAX spider scan timed out after {elapsed:.1f} seconds, stopping...")
                self.zap.ajaxSpider.stop()
                time.sleep(2)  # Give it time to stop
                break
            logger.debug(f"AJAX spider still running... ({elapsed:.1f}s)")
            time.sleep(5)
        
        # Get results
        try:
            results = self.zap.ajaxSpider.results(start=0, count=10000)
        except Exception as e:
            logger.warning(f"Failed to get AJAX spider results: {e}")
            results = []
            
        status = self.zap.ajaxSpider.status
        logger.info(f"AJAX spider {status}, found {len(results)} results")
        
        return {
            'status': status,
            'results_count': len(results),
            'results': results,
            'timed_out': status == 'stopped' and (time.time() - start_time) > max_duration
        }
    
    def passive_scan(self, target_url: str) -> Dict[str, Any]:
        """Run passive scan on target."""
        logger.info(f"Starting passive scan for {target_url}")
        
        # Access the URL to trigger passive scanning
        self.zap.urlopen(target_url)
        
        # Wait for passive scan to complete
        while int(self.zap.pscan.records_to_scan) > 0:
            records = self.zap.pscan.records_to_scan
            logger.debug(f"Passive scan records remaining: {records}")
            time.sleep(2)
        
        # Get alerts
        alerts = self.zap.core.alerts(baseurl=target_url)
        logger.info(f"Passive scan found {len(alerts)} alerts")
        
        return {
            'alerts_count': len(alerts),
            'alerts': self._process_alerts(alerts)
        }
    
    def active_scan(self, target_url: str, max_duration: int = 300) -> Dict[str, Any]:
        """Run active vulnerability scan with timeout."""
        logger.info(f"Starting active scan for {target_url} (max {max_duration}s)")
        
        # Configure scan to prevent getting stuck
        # Use the action API to set options
        try:
            # Reduce threads to avoid overwhelming the target
            requests.get(f'http://{self.host}:{self.port}/JSON/ascan/action/setOptionThreadPerHost/', 
                        params={'Integer': '4', 'apikey': self.api_key})
            
            # Set max scan duration per rule (2 minutes to be safer)
            requests.get(f'http://{self.host}:{self.port}/JSON/ascan/action/setOptionMaxRuleDurationInMins/', 
                        params={'Integer': '2', 'apikey': self.api_key})
            
            # Set delay between requests to be respectful
            requests.get(f'http://{self.host}:{self.port}/JSON/ascan/action/setOptionDelayInMs/', 
                        params={'Integer': '100', 'apikey': self.api_key})
            
            logger.info("Active scan options configured successfully")
        except Exception as e:
            logger.warning(f"Failed to set some scan options: {e}")
        
        # Create a custom scan policy for this scan
        policy_name = f"fast_scan_{int(time.time())}"
        
        # Clone the default policy
        self.zap.ascan.add_scan_policy(policy_name)
        
        # Disable extremely slow and problematic scanners
        slow_scanners = [
            '40018',  # SQL Injection (causes huge payloads and hangs)
            '40009',  # Server Side Include
            '30003',  # Integer Overflow Error
            '90020',  # Remote OS Command Injection
            '0',      # Directory Browsing (can be very slow)
            '42',     # Source Code Disclosure - SVN (slow)
            '40014',  # Cross Site Scripting (Persistent) - Prime
            '40016',  # Cross Site Scripting (Persistent) - Spider
            '40017',  # Cross Site Scripting (Persistent) - Prime
            '20010',  # Anti CSRF Tokens Scanner (can be slow)
            '90023',  # XML External Entity Attack (can cause hangs)
        ]
        
        for scanner_id in slow_scanners:
            try:
                self.zap.ascan.disable_scanners(scanner_id, policy_name)
            except:
                pass
        
        # Start active scan with custom policy
        scan_id = self.zap.ascan.scan(target_url, scanpolicyname=policy_name)
            
        logger.info(f"Active scan started with ID: {scan_id}")
        
        # Wait for active scan to complete with timeout
        start_time = time.time()
        last_progress = 0
        stuck_count = 0
        
        while int(self.zap.ascan.status(scan_id)) < 100:
            progress = int(self.zap.ascan.status(scan_id))
            elapsed = time.time() - start_time
            
            # Check if scan is stuck - be more aggressive
            if progress == last_progress:
                stuck_count += 1
                if stuck_count > 6:  # Stuck for 30 seconds
                    logger.warning(f"Active scan appears stuck at {progress}% after {elapsed:.1f}s, stopping...")
                    self.zap.ascan.stop(scan_id)
                    break
            else:
                stuck_count = 0
                last_progress = progress
            
            # Also check absolute timeout - don't let it run more than 2 minutes
            if elapsed > 120:
                logger.warning(f"Active scan timeout after {elapsed:.1f}s, stopping...")
                self.zap.ascan.stop(scan_id)
                break
            
            logger.debug(f"Active scan progress: {progress}% (elapsed: {elapsed:.1f}s)")
                
            time.sleep(5)
        
        # Get alerts
        alerts = self.zap.core.alerts(baseurl=target_url)
        logger.info(f"Active scan found {len(alerts)} alerts")
        
        return {
            'scan_id': scan_id,
            'alerts_count': len(alerts),
            'alerts': self._process_alerts(alerts),
            'completed': int(self.zap.ascan.status(scan_id)) == 100,
            'final_progress': int(self.zap.ascan.status(scan_id))
        }
    
    def get_alerts(self, target_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all alerts, optionally filtered by URL."""
        if target_url:
            alerts = self.zap.core.alerts(baseurl=target_url)
        else:
            alerts = self.zap.core.alerts()
        
        return self._process_alerts(alerts)
    
    def _process_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and categorize alerts."""
        processed_alerts = []
        
        for alert in alerts:
            processed_alert = {
                'id': alert.get('alertRef'),
                'name': alert.get('name'),
                'risk': alert.get('risk'),
                'confidence': alert.get('confidence'),
                'description': alert.get('description'),
                'solution': alert.get('solution'),
                'reference': alert.get('reference'),
                'url': alert.get('url'),
                'method': alert.get('method'),
                'param': alert.get('param'),
                'attack': alert.get('attack'),
                'evidence': alert.get('evidence'),
                'other': alert.get('other'),
                'cwe_id': alert.get('cweid'),
                'wasc_id': alert.get('wascid'),
                'source_id': alert.get('sourceid')
            }
            processed_alerts.append(processed_alert)
        
        # Sort by risk level
        risk_order = {'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3}
        processed_alerts.sort(
            key=lambda x: risk_order.get(x['risk'], 4)
        )
        
        return processed_alerts
    
    def set_authentication(self, context_name: str, auth_config: Dict[str, Any]):
        """Configure authentication for scanning."""
        logger.info(f"Setting up authentication for context: {context_name}")
        
        # Create context
        context_id = self.zap.context.new_context(context_name)
        
        # Configure authentication based on type
        auth_type = auth_config.get('type', 'form')
        
        if auth_type == 'form':
            self._setup_form_auth(context_id, auth_config)
        elif auth_type == 'json':
            self._setup_json_auth(context_id, auth_config)
        elif auth_type == 'script':
            self._setup_script_auth(context_id, auth_config)
        
        return context_id
    
    def _setup_form_auth(self, context_id: str, auth_config: Dict[str, Any]):
        """Setup form-based authentication."""
        login_url = auth_config.get('login_url')
        username_param = auth_config.get('username_param', 'username')
        password_param = auth_config.get('password_param', 'password')
        
        # Set authentication method
        self.zap.authentication.set_authentication_method(
            contextid=context_id,
            authmethodname='formBasedAuthentication',
            authmethodconfigparams=f'loginUrl={login_url}&loginRequestData={username_param}={{%username%}}&{password_param}={{%password%}}'
        )
        
        # Set logged in/out indicators
        if 'logged_in_indicator' in auth_config:
            self.zap.authentication.set_logged_in_indicator(
                context_id,
                auth_config['logged_in_indicator']
            )
        
        if 'logged_out_indicator' in auth_config:
            self.zap.authentication.set_logged_out_indicator(
                context_id,
                auth_config['logged_out_indicator']
            )
    
    def _setup_json_auth(self, context_id: str, auth_config: Dict[str, Any]):
        """Setup JSON-based authentication."""
        login_url = auth_config.get('login_url')
        request_body = auth_config.get('request_body', '{"username":"{%username%}","password":"{%password%}"}')
        
        self.zap.authentication.set_authentication_method(
            contextid=context_id,
            authmethodname='jsonBasedAuthentication',
            authmethodconfigparams=f'loginUrl={login_url}&loginRequestData={request_body}'
        )
    
    def _setup_script_auth(self, context_id: str, auth_config: Dict[str, Any]):
        """Setup script-based authentication."""
        script_name = auth_config.get('script_name')
        
        self.zap.authentication.set_authentication_method(
            contextid=context_id,
            authmethodname='scriptBasedAuthentication',
            authmethodconfigparams=f'scriptName={script_name}'
        )
    
    def generate_report(self, report_type: str = 'html') -> bytes:
        """Generate scan report."""
        logger.info(f"Generating {report_type} report")
        
        if report_type == 'html':
            return self.zap.core.htmlreport()
        elif report_type == 'xml':
            return self.zap.core.xmlreport()
        elif report_type == 'json':
            return self.zap.core.jsonreport()
        elif report_type == 'md':
            return self.zap.core.mdreport()
        else:
            raise ValueError(f"Unsupported report type: {report_type}")
    
    def cleanup(self):
        """Clean up ZAP session."""
        logger.info("Cleaning up ZAP session")
        self.zap.core.new_session()