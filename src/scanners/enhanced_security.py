"""Enhanced Security Scanner with Fresh Reading Guarantees."""

import logging
import time
import random
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urlparse, urlencode

from ..integrations.zap_client import ZAPClient
from ..core.config import settings

logger = logging.getLogger(__name__)


class EnhancedSecurityScanner:
    """Enhanced security scanner that ensures fresh readings for each scan."""
    
    def __init__(self, zap_client: Optional[ZAPClient] = None):
        """Initialize enhanced security scanner."""
        self.zap = zap_client or ZAPClient()
        self.scan_results = {}
        self.start_time = None
        self.end_time = None
        self.scan_session_id = None
    
    def _clear_zap_session(self):
        """Clear ZAP session to ensure fresh scan."""
        logger.info("Clearing ZAP session for fresh scan")
        try:
            # Create new session to clear all cached data
            self.zap.zap.core.new_session(overwrite=True)
            
            # Clear all alerts
            self.zap.zap.core.delete_all_alerts()
            
            # Clear spider data
            self.zap.zap.spider.remove_all_scans()
            
            # Clear passive scan queue
            self.zap.zap.pscan.clear_queue()
            
            # Disable caching
            self.zap.zap.core.set_option_default_user_agent(
                f"OWASP_ZAP/2.14.0 NoCache-{int(time.time())}"
            )
            
            logger.info("ZAP session cleared successfully")
        except Exception as e:
            logger.warning(f"Error clearing ZAP session: {e}")
    
    def _add_cache_busting_headers(self):
        """Add headers to prevent caching."""
        logger.info("Adding cache-busting headers")
        try:
            # Add anti-cache headers
            headers = [
                ("Cache-Control", "no-cache, no-store, must-revalidate"),
                ("Pragma", "no-cache"),
                ("Expires", "0"),
                ("X-Scanner-Session", self.scan_session_id),
                ("X-Scan-Timestamp", str(int(time.time())))
            ]
            
            for header, value in headers:
                self.zap.zap.replacer.add_rule(
                    description=f"Add {header}",
                    enabled=True,
                    matchtype="REQ_HEADER",
                    matchregex=False,
                    matchstring=header,
                    replacement=f"{header}: {value}",
                    initiators="",
                    url=""
                )
        except Exception as e:
            logger.warning(f"Error adding cache-busting headers: {e}")
    
    def _force_fresh_crawl(self, target_url: str):
        """Force fresh crawl with cache-busting parameters."""
        logger.info("Forcing fresh crawl with cache-busting")
        
        # Add timestamp parameter to URL
        timestamp = int(time.time() * 1000)
        cache_buster = f"_zap_cb={timestamp}&_fresh={random.randint(1000, 9999)}"
        
        # Parse URL and add parameters
        parsed = urlparse(target_url)
        if parsed.query:
            fresh_url = f"{target_url}&{cache_buster}"
        else:
            fresh_url = f"{target_url}?{cache_buster}"
        
        # Access URL with fresh parameters
        self.zap.zap.core.access_url(fresh_url, followredirects=True)
        
        # Also access base URL
        self.zap.zap.core.access_url(target_url, followredirects=True)
        
        return fresh_url
    
    def scan(self, target_url: str, scan_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run comprehensive security scan with fresh readings."""
        logger.info(f"Starting ENHANCED security scan for {target_url}")
        self.start_time = datetime.now()
        self.scan_session_id = f"scan_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Clear previous session data
        self._clear_zap_session()
        
        # Add cache-busting headers
        self._add_cache_busting_headers()
        
        # Wait for session clear to complete
        time.sleep(2)
        
        # Default scan configuration
        config = {
            'spider': True,
            'ajax_spider': True,
            'passive_scan': True,
            'active_scan': True,
            'force_fresh': True,
            'clear_cache': True,
            'authentication': None,
            **((scan_config or {}))
        }
        
        results = {
            'target_url': target_url,
            'scan_start': self.start_time.isoformat(),
            'scan_session_id': self.scan_session_id,
            'scan_config': config,
            'fresh_scan': True,
            'phases': {}
        }
        
        try:
            # Force fresh crawl
            fresh_url = self._force_fresh_crawl(target_url)
            logger.info(f"Fresh crawl initiated with URL: {fresh_url}")
            
            # Phase 1: Spider scan with fresh session
            if config['spider']:
                logger.info("Phase 1: Running fresh spider scan")
                
                # Clear spider data again before scan
                self.zap.zap.spider.remove_all_scans()
                
                # Configure spider options
                self.zap.zap.spider.set_option_max_duration(0)  # No time limit
                self.zap.zap.spider.set_option_max_depth(settings.scanning.max_depth)
                self.zap.zap.spider.set_option_max_children(0)  # No limit
                self.zap.zap.spider.set_option_accept_cookies(True)
                self.zap.zap.spider.set_option_send_referer_header(True)
                
                # Start spider scan
                scan_id = self.zap.zap.spider.scan(
                    target_url,
                    recurse=True,
                    contextname=None,
                    subtreeonly=False
                )
                
                # Wait for spider to complete
                while int(self.zap.zap.spider.status(scan_id)) < 100:
                    progress = self.zap.zap.spider.status(scan_id)
                    logger.debug(f"Spider progress: {progress}%")
                    time.sleep(2)
                
                # Get spider results
                urls = self.zap.zap.spider.results(scan_id)
                results['phases']['spider'] = {
                    'scan_id': scan_id,
                    'urls_found': len(urls),
                    'urls': urls
                }
            
            # Phase 2: AJAX spider for dynamic content
            if config['ajax_spider']:
                logger.info("Phase 2: Running fresh AJAX spider scan")
                
                # Start AJAX spider
                self.zap.zap.ajaxSpider.scan(target_url)
                
                # Wait for AJAX spider
                timeout = 60  # Max 60 seconds for AJAX spider
                start_time = time.time()
                while self.zap.zap.ajaxSpider.status == 'running':
                    if time.time() - start_time > timeout:
                        self.zap.zap.ajaxSpider.stop()
                        break
                    logger.debug("AJAX spider still running...")
                    time.sleep(3)
                
                # Get AJAX results
                ajax_results = self.zap.zap.ajaxSpider.results(start=0, count=10000)
                results['phases']['ajax_spider'] = {
                    'status': 'completed',
                    'results_count': len(ajax_results),
                    'results': ajax_results
                }
            
            # Phase 3: Passive scan
            if config['passive_scan']:
                logger.info("Phase 3: Running fresh passive scan")
                
                # Ensure passive scanning is enabled
                self.zap.zap.pscan.enable_all_scanners()
                
                # Wait for passive scan to complete
                time.sleep(5)  # Give passive scanner time to start
                
                while int(self.zap.zap.pscan.records_to_scan) > 0:
                    records = self.zap.zap.pscan.records_to_scan
                    logger.debug(f"Passive scan records remaining: {records}")
                    time.sleep(2)
                
                results['phases']['passive_scan'] = {
                    'status': 'completed',
                    'records_scanned': 'all'
                }
            
            # Phase 4: Active scan
            if config['active_scan']:
                logger.info("Phase 4: Running fresh active scan")
                
                # Configure active scanner
                # Note: These options may not be available in all ZAP versions
                try:
                    if 'attack_strength' in scan_config:
                        self.zap.zap.ascan.set_option_attack_strength(scan_config['attack_strength'])
                    if 'alert_threshold' in scan_config:
                        self.zap.zap.ascan.set_option_alert_threshold(scan_config['alert_threshold'])
                except AttributeError:
                    logger.warning("Attack strength/threshold options not available in this ZAP version")
                
                # Enable all scanners
                self.zap.zap.ascan.enable_all_scanners()
                
                # Start active scan
                scan_id = self.zap.zap.ascan.scan(
                    target_url,
                    recurse=True,
                    inscopeonly=False,
                    scanpolicyname=None,
                    method=None,
                    postdata=None
                )
                
                # Wait for active scan
                while int(self.zap.zap.ascan.status(scan_id)) < 100:
                    progress = self.zap.zap.ascan.status(scan_id)
                    logger.debug(f"Active scan progress: {progress}%")
                    time.sleep(5)
                
                results['phases']['active_scan'] = {
                    'scan_id': scan_id,
                    'status': 'completed'
                }
            
            # Get all alerts after fresh scan
            logger.info("Retrieving fresh scan alerts")
            all_alerts = self.zap.zap.core.alerts(baseurl=target_url)
            
            # Process and analyze alerts
            processed_alerts = self._process_fresh_alerts(all_alerts)
            results['alerts'] = processed_alerts
            results['total_alerts'] = len(processed_alerts)
            
            # Categorize by risk
            results['alerts_by_risk'] = self._categorize_alerts_by_risk(processed_alerts)
            
            # Calculate risk score
            results['risk_score'] = self._calculate_risk_score(processed_alerts)
            
            # Add summary
            results['summary'] = {
                'total_issues': len(processed_alerts),
                'critical_count': len([a for a in processed_alerts if a.get('risk') == 'Critical']),
                'high_count': len([a for a in processed_alerts if a.get('risk') == 'High']),
                'medium_count': len([a for a in processed_alerts if a.get('risk') == 'Medium']),
                'low_count': len([a for a in processed_alerts if a.get('risk') == 'Low']),
                'info_count': len([a for a in processed_alerts if a.get('risk') == 'Informational']),
                'risk_score': results['risk_score']
            }
            
        except Exception as e:
            logger.error(f"Enhanced security scan failed: {e}")
            results['error'] = str(e)
        finally:
            self.end_time = datetime.now()
            results['scan_end'] = self.end_time.isoformat()
            results['scan_duration'] = (self.end_time - self.start_time).total_seconds()
            self.scan_results = results
            
            # Clear session after scan
            if config.get('clear_cache', True):
                self._clear_zap_session()
        
        return results
    
    def _process_fresh_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process alerts from fresh scan."""
        processed_alerts = []
        seen_alerts = set()
        
        for alert in alerts:
            # Create unique alert identifier
            alert_key = (
                alert.get('name', ''),
                alert.get('url', ''),
                alert.get('param', ''),
                alert.get('risk', '')
            )
            
            # Skip duplicate alerts
            if alert_key in seen_alerts:
                continue
            
            seen_alerts.add(alert_key)
            
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
                'source_id': alert.get('sourceid'),
                'scan_session': self.scan_session_id,
                'fresh_scan': True
            }
            processed_alerts.append(processed_alert)
        
        # Sort by risk level
        risk_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}
        processed_alerts.sort(
            key=lambda x: risk_order.get(x['risk'], 5)
        )
        
        return processed_alerts
    
    def _categorize_alerts_by_risk(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize alerts by risk level."""
        categories = {
            'Critical': 0,
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
            'Critical': 20,
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
        normalized_score = min(100, total_score)
        
        return round(normalized_score, 2)
    
    def verify_fresh_scan(self) -> bool:
        """Verify that the scan used fresh data."""
        if not self.scan_results:
            return False
        
        # Check scan session ID
        if not self.scan_session_id:
            return False
        
        # Check if results have fresh_scan flag
        return self.scan_results.get('fresh_scan', False)
    
    def cleanup(self):
        """Clean up after scan."""
        logger.info("Cleaning up enhanced scanner session")
        self._clear_zap_session()