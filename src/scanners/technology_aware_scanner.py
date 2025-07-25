"""Technology-aware security scanner using WhatWeb and Nikto for intelligent scanning."""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..integrations.whatweb_client import WhatWebClient
from ..integrations.nikto_client import NiktoClient
from ..integrations.zap_client import ZAPClient
from ..integrations.free_apis import FreeAPIAggregator
from .enhanced_security import EnhancedSecurityScanner

logger = logging.getLogger(__name__)


class TechnologyAwareScanner:
    """Scanner that uses technology detection to optimize security testing."""
    
    def __init__(self, zap_client: Optional[ZAPClient] = None):
        """Initialize technology-aware scanner.
        
        Args:
            zap_client: Optional ZAP client instance
        """
        self.whatweb = None
        self.nikto = None
        self.zap_scanner = EnhancedSecurityScanner(zap_client)
        self.free_apis = FreeAPIAggregator()
        
        # Try to initialize reconnaissance tools
        try:
            self.whatweb = WhatWebClient()
            logger.info("WhatWeb integration enabled")
        except Exception as e:
            logger.warning(f"WhatWeb not available: {e}")
        
        try:
            self.nikto = NiktoClient()
            logger.info("Nikto integration enabled")
        except Exception as e:
            logger.warning(f"Nikto not available: {e}")
    
    def scan(self, target_url: str, scan_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run technology-aware security scan.
        
        Args:
            target_url: URL to scan
            scan_config: Scan configuration options
            
        Returns:
            Comprehensive scan results
        """
        logger.info(f"Starting technology-aware scan for {target_url}")
        start_time = datetime.now()
        
        config = {
            'run_whatweb': True,
            'run_nikto': True,
            'run_zap': True,
            'run_free_apis': True,
            'parallel_execution': True,
            **((scan_config or {}))
        }
        
        results = {
            'target_url': target_url,
            'scan_type': 'technology_aware',
            'scan_start': start_time.isoformat(),
            'scan_config': config,
            'phases': {}
        }
        
        # Phase 1: Technology Detection
        if config['run_whatweb'] and self.whatweb:
            logger.info("Phase 1: Technology detection with WhatWeb")
            whatweb_results = self._run_whatweb(target_url)
            results['phases']['technology_detection'] = whatweb_results
            
            # Use technology info to configure other scanners
            tech_stack = whatweb_results.get('technologies', {})
            scan_strategy = self._determine_scan_strategy(tech_stack)
            results['scan_strategy'] = scan_strategy
        else:
            scan_strategy = self._get_default_strategy()
        
        # Phase 2: Parallel reconnaissance and scanning
        if config['parallel_execution']:
            results = self._run_parallel_scans(target_url, scan_strategy, config, results)
        else:
            results = self._run_sequential_scans(target_url, scan_strategy, config, results)
        
        # Phase 3: Result aggregation and analysis
        results['analysis'] = self._analyze_results(results)
        
        # Phase 4: Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        end_time = datetime.now()
        results['scan_end'] = end_time.isoformat()
        results['scan_duration'] = (end_time - start_time).total_seconds()
        
        return results
    
    def _run_whatweb(self, target_url: str) -> Dict[str, Any]:
        """Run WhatWeb technology detection."""
        try:
            # Start with passive scan
            results = self.whatweb.quick_scan(target_url)
            
            # If minimal results, try aggressive scan
            if len(results.get('technologies', {})) < 3:
                logger.info("Running aggressive WhatWeb scan for better detection")
                results = self.whatweb.deep_scan(target_url)
            
            return results
        except Exception as e:
            logger.error(f"WhatWeb scan failed: {e}")
            return {'error': str(e)}
    
    def _determine_scan_strategy(self, tech_stack: Dict[str, Any]) -> Dict[str, Any]:
        """Determine optimal scan strategy based on detected technologies."""
        strategy = {
            'focus_areas': [],
            'nikto_tuning': '123b',  # Default: files, misconfig, disclosure, software
            'zap_config': {},
            'priority_checks': []
        }
        
        # Check for specific technologies and adjust strategy
        tech_names = [tech.lower() for tech in tech_stack.keys()]
        
        # Web servers
        if any(server in tech_names for server in ['apache', 'nginx', 'iis']):
            strategy['focus_areas'].append('server_configuration')
            strategy['nikto_tuning'] += '6'  # Add DoS checks for servers
        
        # CMS detection
        if any(cms in tech_names for cms in ['wordpress', 'joomla', 'drupal']):
            strategy['focus_areas'].append('cms_vulnerabilities')
            strategy['priority_checks'].append('default_credentials')
            strategy['zap_config']['spider_max_depth'] = 10  # Deeper spidering for CMS
            
            if 'wordpress' in tech_names:
                strategy['priority_checks'].append('wp_vulnerabilities')
        
        # Programming languages
        if any(lang in tech_names for lang in ['php', 'asp', 'jsp']):
            strategy['focus_areas'].append('injection_vulnerabilities')
            strategy['nikto_tuning'] += '489'  # XSS, Command, SQL injection
        
        # Databases
        if any(db in tech_names for db in ['mysql', 'postgresql', 'mssql', 'mongodb']):
            strategy['focus_areas'].append('database_security')
            strategy['priority_checks'].append('sql_injection')
            strategy['zap_config']['ascan_policy'] = 'SQL-Injection'
        
        # JavaScript frameworks
        if any(js in tech_names for js in ['jquery', 'angular', 'react', 'vue']):
            strategy['focus_areas'].append('client_side_security')
            strategy['zap_config']['ajax_spider'] = True
            
            # Check for vulnerable jQuery versions
            for tech_name, tech_info in tech_stack.items():
                if 'jquery' in tech_name.lower():
                    version = tech_info.get('version')
                    if version and version.startswith(('1.', '2.')):
                        strategy['priority_checks'].append('jquery_vulnerabilities')
        
        # Security services
        if any(sec in tech_names for sec in ['cloudflare', 'sucuri', 'wordfence']):
            strategy['focus_areas'].append('waf_bypass')
            logger.info("WAF/Security service detected - adjusting scan strategy")
        
        return strategy
    
    def _get_default_strategy(self) -> Dict[str, Any]:
        """Get default scan strategy when no technology info available."""
        return {
            'focus_areas': ['general_security'],
            'nikto_tuning': '123b',
            'zap_config': {
                'spider': True,
                'ajax_spider': True,
                'passive_scan': True,
                'active_scan': True
            },
            'priority_checks': []
        }
    
    def _run_parallel_scans(self, target_url: str, strategy: Dict[str, Any], 
                           config: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
        """Run scans in parallel for faster results."""
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            
            # Submit Nikto scan
            if config['run_nikto'] and self.nikto:
                futures['nikto'] = executor.submit(
                    self._run_nikto, target_url, strategy
                )
            
            # Submit ZAP scan
            if config['run_zap']:
                futures['zap'] = executor.submit(
                    self._run_zap, target_url, strategy
                )
            
            # Submit free API scans
            if config['run_free_apis']:
                futures['free_apis'] = executor.submit(
                    self.free_apis.scan_all, target_url
                )
            
            # Collect results as they complete
            for future_name, future in futures.items():
                try:
                    result = future.result(timeout=600)  # 10 minute timeout
                    results['phases'][future_name] = result
                except Exception as e:
                    logger.error(f"{future_name} scan failed: {e}")
                    results['phases'][future_name] = {'error': str(e)}
        
        return results
    
    def _run_sequential_scans(self, target_url: str, strategy: Dict[str, Any],
                             config: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
        """Run scans sequentially."""
        # Run Nikto
        if config['run_nikto'] and self.nikto:
            logger.info("Phase 2a: Server scanning with Nikto")
            results['phases']['nikto'] = self._run_nikto(target_url, strategy)
        
        # Run ZAP
        if config['run_zap']:
            logger.info("Phase 2b: Application scanning with ZAP")
            results['phases']['zap'] = self._run_zap(target_url, strategy)
        
        # Run free APIs
        if config['run_free_apis']:
            logger.info("Phase 2c: Cloud API scanning")
            results['phases']['free_apis'] = self.free_apis.scan_all(target_url)
        
        return results
    
    def _run_nikto(self, target_url: str, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Run Nikto scan with strategy-based configuration."""
        try:
            return self.nikto.scan(
                target_url,
                tuning=strategy['nikto_tuning'],
                timeout=300  # 5 minutes
            )
        except Exception as e:
            logger.error(f"Nikto scan failed: {e}")
            return {'error': str(e)}
    
    def _run_zap(self, target_url: str, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Run ZAP scan with strategy-based configuration."""
        try:
            zap_config = {
                'spider': True,
                'ajax_spider': strategy['zap_config'].get('ajax_spider', False),
                'passive_scan': True,
                'active_scan': True,
                'force_fresh': True,
                **strategy['zap_config']
            }
            
            return self.zap_scanner.scan(target_url, zap_config)
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            return {'error': str(e)}
    
    def _analyze_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze all scan results for patterns and correlations."""
        analysis = {
            'total_vulnerabilities': 0,
            'unique_vulnerabilities': [],
            'confirmed_vulnerabilities': [],
            'technology_risks': [],
            'attack_surface': []
        }
        
        # Collect all vulnerabilities
        all_vulns = []
        
        # From WhatWeb
        if 'technology_detection' in results['phases']:
            whatweb = results['phases']['technology_detection']
            all_vulns.extend(whatweb.get('vulnerabilities', []))
            
            # Add technology-specific risks
            for tech_name, tech_info in whatweb.get('technologies', {}).items():
                version = tech_info.get('version')
                if version:
                    analysis['technology_risks'].append({
                        'technology': tech_name,
                        'version': version,
                        'risk': self._assess_technology_risk(tech_name, version)
                    })
        
        # From Nikto
        if 'nikto' in results['phases']:
            nikto = results['phases']['nikto']
            for vuln in nikto.get('vulnerabilities', []):
                all_vulns.append({
                    'source': 'nikto',
                    'description': vuln.get('description'),
                    'severity': vuln.get('severity'),
                    'url': vuln.get('url')
                })
        
        # From ZAP
        if 'zap' in results['phases']:
            zap = results['phases']['zap']
            for alert in zap.get('alerts', []):
                all_vulns.append({
                    'source': 'zap',
                    'description': alert.get('name'),
                    'severity': alert.get('risk', '').lower(),
                    'url': alert.get('url')
                })
        
        # Deduplicate and correlate
        analysis['total_vulnerabilities'] = len(all_vulns)
        
        # Find confirmed vulnerabilities (found by multiple tools)
        vuln_signatures = {}
        for vuln in all_vulns:
            # Create signature for deduplication
            sig = f"{vuln['description'][:50]}|{vuln.get('url', '')}"
            if sig in vuln_signatures:
                vuln_signatures[sig]['sources'].append(vuln['source'])
                if len(vuln_signatures[sig]['sources']) > 1:
                    analysis['confirmed_vulnerabilities'].append(vuln_signatures[sig])
            else:
                vuln_signatures[sig] = {
                    'vulnerability': vuln,
                    'sources': [vuln['source']]
                }
        
        analysis['unique_vulnerabilities'] = list(vuln_signatures.values())
        
        return analysis
    
    def _assess_technology_risk(self, tech_name: str, version: str) -> str:
        """Assess risk level of a technology version."""
        # Simple version checking - could be enhanced with CVE database
        tech_lower = tech_name.lower()
        
        # Check for EOL versions
        if 'php' in tech_lower and version.startswith(('5.', '7.0', '7.1', '7.2')):
            return 'high'
        elif 'apache' in tech_lower and version.startswith(('2.0', '2.2')):
            return 'high'
        elif 'wordpress' in tech_lower and version.startswith(('3.', '4.')):
            return 'medium'
        elif 'jquery' in tech_lower and version.startswith('1.'):
            return 'medium'
        
        return 'low'
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on scan results."""
        recommendations = []
        analysis = results.get('analysis', {})
        
        # Technology-based recommendations
        for tech_risk in analysis.get('technology_risks', []):
            if tech_risk['risk'] in ['high', 'medium']:
                recommendations.append({
                    'priority': 'high' if tech_risk['risk'] == 'high' else 'medium',
                    'category': 'version_update',
                    'description': f"Update {tech_risk['technology']} from version {tech_risk['version']}",
                    'impact': 'Addresses known vulnerabilities in outdated software'
                })
        
        # Confirmed vulnerability recommendations
        for confirmed in analysis.get('confirmed_vulnerabilities', []):
            vuln = confirmed['vulnerability']
            recommendations.append({
                'priority': 'high',
                'category': 'confirmed_vulnerability',
                'description': vuln['description'],
                'confidence': 'high',
                'found_by': confirmed['sources']
            })
        
        # Strategy-based recommendations
        strategy = results.get('scan_strategy', {})
        if 'cms_vulnerabilities' in strategy.get('focus_areas', []):
            recommendations.append({
                'priority': 'medium',
                'category': 'configuration',
                'description': 'Implement CMS hardening best practices',
                'details': [
                    'Remove version disclosure',
                    'Disable user enumeration',
                    'Implement strong authentication',
                    'Keep plugins/themes updated'
                ]
            })
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        return recommendations
    
    def get_quick_assessment(self, target_url: str) -> Dict[str, Any]:
        """Get a quick security assessment using only fast scanners."""
        return self.scan(target_url, {
            'run_whatweb': True,
            'run_nikto': True,
            'run_zap': False,  # Skip time-consuming ZAP scan
            'run_free_apis': True
        })