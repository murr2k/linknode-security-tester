"""WhatWeb technology detection integration."""

import logging
import json
import subprocess
import re
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class WhatWebClient:
    """Client for WhatWeb technology detection tool."""
    
    def __init__(self, whatweb_path: Optional[str] = None):
        """Initialize WhatWeb client.
        
        Args:
            whatweb_path: Path to whatweb binary (defaults to system PATH)
        """
        self.whatweb_path = whatweb_path or "whatweb"
        self._verify_installation()
    
    def _verify_installation(self):
        """Verify WhatWeb is installed and accessible."""
        try:
            result = subprocess.run(
                [self.whatweb_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError(f"WhatWeb not found at {self.whatweb_path}")
            
            version_match = re.search(r'WhatWeb version ([\d.]+)', result.stdout)
            if version_match:
                logger.info(f"WhatWeb version {version_match.group(1)} detected")
        except Exception as e:
            logger.error(f"WhatWeb verification failed: {e}")
            raise RuntimeError(
                "WhatWeb not installed. Install with: "
                "git clone https://github.com/urbanadventurer/WhatWeb.git"
            )
    
    def scan(self, target_url: str, aggression: int = 1, 
             plugins: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run WhatWeb technology detection.
        
        Args:
            target_url: URL to scan
            aggression: Scan aggression level (1-4)
                1 = Stealthy (passive)
                2 = Unused
                3 = Aggressive (more HTTP requests)
                4 = Heavy (many HTTP requests)
            plugins: Specific plugins to use (None = all)
            
        Returns:
            Technology detection results
        """
        logger.info(f"Running WhatWeb scan on {target_url} (aggression={aggression})")
        
        # Build command
        cmd = [
            self.whatweb_path,
            target_url,
            f"--aggression={aggression}",
            "--log-json=-",  # Output JSON to stdout
            "--no-errors"    # Suppress error messages
        ]
        
        # Add specific plugins if requested
        if plugins:
            cmd.extend([f"--plugins={','.join(plugins)}"])
        
        try:
            # Run WhatWeb
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout
            )
            
            if result.returncode != 0 and result.stderr:
                logger.warning(f"WhatWeb stderr: {result.stderr}")
            
            # Parse JSON output
            return self._parse_results(result.stdout, target_url)
            
        except subprocess.TimeoutExpired:
            logger.error("WhatWeb scan timed out")
            return {'error': 'Scan timeout', 'url': target_url}
        except Exception as e:
            logger.error(f"WhatWeb scan failed: {e}")
            return {'error': str(e), 'url': target_url}
    
    def _parse_results(self, output: str, target_url: str) -> Dict[str, Any]:
        """Parse WhatWeb JSON output."""
        results = {
            'url': target_url,
            'technologies': {},
            'emails': [],
            'vulnerabilities': [],
            'interesting_findings': []
        }
        
        try:
            # WhatWeb outputs one JSON object per line
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                try:
                    data = json.loads(line)
                    
                    # Extract HTTP status
                    if 'http_status' in data:
                        results['http_status'] = data['http_status']
                    
                    # Extract target info
                    if 'target' in data:
                        results['target'] = data['target']
                    
                    # Extract plugins/technologies
                    if 'plugins' in data:
                        for plugin_name, plugin_data in data['plugins'].items():
                            tech_info = {
                                'name': plugin_name,
                                'version': None,
                                'confidence': 100,  # Default
                                'details': []
                            }
                            
                            # Extract version if available
                            if 'version' in plugin_data:
                                versions = plugin_data['version']
                                if isinstance(versions, list) and versions:
                                    tech_info['version'] = versions[0]
                                elif isinstance(versions, str):
                                    tech_info['version'] = versions
                            
                            # Extract other details
                            for key, value in plugin_data.items():
                                if key not in ['version'] and value:
                                    if isinstance(value, list):
                                        tech_info['details'].extend(value)
                                    else:
                                        tech_info['details'].append(str(value))
                            
                            # Check for emails
                            if plugin_name == 'Email' and 'string' in plugin_data:
                                results['emails'].extend(plugin_data['string'])
                            
                            # Store technology
                            results['technologies'][plugin_name] = tech_info
                            
                            # Check for vulnerabilities
                            self._check_vulnerabilities(plugin_name, tech_info, results)
                    
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse JSON line: {line}")
        
        except Exception as e:
            logger.error(f"Failed to parse WhatWeb output: {e}")
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _check_vulnerabilities(self, tech_name: str, tech_info: Dict[str, Any], 
                             results: Dict[str, Any]):
        """Check for known vulnerabilities in detected technologies."""
        # Check for outdated versions
        vulnerable_versions = {
            'Apache': {'2.2': 'EOL - Multiple vulnerabilities', 
                      '2.0': 'EOL - Critical vulnerabilities'},
            'nginx': {'1.16': 'Outdated - Security updates available',
                     '1.14': 'EOL - Multiple vulnerabilities'},
            'PHP': {'5.': 'EOL - Critical vulnerabilities',
                   '7.0': 'EOL - Security vulnerabilities',
                   '7.1': 'EOL - Security vulnerabilities',
                   '7.2': 'EOL - Security vulnerabilities'},
            'WordPress': {'4.': 'Outdated - Security updates required',
                         '3.': 'Critical - Multiple vulnerabilities'},
            'jQuery': {'1.': 'Multiple XSS vulnerabilities',
                      '2.': 'Some versions have vulnerabilities'}
        }
        
        version = tech_info.get('version')
        if version:
            for vuln_tech, vuln_versions in vulnerable_versions.items():
                if vuln_tech.lower() in tech_name.lower():
                    for vuln_ver, vuln_desc in vuln_versions.items():
                        if version.startswith(vuln_ver):
                            results['vulnerabilities'].append({
                                'technology': tech_name,
                                'version': version,
                                'issue': vuln_desc,
                                'severity': 'high' if 'Critical' in vuln_desc else 'medium'
                            })
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of findings."""
        summary = {
            'total_technologies': len(results['technologies']),
            'emails_found': len(results['emails']),
            'vulnerabilities_found': len(results['vulnerabilities']),
            'main_technologies': [],
            'security_concerns': []
        }
        
        # Identify main technologies
        important_techs = ['CMS', 'Apache', 'nginx', 'IIS', 'PHP', 'ASP', 
                          'WordPress', 'Joomla', 'Drupal', 'Django', 'Rails']
        
        for tech_name, tech_info in results['technologies'].items():
            for important in important_techs:
                if important.lower() in tech_name.lower():
                    summary['main_technologies'].append({
                        'name': tech_name,
                        'version': tech_info.get('version', 'Unknown')
                    })
                    break
        
        # Add security concerns
        if results['vulnerabilities']:
            summary['security_concerns'].append(
                f"{len(results['vulnerabilities'])} vulnerable components detected"
            )
        
        if results['emails']:
            summary['security_concerns'].append(
                f"{len(results['emails'])} email addresses exposed"
            )
        
        # Check for security headers in tech stack
        security_positive = ['CloudFlare', 'Sucuri', 'Wordfence']
        for tech in results['technologies']:
            for positive in security_positive:
                if positive.lower() in tech.lower():
                    summary['security_concerns'].append(
                        f"Security service detected: {tech}"
                    )
        
        return summary
    
    def quick_scan(self, target_url: str) -> Dict[str, Any]:
        """Perform a quick passive scan."""
        return self.scan(target_url, aggression=1)
    
    def deep_scan(self, target_url: str) -> Dict[str, Any]:
        """Perform a deep aggressive scan."""
        return self.scan(target_url, aggression=3)
    
    def get_technology_stack(self, target_url: str) -> List[str]:
        """Get simplified technology stack list."""
        results = self.quick_scan(target_url)
        
        tech_stack = []
        for tech_name, tech_info in results.get('technologies', {}).items():
            if tech_info.get('version'):
                tech_stack.append(f"{tech_name} {tech_info['version']}")
            else:
                tech_stack.append(tech_name)
        
        return sorted(tech_stack)