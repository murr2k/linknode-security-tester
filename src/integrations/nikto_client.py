"""Nikto web server scanner integration."""

import logging
import json
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from datetime import datetime
import tempfile
import os

logger = logging.getLogger(__name__)


class NiktoClient:
    """Client for Nikto web server vulnerability scanner."""
    
    def __init__(self, nikto_path: Optional[str] = None):
        """Initialize Nikto client.
        
        Args:
            nikto_path: Path to nikto binary (defaults to system PATH)
        """
        self.nikto_path = nikto_path or "nikto"
        self._verify_installation()
    
    def _verify_installation(self):
        """Verify Nikto is installed and accessible."""
        try:
            result = subprocess.run(
                [self.nikto_path, "-Version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError(f"Nikto not found at {self.nikto_path}")
            
            # Check version in output
            if "Nikto" in result.stdout:
                logger.info("Nikto installation verified")
            else:
                raise RuntimeError("Nikto output not recognized")
                
        except Exception as e:
            logger.error(f"Nikto verification failed: {e}")
            raise RuntimeError(
                "Nikto not installed. Install with: "
                "apt-get install nikto OR "
                "git clone https://github.com/sullo/nikto.git"
            )
    
    def scan(self, target_url: str, tuning: Optional[str] = None,
             plugins: Optional[List[str]] = None,
             timeout: int = 300) -> Dict[str, Any]:
        """Run Nikto web server scan.
        
        Args:
            target_url: URL to scan
            tuning: Scan tuning options (string of numbers)
                1 = Interesting files/dirs
                2 = Misconfiguration
                3 = Information Disclosure
                4 = Injection (XSS/Script/HTML)
                5 = Remote File Retrieval
                6 = Denial of Service
                7 = Remote File Upload
                8 = Command Execution
                9 = SQL Injection
                0 = File Upload
                a = Authentication Bypass
                b = Software Detection
                c = Remote Source Inclusion
                x = Reverse Tuning (exclude checks)
            plugins: Specific plugins to use
            timeout: Scan timeout in seconds
            
        Returns:
            Scan results dictionary
        """
        logger.info(f"Running Nikto scan on {target_url}")
        
        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            output_file = tmp.name
        
        try:
            # Build command
            cmd = [
                self.nikto_path,
                "-h", target_url,
                "-o", output_file,
                "-Format", "json",
                "-nointeractive",
                "-maxtime", f"{timeout}s"
            ]
            
            # Add tuning if specified
            if tuning:
                cmd.extend(["-Tuning", tuning])
            
            # Add plugins if specified
            if plugins:
                cmd.extend(["-Plugins", ";".join(plugins)])
            
            # Run Nikto
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30  # Add buffer to subprocess timeout
            )
            
            if result.returncode != 0 and result.stderr:
                logger.warning(f"Nikto stderr: {result.stderr}")
            
            # Parse results
            return self._parse_results(output_file, target_url)
            
        except subprocess.TimeoutExpired:
            logger.error("Nikto scan timed out")
            return {'error': 'Scan timeout', 'url': target_url}
        except Exception as e:
            logger.error(f"Nikto scan failed: {e}")
            return {'error': str(e), 'url': target_url}
        finally:
            # Clean up temp file
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def _parse_results(self, output_file: str, target_url: str) -> Dict[str, Any]:
        """Parse Nikto JSON output."""
        results = {
            'url': target_url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'server_info': {},
            'statistics': {},
            'summary': {}
        }
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if isinstance(data, dict):
                nikto_data = data
            elif isinstance(data, list) and data:
                nikto_data = data[0]
            else:
                logger.warning("Unexpected Nikto JSON structure")
                return results
            
            # Extract host information
            if 'host' in nikto_data:
                host_info = nikto_data['host']
                results['server_info'] = {
                    'hostname': host_info.get('hostname', ''),
                    'ip': host_info.get('ip', ''),
                    'port': host_info.get('port', ''),
                    'banner': host_info.get('banner', '')
                }
            
            # Extract vulnerabilities
            if 'vulnerabilities' in nikto_data:
                for vuln in nikto_data['vulnerabilities']:
                    results['vulnerabilities'].append(self._parse_vulnerability(vuln))
            
            # Extract statistics
            if 'statistics' in nikto_data:
                results['statistics'] = nikto_data['statistics']
            
            # Generate summary
            results['summary'] = self._generate_summary(results)
            
        except Exception as e:
            logger.error(f"Failed to parse Nikto output: {e}")
            # Try alternative parsing
            results = self._parse_alternative_format(output_file, results)
        
        return results
    
    def _parse_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Parse individual vulnerability entry."""
        return {
            'id': vuln.get('id', 'unknown'),
            'description': vuln.get('msg', vuln.get('description', '')),
            'url': vuln.get('url', ''),
            'method': vuln.get('method', 'GET'),
            'osvdb': vuln.get('OSVDB', ''),
            'reference': vuln.get('references', ''),
            'severity': self._determine_severity(vuln)
        }
    
    def _determine_severity(self, vuln: Dict[str, Any]) -> str:
        """Determine vulnerability severity based on description and ID."""
        description = vuln.get('msg', '').lower()
        vuln_id = str(vuln.get('id', ''))
        
        # High severity indicators
        high_indicators = [
            'injection', 'execute', 'traversal', 'inclusion',
            'authentication', 'bypass', 'default password',
            'command execution', 'sql injection'
        ]
        
        # Medium severity indicators
        medium_indicators = [
            'disclosure', 'configuration', 'version', 'backup',
            'directory listing', 'method', 'header'
        ]
        
        for indicator in high_indicators:
            if indicator in description:
                return 'high'
        
        for indicator in medium_indicators:
            if indicator in description:
                return 'medium'
        
        return 'low'
    
    def _parse_alternative_format(self, output_file: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Try to parse alternative Nikto output formats."""
        try:
            # Sometimes Nikto outputs line-by-line JSON
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            item = json.loads(line)
                            if 'vulnerability' in item:
                                results['vulnerabilities'].append(
                                    self._parse_vulnerability(item['vulnerability'])
                                )
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Alternative parsing also failed: {e}")
        
        return results
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of Nikto findings."""
        vulns = results['vulnerabilities']
        
        summary = {
            'total_vulnerabilities': len(vulns),
            'high_severity': len([v for v in vulns if v['severity'] == 'high']),
            'medium_severity': len([v for v in vulns if v['severity'] == 'medium']),
            'low_severity': len([v for v in vulns if v['severity'] == 'low']),
            'main_issues': [],
            'recommendations': []
        }
        
        # Identify main issues
        if summary['high_severity'] > 0:
            summary['main_issues'].append(
                f"{summary['high_severity']} high severity vulnerabilities found"
            )
            summary['recommendations'].append(
                "Address high severity issues immediately"
            )
        
        # Check for specific issues
        for vuln in vulns:
            desc = vuln['description'].lower()
            if 'ssl' in desc or 'tls' in desc:
                summary['main_issues'].append("SSL/TLS configuration issues")
                summary['recommendations'].append("Review SSL/TLS configuration")
                break
        
        # Server info recommendations
        if results['server_info'].get('banner'):
            summary['main_issues'].append("Server version disclosed in banner")
            summary['recommendations'].append("Hide server version information")
        
        return summary
    
    def quick_scan(self, target_url: str) -> Dict[str, Any]:
        """Perform a quick scan focusing on common issues."""
        # Tuning: 1,2,3,b = Files, Misconfig, Disclosure, Software
        return self.scan(target_url, tuning="123b", timeout=120)
    
    def comprehensive_scan(self, target_url: str) -> Dict[str, Any]:
        """Perform a comprehensive scan of all categories."""
        # All tuning options except DoS
        return self.scan(target_url, tuning="12345789abc", timeout=600)
    
    def injection_scan(self, target_url: str) -> Dict[str, Any]:
        """Scan specifically for injection vulnerabilities."""
        # Tuning: 4,8,9 = XSS, Command, SQL injection
        return self.scan(target_url, tuning="489", timeout=300)
    
    def get_server_info(self, results: Dict[str, Any]) -> Dict[str, str]:
        """Extract server information from scan results."""
        server_info = results.get('server_info', {})
        
        # Try to extract additional info from vulnerabilities
        for vuln in results.get('vulnerabilities', []):
            desc = vuln.get('description', '')
            if 'Apache' in desc and 'version' not in server_info:
                server_info['software'] = 'Apache'
            elif 'nginx' in desc and 'version' not in server_info:
                server_info['software'] = 'nginx'
            elif 'IIS' in desc and 'version' not in server_info:
                server_info['software'] = 'IIS'
        
        return server_info