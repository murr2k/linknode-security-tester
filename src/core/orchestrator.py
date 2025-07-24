"""Core orchestrator for managing scans and coordinating components."""

import logging
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import json

from ..integrations.zap_client import ZAPClient
from ..scanners.security import SecurityScanner
from ..core.config import settings

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates all scanning operations."""
    
    def __init__(self):
        """Initialize orchestrator."""
        self.zap_client = None
        self.security_scanner = None
        self.scan_history = []
        self.current_scan = None
    
    def initialize(self):
        """Initialize all components."""
        logger.info("Initializing scan orchestrator")
        
        # Initialize ZAP client
        try:
            self.zap_client = ZAPClient()
            self.security_scanner = SecurityScanner(self.zap_client)
            logger.info("All components initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            raise
    
    async def run_comprehensive_scan(
        self,
        target_url: str,
        scan_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Run comprehensive scan including all selected types."""
        logger.info(f"Starting comprehensive scan for {target_url}")
        
        # Default to all scan types
        if not scan_types:
            scan_types = ['security', 'quality', 'performance']
        
        self.current_scan = {
            'id': datetime.now().strftime('%Y%m%d%H%M%S'),
            'target_url': target_url,
            'scan_types': scan_types,
            'start_time': datetime.now(),
            'status': 'running',
            'results': {}
        }
        
        try:
            # Run security scan
            if 'security' in scan_types:
                logger.info("Running security scan")
                security_results = await self._run_security_scan(target_url)
                self.current_scan['results']['security'] = security_results
            
            # Run quality scan (placeholder for now)
            if 'quality' in scan_types:
                logger.info("Running quality scan")
                quality_results = await self._run_quality_scan(target_url)
                self.current_scan['results']['quality'] = quality_results
            
            # Run performance scan (placeholder for now)
            if 'performance' in scan_types:
                logger.info("Running performance scan")
                performance_results = await self._run_performance_scan(target_url)
                self.current_scan['results']['performance'] = performance_results
            
            # Update scan status
            self.current_scan['status'] = 'completed'
            self.current_scan['end_time'] = datetime.now()
            self.current_scan['duration'] = (
                self.current_scan['end_time'] - self.current_scan['start_time']
            ).total_seconds()
            
            # Generate summary
            self.current_scan['summary'] = self._generate_scan_summary(
                self.current_scan['results']
            )
            
            # Add to history
            self.scan_history.append(self.current_scan)
            
            # Save scan results
            self._save_scan_results(self.current_scan)
            
            logger.info(f"Comprehensive scan completed in {self.current_scan['duration']}s")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.current_scan['status'] = 'failed'
            self.current_scan['error'] = str(e)
            raise
        
        return self.current_scan
    
    async def _run_security_scan(self, target_url: str) -> Dict[str, Any]:
        """Run security scan asynchronously."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.security_scanner.scan,
            target_url
        )
    
    async def _run_quality_scan(self, target_url: str) -> Dict[str, Any]:
        """Run quality assessment scan."""
        # Placeholder for quality scanner implementation
        logger.info("Quality scan not yet implemented")
        return {
            'status': 'not_implemented',
            'message': 'Quality scanning will be implemented in the next phase'
        }
    
    async def _run_performance_scan(self, target_url: str) -> Dict[str, Any]:
        """Run performance analysis scan."""
        # Placeholder for performance scanner implementation
        logger.info("Performance scan not yet implemented")
        return {
            'status': 'not_implemented',
            'message': 'Performance scanning will be implemented in the next phase'
        }
    
    def _generate_scan_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of scan results."""
        summary = {
            'total_issues': 0,
            'critical_issues': 0,
            'high_risk_issues': 0,
            'medium_risk_issues': 0,
            'low_risk_issues': 0,
            'recommendations': []
        }
        
        # Process security results
        if 'security' in results:
            security_results = results['security']
            if 'alerts_by_risk' in security_results:
                risk_counts = security_results['alerts_by_risk']
                summary['high_risk_issues'] = risk_counts.get('High', 0)
                summary['medium_risk_issues'] = risk_counts.get('Medium', 0)
                summary['low_risk_issues'] = risk_counts.get('Low', 0)
                summary['total_issues'] = sum(risk_counts.values())
            
            # Add recommendations based on findings
            if summary['high_risk_issues'] > 0:
                summary['recommendations'].append(
                    "URGENT: Address high-risk security vulnerabilities immediately"
                )
            if security_results.get('risk_score', 0) > 70:
                summary['recommendations'].append(
                    "Consider conducting a comprehensive security audit"
                )
        
        return summary
    
    def _save_scan_results(self, scan_data: Dict[str, Any]):
        """Save scan results to file."""
        results_dir = Path("scan_results")
        results_dir.mkdir(exist_ok=True)
        
        filename = f"scan_{scan_data['id']}_{scan_data['target_url'].replace('https://', '').replace('/', '_')}.json"
        filepath = results_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2, default=str)
        
        logger.info(f"Scan results saved to {filepath}")
    
    def get_scan_history(self) -> List[Dict[str, Any]]:
        """Get scan history."""
        return self.scan_history
    
    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get specific scan by ID."""
        for scan in self.scan_history:
            if scan['id'] == scan_id:
                return scan
        return None
    
    def cleanup(self):
        """Clean up resources."""
        logger.info("Cleaning up orchestrator resources")
        if self.zap_client:
            self.zap_client.cleanup()