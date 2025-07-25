"""HostedScan.com API integration client."""

import logging
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
import time

logger = logging.getLogger(__name__)


class HostedScanClient:
    """Client for interacting with HostedScan.com API."""
    
    def __init__(self, api_key: str):
        """Initialize HostedScan client.
        
        Args:
            api_key: HostedScan API key
        """
        self.api_key = api_key
        self.base_url = "https://api.hostedscan.com/v1"
        self.headers = {
            "X-HOSTEDSCAN-API-KEY": api_key,
            "Content-Type": "application/json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make API request with error handling."""
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"HostedScan API error: {e}")
            raise
    
    # Target Management
    def create_target(self, url: str, name: str, description: Optional[str] = None) -> Dict[str, Any]:
        """Create a new scan target.
        
        Args:
            url: Target URL to scan
            name: Name for the target
            description: Optional description
            
        Returns:
            Target creation response
        """
        logger.info(f"Creating HostedScan target: {name} ({url})")
        
        data = {
            "url": url,
            "name": name,
            "description": description or f"Created by Linknode Scanner at {datetime.now()}"
        }
        
        return self._make_request("POST", "/targets", json=data)
    
    def list_targets(self) -> List[Dict[str, Any]]:
        """List all targets."""
        return self._make_request("GET", "/targets")
    
    def get_target(self, target_id: str) -> Dict[str, Any]:
        """Get target details."""
        return self._make_request("GET", f"/targets/{target_id}")
    
    def update_target(self, target_id: str, **kwargs) -> Dict[str, Any]:
        """Update target configuration."""
        return self._make_request("PUT", f"/targets/{target_id}", json=kwargs)
    
    def delete_target(self, target_id: str) -> Dict[str, Any]:
        """Delete a target."""
        return self._make_request("DELETE", f"/targets/{target_id}")
    
    # Scan Management
    def create_scan(self, target_id: str, scan_type: str = "full", 
                   scan_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create and start a new scan.
        
        Args:
            target_id: ID of target to scan
            scan_type: Type of scan (full, quick, api, etc.)
            scan_config: Additional scan configuration
            
        Returns:
            Scan creation response
        """
        logger.info(f"Starting HostedScan {scan_type} scan for target {target_id}")
        
        data = {
            "target_id": target_id,
            "scan_type": scan_type,
            "config": scan_config or {}
        }
        
        return self._make_request("POST", "/scans", json=data)
    
    def list_scans(self, target_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List scans, optionally filtered by target."""
        endpoint = "/scans"
        if target_id:
            endpoint += f"?target_id={target_id}"
        
        return self._make_request("GET", endpoint)
    
    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        """Get scan details and status."""
        return self._make_request("GET", f"/scans/{scan_id}")
    
    def wait_for_scan(self, scan_id: str, timeout: int = 3600) -> Dict[str, Any]:
        """Wait for scan to complete.
        
        Args:
            scan_id: ID of scan to monitor
            timeout: Maximum time to wait in seconds
            
        Returns:
            Final scan status
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            scan = self.get_scan(scan_id)
            status = scan.get("status", "unknown")
            
            if status in ["completed", "failed", "cancelled"]:
                logger.info(f"Scan {scan_id} finished with status: {status}")
                return scan
            
            logger.debug(f"Scan {scan_id} status: {status}")
            time.sleep(30)  # Check every 30 seconds
        
        raise TimeoutError(f"Scan {scan_id} did not complete within {timeout} seconds")
    
    def cancel_scan(self, scan_id: str) -> Dict[str, Any]:
        """Cancel a running scan."""
        return self._make_request("DELETE", f"/scans/{scan_id}")
    
    # Risk Management
    def get_risks(self, scan_id: Optional[str] = None, 
                  target_id: Optional[str] = None,
                  severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get security risks/vulnerabilities.
        
        Args:
            scan_id: Filter by scan ID
            target_id: Filter by target ID
            severity: Filter by severity (critical, high, medium, low)
            
        Returns:
            List of risk findings
        """
        params = {}
        if scan_id:
            params["scan_id"] = scan_id
        if target_id:
            params["target_id"] = target_id
        if severity:
            params["severity"] = severity
        
        return self._make_request("GET", "/risks", params=params)
    
    def get_risk(self, risk_id: str) -> Dict[str, Any]:
        """Get detailed risk information."""
        return self._make_request("GET", f"/risks/{risk_id}")
    
    def update_risk(self, risk_id: str, status: str, notes: Optional[str] = None) -> Dict[str, Any]:
        """Update risk status (e.g., mark as resolved).
        
        Args:
            risk_id: ID of risk to update
            status: New status (open, resolved, accepted, etc.)
            notes: Optional notes about the update
        """
        data = {
            "status": status,
            "notes": notes
        }
        
        return self._make_request("PUT", f"/risks/{risk_id}", json=data)
    
    # Report Generation
    def generate_report(self, scan_id: str, report_format: str = "json") -> Dict[str, Any]:
        """Generate security report.
        
        Args:
            scan_id: ID of scan to report on
            report_format: Format (json, pdf, html, csv)
            
        Returns:
            Report data or download URL
        """
        data = {
            "scan_id": scan_id,
            "format": report_format
        }
        
        return self._make_request("POST", "/reports", json=data)
    
    # Authentication Configuration
    def configure_auth(self, target_id: str, auth_type: str, 
                      auth_config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure authentication for a target.
        
        Args:
            target_id: Target to configure
            auth_type: Type of auth (basic, bearer, cookie, selenium)
            auth_config: Authentication configuration
            
        Returns:
            Configuration response
        """
        endpoint = f"/targets/{target_id}/auth/{auth_type}"
        
        # Handle file uploads for Selenium recordings
        if auth_type == "selenium" and "recording_file" in auth_config:
            files = {"file": open(auth_config["recording_file"], "rb")}
            # Remove Content-Type for multipart upload
            headers = {k: v for k, v in self.headers.items() if k != "Content-Type"}
            response = requests.post(
                f"{self.base_url}{endpoint}",
                headers=headers,
                files=files
            )
            response.raise_for_status()
            return response.json()
        
        return self._make_request("POST", endpoint, json=auth_config)
    
    # Webhook Management
    def register_webhook(self, url: str, events: List[str]) -> Dict[str, Any]:
        """Register a webhook endpoint.
        
        Args:
            url: Webhook URL to receive events
            events: List of events to subscribe to
            
        Returns:
            Webhook registration response
        """
        data = {
            "url": url,
            "events": events
        }
        
        return self._make_request("POST", "/webhooks", json=data)
    
    def list_webhooks(self) -> List[Dict[str, Any]]:
        """List registered webhooks."""
        return self._make_request("GET", "/webhooks")
    
    def delete_webhook(self, webhook_id: str) -> Dict[str, Any]:
        """Delete a webhook."""
        return self._make_request("DELETE", f"/webhooks/{webhook_id}")
    
    # Utility Methods
    def run_quick_scan(self, url: str, wait: bool = True) -> Dict[str, Any]:
        """Run a quick scan on a URL.
        
        Args:
            url: URL to scan
            wait: Whether to wait for scan completion
            
        Returns:
            Scan results if wait=True, scan info if wait=False
        """
        # Check if target exists
        targets = self.list_targets()
        target = next((t for t in targets if t["url"] == url), None)
        
        # Create target if needed
        if not target:
            target = self.create_target(url, f"Quick scan - {url}")
        
        # Start scan
        scan = self.create_scan(target["id"], scan_type="quick")
        
        if wait:
            # Wait for completion
            scan = self.wait_for_scan(scan["id"])
            
            # Get risks
            risks = self.get_risks(scan_id=scan["id"])
            
            return {
                "scan": scan,
                "risks": risks,
                "summary": {
                    "total_risks": len(risks),
                    "critical": len([r for r in risks if r.get("severity") == "critical"]),
                    "high": len([r for r in risks if r.get("severity") == "high"]),
                    "medium": len([r for r in risks if r.get("severity") == "medium"]),
                    "low": len([r for r in risks if r.get("severity") == "low"])
                }
            }
        
        return scan
    
    def get_scan_summary(self, scan_id: str) -> Dict[str, Any]:
        """Get comprehensive scan summary.
        
        Args:
            scan_id: ID of scan to summarize
            
        Returns:
            Scan summary with risk breakdown
        """
        scan = self.get_scan(scan_id)
        risks = self.get_risks(scan_id=scan_id)
        
        return {
            "scan_id": scan_id,
            "target_url": scan.get("target", {}).get("url"),
            "status": scan.get("status"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at"),
            "duration": scan.get("duration"),
            "total_risks": len(risks),
            "risks_by_severity": {
                "critical": len([r for r in risks if r.get("severity") == "critical"]),
                "high": len([r for r in risks if r.get("severity") == "high"]),
                "medium": len([r for r in risks if r.get("severity") == "medium"]),
                "low": len([r for r in risks if r.get("severity") == "low"]),
                "info": len([r for r in risks if r.get("severity") == "info"])
            },
            "top_risks": risks[:10] if risks else []
        }