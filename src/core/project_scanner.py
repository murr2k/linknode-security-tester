"""Project-aware scanner with isolation and data separation."""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import tempfile
import shutil

from .project_manager import ProjectManager, Project
from ..scanners.security import SecurityScanner
from ..scanners.technology_aware_scanner import TechnologyAwareScanner
from ..integrations.zap_client import ZAPClient
from .report_generator import ReportGenerator

logger = logging.getLogger(__name__)


class ProjectScanner:
    """Scanner that operates within project context with proper isolation."""
    
    def __init__(self, project_manager: ProjectManager):
        """Initialize project scanner.
        
        Args:
            project_manager: Project manager instance
        """
        self.project_manager = project_manager
        self.active_project: Optional[Project] = None
        self.project_dir: Optional[Path] = None
        self.temp_dir: Optional[Path] = None
        self.current_scanner: Optional[Any] = None
        
    def set_project(self, project_id: str) -> bool:
        """Set active project for scanning.
        
        Args:
            project_id: Project ID
            
        Returns:
            True if project set successfully
        """
        project = self.project_manager.get_project(project_id)
        if not project:
            logger.error(f"Project not found: {project_id}")
            return False
        
        self.active_project = project
        self.project_dir = self.project_manager.get_project_dir(project_id)
        
        # Create isolated temp directory for this project
        self.temp_dir = Path(tempfile.mkdtemp(prefix=f"scan_{project_id[:8]}_"))
        
        # Set up project-specific environment
        self._setup_project_environment()
        
        logger.info(f"Set active project: {project.name} ({project.id})")
        return True
    
    def _setup_project_environment(self):
        """Set up isolated environment for project scanning."""
        if not self.active_project or not self.project_dir:
            return
        
        # Create project-specific directories
        scan_dir = self.project_dir / "scans"
        report_dir = self.project_dir / "reports"
        config_dir = self.project_dir / "config"
        
        for dir_path in [scan_dir, report_dir, config_dir]:
            dir_path.mkdir(exist_ok=True)
        
        # Load project-specific configuration
        config_file = config_dir / "scan_config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                self.project_config = json.load(f)
        else:
            # Create default config
            self.project_config = {
                "scan_defaults": {
                    "timeout": 300,
                    "max_depth": 10,
                    "parallel": True
                },
                "exclusions": [],
                "custom_headers": {},
                "authentication": {
                    "type": "none"
                }
            }
            with open(config_file, 'w') as f:
                json.dump(self.project_config, f, indent=2)
    
    def scan(self, scan_type: str = "full", 
             options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run security scan within project context.
        
        Args:
            scan_type: Type of scan to run
            options: Additional scan options
            
        Returns:
            Scan results
        """
        if not self.active_project:
            raise RuntimeError("No active project set")
        
        logger.info(f"Starting {scan_type} scan for project: {self.active_project.name}")
        
        # Merge options with project defaults
        scan_options = self.project_config.get("scan_defaults", {}).copy()
        if options:
            scan_options.update(options)
        
        # Add project-specific headers
        if self.project_config.get("custom_headers"):
            scan_options["headers"] = self.project_config["custom_headers"]
        
        # Create isolated scanner instance
        results = self._run_isolated_scan(scan_type, scan_options)
        
        # Save results to project
        self._save_scan_results(results, scan_type)
        
        return results
    
    def _run_isolated_scan(self, scan_type: str, 
                          options: Dict[str, Any]) -> Dict[str, Any]:
        """Run scan in isolated environment.
        
        Args:
            scan_type: Type of scan
            options: Scan options
            
        Returns:
            Scan results
        """
        # Set up isolated ZAP session for this project
        session_name = f"project_{self.active_project.id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Initialize scanners with project isolation
            if scan_type == "technology":
                # Technology-aware scan
                zap_client = self._create_isolated_zap_client(session_name)
                scanner = TechnologyAwareScanner(zap_client)
                results = scanner.scan(self.active_project.target_url, options)
            else:
                # Standard security scan
                scanner = SecurityScanner()
                self.current_scanner = scanner  # Store for progress updates
                
                # Configure scanner with project settings
                if hasattr(scanner, 'zap_client'):
                    scanner.zap_client = self._create_isolated_zap_client(session_name)
                
                # Run appropriate scan type
                if scan_type == "quick":
                    # Quick scan - basic security checks
                    results = scanner.scan(self.active_project.target_url, {
                        'spider': True,
                        'ajax_spider': False,
                        'passive_scan': True,
                        'active_scan': False
                    })
                elif scan_type == "full":
                    # Full scan - comprehensive security assessment
                    results = scanner.scan(self.active_project.target_url, {
                        'spider': True,
                        'ajax_spider': True,
                        'passive_scan': True,
                        'active_scan': True
                    })
                elif scan_type == "compliance":
                    # Compliance scan - OWASP Top 10 focused
                    results = scanner.scan(self.active_project.target_url, {
                        'spider': True,
                        'ajax_spider': True,
                        'passive_scan': True,
                        'active_scan': True,
                        'compliance_mode': True
                    })
                else:  # Default to quick scan
                    results = scanner.scan(self.active_project.target_url)
            
            # Add project metadata to results
            results["project"] = {
                "id": self.active_project.id,
                "name": self.active_project.name,
                "client": self.active_project.client_name
            }
            
            return results
            
        finally:
            # Clean up temporary files
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_isolated_zap_client(self, session_name: str) -> ZAPClient:
        """Create ZAP client with project isolation.
        
        Args:
            session_name: Unique session name
            
        Returns:
            Configured ZAP client
        """
        # Create project-specific ZAP context
        zap_client = ZAPClient()
        
        # Start new session for isolation
        zap_client.zap.core.new_session(name=session_name, overwrite=True)
        
        # Configure project-specific settings
        if self.project_config.get("exclusions"):
            for pattern in self.project_config["exclusions"]:
                zap_client.zap.spider.exclude_from_scan(pattern)
                zap_client.zap.ascan.exclude_from_scan(pattern)
        
        # Set up authentication if configured
        auth_config = self.project_config.get("authentication", {})
        if auth_config.get("type") != "none":
            self._configure_authentication(zap_client, auth_config)
        
        return zap_client
    
    def _configure_authentication(self, zap_client: ZAPClient, 
                                auth_config: Dict[str, Any]):
        """Configure authentication for scanning.
        
        Args:
            zap_client: ZAP client instance
            auth_config: Authentication configuration
        """
        auth_type = auth_config.get("type")
        
        if auth_type == "form":
            # Form-based authentication
            context_id = zap_client.zap.context.new_context("ProjectAuth")
            
            zap_client.zap.authentication.set_authentication_method(
                contextid=context_id,
                authmethodname="formBasedAuthentication",
                authmethodconfigparams=f"loginUrl={auth_config.get('login_url')}&"
                                     f"loginRequestData={auth_config.get('login_data')}"
            )
            
            # Add user if credentials provided
            if auth_config.get("username") and auth_config.get("password"):
                user_id = zap_client.zap.users.new_user(
                    contextid=context_id,
                    name="project_user"
                )
                
                zap_client.zap.users.set_authentication_credentials(
                    contextid=context_id,
                    userid=user_id,
                    authcredentialsconfigparams=f"username={auth_config['username']}&"
                                               f"password={auth_config['password']}"
                )
                
                zap_client.zap.users.set_user_enabled(
                    contextid=context_id,
                    userid=user_id,
                    enabled=True
                )
        
        elif auth_type == "bearer":
            # Bearer token authentication
            token = auth_config.get("token")
            if token:
                zap_client.zap.replacer.add_rule(
                    description="Authorization Bearer",
                    enabled=True,
                    matchtype="REQ_HEADER",
                    matchregex="Authorization",
                    matchstring="Authorization",
                    replacement=f"Bearer {token}",
                    initiators=""
                )
    
    def _save_scan_results(self, results: Dict[str, Any], scan_type: str):
        """Save scan results to project directory.
        
        Args:
            results: Scan results
            scan_type: Type of scan performed
        """
        if not self.project_dir:
            return
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_file = self.project_dir / "scans" / f"{scan_type}_{timestamp}.json"
        
        # Save full results
        with open(scan_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Calculate metrics
        vuln_count = self._calculate_vulnerability_count(results)
        risk_score = self._calculate_risk_score(results)
        duration = results.get("scan_duration", 0)
        
        # Add to project database
        self.project_manager.add_scan_result(
            project_id=self.active_project.id,
            scan_type=scan_type,
            vulnerability_count=vuln_count,
            risk_score=risk_score,
            report_path=str(scan_file),
            duration=duration,
            metadata={
                "scanner_version": "1.0",
                "options": results.get("scan_config", {})
            }
        )
        
        logger.info(f"Saved scan results to: {scan_file}")
    
    def _calculate_vulnerability_count(self, results: Dict[str, Any]) -> Dict[str, int]:
        """Calculate vulnerability counts from results.
        
        Args:
            results: Scan results
            
        Returns:
            Vulnerability counts by severity
        """
        counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        
        # Handle different result formats
        if "alerts" in results:
            # ZAP format
            for alert in results["alerts"]:
                risk = alert.get("risk", "Informational")
                counts[risk] = counts.get(risk, 0) + 1
        
        elif "analysis" in results:
            # Technology-aware scanner format
            for vuln in results["analysis"].get("unique_vulnerabilities", []):
                severity = vuln.get("vulnerability", {}).get("severity", "Low")
                if severity == "high":
                    counts["High"] += 1
                elif severity == "medium":
                    counts["Medium"] += 1
                else:
                    counts["Low"] += 1
        
        return counts
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score.
        
        Args:
            results: Scan results
            
        Returns:
            Risk score (0-100)
        """
        if "risk_score" in results:
            return results["risk_score"]
        
        # Calculate based on vulnerabilities
        counts = self._calculate_vulnerability_count(results)
        
        score = (
            counts.get("High", 0) * 10 +
            counts.get("Medium", 0) * 5 +
            counts.get("Low", 0) * 2 +
            counts.get("Informational", 0) * 0.5
        )
        
        return min(100, score)
    
    def generate_report(self, scan_id: Optional[str] = None, 
                       format: str = "html") -> Path:
        """Generate report for project scans.
        
        Args:
            scan_id: Specific scan ID or None for latest
            format: Report format (html, pdf, json)
            
        Returns:
            Path to generated report
        """
        if not self.active_project:
            raise RuntimeError("No active project set")
        
        # Get scan results
        scans = self.project_manager.get_project_scans(self.active_project.id)
        if not scans:
            raise ValueError("No scans found for project")
        
        # Get specific scan or latest
        if scan_id:
            scan = next((s for s in scans if s.id == scan_id), None)
            if not scan:
                raise ValueError(f"Scan not found: {scan_id}")
        else:
            scan = scans[0]  # Latest scan
        
        # Load scan results
        with open(scan.report_path, 'r') as f:
            scan_data = json.load(f)
        
        # Prepare data for report generator
        project_data = {
            "id": self.active_project.id,
            "name": self.active_project.name,
            "client": self.active_project.client_name,
            "url": self.active_project.target_url,
            "description": self.active_project.description
        }
        
        scan_metadata = {
            "id": scan.id,
            "type": scan.scan_type,
            "date": scan.scan_date,
            "duration": scan.duration,
            "risk_score": scan.risk_score,
            "vulnerabilities": scan.vulnerability_count
        }
        
        # Generate report using enhanced generator
        generator = ReportGenerator(project_data, scan_metadata, scan_data)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_project_name = "".join(c for c in self.active_project.name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        report_name = f"report_{safe_project_name}_{timestamp}.{format}"
        report_path = self.project_dir / "reports" / report_name
        
        # Generate report
        report_path = generator.generate(format, report_path)
        
        logger.info(f"Generated report: {report_path}")
        return report_path
    
    def _generate_html_report(self, report_path: Path, scan, scan_data: Dict[str, Any]):
        """Generate HTML report (simplified version)."""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {self.active_project.name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1, h2 {{ color: #333; }}
                .info {{ background: #f0f0f0; padding: 15px; margin: 10px 0; }}
                .high {{ color: #d32f2f; }}
                .medium {{ color: #f57c00; }}
                .low {{ color: #388e3c; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Security Scan Report</h1>
            
            <div class="info">
                <h2>Project Information</h2>
                <p><strong>Project:</strong> {self.active_project.name}</p>
                <p><strong>Client:</strong> {self.active_project.client_name}</p>
                <p><strong>Target:</strong> {self.active_project.target_url}</p>
                <p><strong>Scan Date:</strong> {scan.scan_date}</p>
                <p><strong>Scan Type:</strong> {scan.scan_type}</p>
                <p><strong>Risk Score:</strong> {scan.risk_score:.1f}/100</p>
            </div>
            
            <h2>Vulnerability Summary</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                <tr class="high">
                    <td>High</td>
                    <td>{scan.vulnerability_count.get('High', 0)}</td>
                </tr>
                <tr class="medium">
                    <td>Medium</td>
                    <td>{scan.vulnerability_count.get('Medium', 0)}</td>
                </tr>
                <tr class="low">
                    <td>Low</td>
                    <td>{scan.vulnerability_count.get('Low', 0)}</td>
                </tr>
                <tr>
                    <td>Informational</td>
                    <td>{scan.vulnerability_count.get('Informational', 0)}</td>
                </tr>
            </table>
            
            <p><em>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em></p>
        </body>
        </html>
        """
        
        with open(report_path, 'w') as f:
            f.write(html_content)