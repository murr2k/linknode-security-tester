"""Enhanced report generation with HTML and PDF support."""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import base64
import io

# Optional imports for enhanced features
try:
    from weasyprint import HTML, CSS
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate professional security reports in various formats."""
    
    def __init__(self, project_data: Dict[str, Any], scan_data: Dict[str, Any], 
                 scan_results: Dict[str, Any]):
        """Initialize report generator.
        
        Args:
            project_data: Project information
            scan_data: Scan metadata
            scan_results: Full scan results
        """
        self.project = project_data
        self.scan = scan_data
        self.results = scan_results
        
    def generate(self, format: str, output_path: Path) -> Path:
        """Generate report in specified format.
        
        Args:
            format: Report format (html, pdf, json)
            output_path: Output file path
            
        Returns:
            Path to generated report
        """
        if format == "json":
            return self._generate_json(output_path)
        elif format == "html":
            return self._generate_html(output_path)
        elif format == "pdf":
            return self._generate_pdf(output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json(self, output_path: Path) -> Path:
        """Generate JSON report."""
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "generator": "Linknode Security Tester",
                "version": "1.0"
            },
            "project": self.project,
            "scan": self.scan,
            "results": self.results,
            "summary": self._generate_summary(),
            "vulnerabilities": self._extract_vulnerabilities()
        }
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return output_path
    
    def _generate_html(self, output_path: Path) -> Path:
        """Generate enhanced HTML report."""
        vulnerabilities = self._extract_vulnerabilities()
        summary = self._generate_summary()
        charts_html = self._generate_charts_html() if HAS_MATPLOTLIB else ""
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {self.project['name']}</title>
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <h1>Security Assessment Report</h1>
            <div class="report-meta">
                <span>Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}</span>
            </div>
        </header>
        
        <!-- Executive Summary -->
        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Overall Risk Score</h3>
                    <div class="risk-score risk-{self._get_risk_level(self.scan['risk_score'])}">
                        {self.scan['risk_score']:.1f}/100
                    </div>
                </div>
                <div class="summary-card">
                    <h3>Total Vulnerabilities</h3>
                    <div class="vuln-total">{summary['total_vulnerabilities']}</div>
                </div>
                <div class="summary-card">
                    <h3>Critical Findings</h3>
                    <div class="critical-count">{summary['critical_findings']}</div>
                </div>
                <div class="summary-card">
                    <h3>Scan Duration</h3>
                    <div class="duration">{self._format_duration(self.scan['duration'])}</div>
                </div>
            </div>
        </section>
        
        <!-- Project Information -->
        <section class="project-info">
            <h2>Project Information</h2>
            <table class="info-table">
                <tr>
                    <td class="label">Project Name:</td>
                    <td>{self.project['name']}</td>
                </tr>
                <tr>
                    <td class="label">Client:</td>
                    <td>{self.project['client']}</td>
                </tr>
                <tr>
                    <td class="label">Target URL:</td>
                    <td><a href="{self.project['url']}" target="_blank">{self.project['url']}</a></td>
                </tr>
                <tr>
                    <td class="label">Scan Type:</td>
                    <td>{self.scan['type']}</td>
                </tr>
                <tr>
                    <td class="label">Scan Date:</td>
                    <td>{datetime.fromisoformat(self.scan['date']).strftime('%B %d, %Y at %H:%M')}</td>
                </tr>
            </table>
        </section>
        
        <!-- Vulnerability Distribution -->
        <section class="vuln-distribution">
            <h2>Vulnerability Distribution</h2>
            <div class="vuln-stats">
                <div class="vuln-stat high">
                    <div class="count">{self.scan['vulnerabilities'].get('High', 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="vuln-stat medium">
                    <div class="count">{self.scan['vulnerabilities'].get('Medium', 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="vuln-stat low">
                    <div class="count">{self.scan['vulnerabilities'].get('Low', 0)}</div>
                    <div class="label">Low</div>
                </div>
                <div class="vuln-stat info">
                    <div class="count">{self.scan['vulnerabilities'].get('Informational', 0)}</div>
                    <div class="label">Info</div>
                </div>
            </div>
            {charts_html}
        </section>
        
        <!-- Detailed Findings -->
        <section class="findings">
            <h2>Detailed Findings</h2>
            {self._generate_findings_html(vulnerabilities)}
        </section>
        
        <!-- Recommendations -->
        <section class="recommendations">
            <h2>Recommendations</h2>
            {self._generate_recommendations_html(summary)}
        </section>
        
        <!-- Footer -->
        <footer>
            <p>This report was generated by Linknode Security Tester</p>
            <p>Report ID: {self.scan.get('id', 'N/A')}</p>
        </footer>
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return output_path
    
    def _generate_pdf(self, output_path: Path) -> Path:
        """Generate PDF report from HTML."""
        if not HAS_WEASYPRINT:
            logger.warning("WeasyPrint not installed, generating HTML instead")
            html_path = output_path.with_suffix('.html')
            self._generate_html(html_path)
            return html_path
        
        # Generate HTML first
        html_path = output_path.with_suffix('.html')
        self._generate_html(html_path)
        
        # Convert to PDF
        try:
            HTML(filename=str(html_path)).write_pdf(output_path)
            # Optionally remove temporary HTML file
            html_path.unlink()
            return output_path
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            logger.info("HTML report saved instead")
            return html_path
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for the report."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        
        header {
            background-color: #2c3e50;
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .report-meta {
            font-size: 0.9em;
            opacity: 0.8;
        }
        
        section {
            padding: 40px;
            border-bottom: 1px solid #eee;
        }
        
        h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        h3 {
            color: #34495e;
            margin-bottom: 15px;
        }
        
        /* Executive Summary */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #e9ecef;
        }
        
        .summary-card h3 {
            font-size: 0.9em;
            color: #6c757d;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .risk-score {
            font-size: 2.5em;
            font-weight: bold;
        }
        
        .risk-high { color: #e74c3c; }
        .risk-medium { color: #f39c12; }
        .risk-low { color: #27ae60; }
        
        .vuln-total, .critical-count, .duration {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .critical-count {
            color: #e74c3c;
        }
        
        /* Project Information */
        .info-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .info-table td {
            padding: 10px;
            border-bottom: 1px solid #eee;
        }
        
        .info-table .label {
            font-weight: bold;
            width: 200px;
            color: #6c757d;
        }
        
        /* Vulnerability Distribution */
        .vuln-stats {
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
        }
        
        .vuln-stat {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            min-width: 120px;
        }
        
        .vuln-stat .count {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .vuln-stat .label {
            font-size: 1.1em;
            text-transform: uppercase;
            font-weight: 600;
        }
        
        .vuln-stat.high {
            background-color: #ffebee;
            color: #c62828;
        }
        
        .vuln-stat.medium {
            background-color: #fff3e0;
            color: #e65100;
        }
        
        .vuln-stat.low {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
        
        .vuln-stat.info {
            background-color: #e3f2fd;
            color: #1565c0;
        }
        
        /* Findings */
        .finding {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .finding-header {
            padding: 15px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .finding-header.high {
            background-color: #ffcdd2;
            color: #b71c1c;
        }
        
        .finding-header.medium {
            background-color: #ffe0b2;
            color: #e65100;
        }
        
        .finding-header.low {
            background-color: #c8e6c9;
            color: #1b5e20;
        }
        
        .finding-content {
            padding: 20px;
            background-color: #f9f9f9;
        }
        
        .finding-content h4 {
            margin-bottom: 10px;
            color: #2c3e50;
        }
        
        .finding-content p {
            margin-bottom: 10px;
        }
        
        .code-block {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }
        
        /* Recommendations */
        .recommendation {
            background-color: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin-bottom: 15px;
        }
        
        .recommendation h4 {
            color: #2e7d32;
            margin-bottom: 5px;
        }
        
        /* Charts */
        .chart-container {
            text-align: center;
            margin: 30px 0;
        }
        
        .chart-container img {
            max-width: 600px;
            height: auto;
        }
        
        /* Footer */
        footer {
            background-color: #34495e;
            color: white;
            text-align: center;
            padding: 20px;
        }
        
        footer p {
            margin: 5px 0;
        }
        
        /* Print Styles */
        @media print {
            .container {
                box-shadow: none;
            }
            
            section {
                page-break-inside: avoid;
            }
            
            .finding {
                page-break-inside: avoid;
            }
        }
        """
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        vuln_counts = self.scan['vulnerabilities']
        total_vulns = sum(vuln_counts.values())
        critical_findings = vuln_counts.get('High', 0) + vuln_counts.get('Critical', 0)
        
        return {
            "total_vulnerabilities": total_vulns,
            "critical_findings": critical_findings,
            "unique_issues": len(self._extract_vulnerabilities()),
            "technologies_detected": self._count_technologies(),
            "scan_coverage": self._calculate_coverage()
        }
    
    def _extract_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Extract and organize vulnerabilities from scan results."""
        vulnerabilities = []
        
        # Handle ZAP format
        if 'alerts' in self.results:
            for alert in self.results['alerts']:
                vulnerabilities.append({
                    'name': alert.get('name', 'Unknown'),
                    'risk': alert.get('risk', 'Info'),
                    'confidence': alert.get('confidence', 'Medium'),
                    'description': alert.get('desc', ''),
                    'solution': alert.get('solution', ''),
                    'reference': alert.get('reference', ''),
                    'instances': alert.get('instances', []),
                    'cwe': alert.get('cweid', 0),
                    'wasc': alert.get('wascid', 0)
                })
        
        # Handle technology scanner format
        elif 'analysis' in self.results:
            if 'unique_vulnerabilities' in self.results['analysis']:
                for vuln in self.results['analysis']['unique_vulnerabilities']:
                    vulnerabilities.append({
                        'name': vuln.get('vulnerability', {}).get('name', 'Unknown'),
                        'risk': self._map_severity(vuln.get('vulnerability', {}).get('severity', 'low')),
                        'confidence': 'High',
                        'description': vuln.get('vulnerability', {}).get('description', ''),
                        'solution': vuln.get('remediation', ''),
                        'reference': vuln.get('references', []),
                        'instances': vuln.get('affected_files', []),
                        'cwe': vuln.get('cwe_id', 0),
                        'wasc': 0
                    })
        
        # Sort by risk level
        risk_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}
        vulnerabilities.sort(key=lambda x: risk_order.get(x['risk'], 5))
        
        return vulnerabilities
    
    def _map_severity(self, severity: str) -> str:
        """Map severity levels to standard format."""
        mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Informational',
            'informational': 'Informational'
        }
        return mapping.get(severity.lower(), 'Low')
    
    def _count_technologies(self) -> int:
        """Count detected technologies."""
        if 'technologies' in self.results:
            return len(self.results['technologies'])
        elif 'tech_stack' in self.results:
            return len(self.results['tech_stack'])
        return 0
    
    def _calculate_coverage(self) -> str:
        """Calculate scan coverage percentage."""
        # This is a simplified calculation
        if 'spider' in self.results and 'urls' in self.results['spider']:
            return f"{len(self.results['spider']['urls'])} URLs scanned"
        return "N/A"
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score."""
        if score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        else:
            return f"{seconds/3600:.1f} hours"
    
    def _generate_findings_html(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate HTML for vulnerability findings."""
        if not vulnerabilities:
            return "<p>No vulnerabilities found during this scan.</p>"
        
        html = ""
        for i, vuln in enumerate(vulnerabilities):
            risk_class = vuln['risk'].lower()
            html += f"""
            <div class="finding">
                <div class="finding-header {risk_class}">
                    {vuln['risk'].upper()}: {vuln['name']}
                </div>
                <div class="finding-content">
                    <h4>Description</h4>
                    <p>{vuln['description']}</p>
                    
                    {f'<h4>Solution</h4><p>{vuln["solution"]}</p>' if vuln['solution'] else ''}
                    
                    {f'<h4>CWE ID</h4><p>CWE-{vuln["cwe"]}</p>' if vuln['cwe'] else ''}
                    
                    {self._format_instances(vuln['instances']) if vuln['instances'] else ''}
                    
                    {f'<h4>References</h4><p>{vuln["reference"]}</p>' if vuln['reference'] else ''}
                </div>
            </div>
            """
        
        return html
    
    def _format_instances(self, instances: List[Any]) -> str:
        """Format vulnerability instances."""
        if not instances:
            return ""
        
        html = "<h4>Affected Locations</h4><ul>"
        for instance in instances[:5]:  # Limit to first 5
            if isinstance(instance, dict):
                uri = instance.get('uri', instance.get('url', str(instance)))
            else:
                uri = str(instance)
            html += f"<li>{uri}</li>"
        
        if len(instances) > 5:
            html += f"<li>... and {len(instances) - 5} more</li>"
        
        html += "</ul>"
        return html
    
    def _generate_recommendations_html(self, summary: Dict[str, Any]) -> str:
        """Generate recommendations based on findings."""
        recommendations = []
        
        if summary['critical_findings'] > 0:
            recommendations.append({
                'priority': 'Critical',
                'title': 'Address Critical Vulnerabilities',
                'description': f'Immediately address the {summary["critical_findings"]} critical/high severity vulnerabilities identified in this scan.'
            })
        
        if self.scan['vulnerabilities'].get('Medium', 0) > 5:
            recommendations.append({
                'priority': 'High',
                'title': 'Review Medium Risk Findings',
                'description': 'A significant number of medium-risk vulnerabilities were found. These should be reviewed and remediated according to their potential impact.'
            })
        
        recommendations.extend([
            {
                'priority': 'Medium',
                'title': 'Implement Security Headers',
                'description': 'Consider implementing security headers like CSP, X-Frame-Options, and X-Content-Type-Options to enhance security posture.'
            },
            {
                'priority': 'Low',
                'title': 'Regular Security Scanning',
                'description': 'Schedule regular security scans to identify new vulnerabilities as the application evolves.'
            }
        ])
        
        html = ""
        for rec in recommendations:
            html += f"""
            <div class="recommendation">
                <h4>{rec['title']}</h4>
                <p>{rec['description']}</p>
            </div>
            """
        
        return html
    
    def _generate_charts_html(self) -> str:
        """Generate charts for the report."""
        if not HAS_MATPLOTLIB:
            return ""
        
        try:
            # Generate vulnerability distribution pie chart
            chart_data = self._generate_vuln_pie_chart()
            if chart_data:
                return f"""
                <div class="chart-container">
                    <h3>Vulnerability Distribution</h3>
                    <img src="data:image/png;base64,{chart_data}" alt="Vulnerability Distribution Chart">
                </div>
                """
        except Exception as e:
            logger.error(f"Chart generation failed: {e}")
        
        return ""
    
    def _generate_vuln_pie_chart(self) -> Optional[str]:
        """Generate vulnerability distribution pie chart."""
        vuln_counts = self.scan['vulnerabilities']
        
        # Filter out zero counts
        data = {k: v for k, v in vuln_counts.items() if v > 0}
        if not data:
            return None
        
        # Create pie chart
        plt.figure(figsize=(8, 6))
        colors = {
            'High': '#e74c3c',
            'Medium': '#f39c12',
            'Low': '#27ae60',
            'Informational': '#3498db'
        }
        
        chart_colors = [colors.get(k, '#95a5a6') for k in data.keys()]
        
        plt.pie(data.values(), labels=data.keys(), colors=chart_colors, 
                autopct='%1.1f%%', startangle=90)
        plt.axis('equal')
        
        # Save to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
        plt.close()
        
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        
        return image_base64