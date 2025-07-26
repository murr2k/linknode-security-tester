"""Unit tests for ReportGenerator class."""

import pytest
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, mock_open

from src.core.report_generator import ReportGenerator


class TestReportGenerator:
    """Test cases for ReportGenerator."""
    
    @pytest.fixture
    def project_data(self):
        """Sample project data."""
        return {
            "id": "test-project-123",
            "name": "Test Security Project",
            "client": "Test Client Corp",
            "url": "https://test.example.com",
            "description": "Test project for unit tests"
        }
    
    @pytest.fixture
    def scan_data(self):
        """Sample scan metadata."""
        return {
            "id": "scan-456",
            "type": "full",
            "date": "2024-01-26T14:30:00",
            "duration": 1800.5,
            "risk_score": 65.0,
            "vulnerabilities": {
                "High": 3,
                "Medium": 8,
                "Low": 15,
                "Informational": 5
            }
        }
    
    @pytest.fixture
    def scan_results_zap(self):
        """Sample scan results in ZAP format."""
        return {
            "alerts": [
                {
                    "name": "SQL Injection",
                    "risk": "High",
                    "confidence": "High",
                    "desc": "SQL injection vulnerability found",
                    "solution": "Use parameterized queries",
                    "reference": "https://owasp.org/sql-injection",
                    "cweid": 89,
                    "wascid": 19,
                    "instances": [
                        {"uri": "https://test.example.com/api/users?id=1"},
                        {"uri": "https://test.example.com/api/search"}
                    ]
                },
                {
                    "name": "Cross-Site Scripting",
                    "risk": "Medium",
                    "confidence": "Medium",
                    "desc": "XSS vulnerability detected",
                    "solution": "Encode output properly",
                    "reference": "https://owasp.org/xss",
                    "cweid": 79,
                    "wascid": 8,
                    "instances": [
                        {"uri": "https://test.example.com/comments"}
                    ]
                }
            ],
            "spider": {
                "urls": [
                    "https://test.example.com/",
                    "https://test.example.com/api",
                    "https://test.example.com/login"
                ]
            }
        }
    
    @pytest.fixture
    def scan_results_tech(self):
        """Sample scan results in technology scanner format."""
        return {
            "analysis": {
                "unique_vulnerabilities": [
                    {
                        "vulnerability": {
                            "name": "Outdated jQuery",
                            "severity": "medium",
                            "description": "jQuery version is outdated"
                        },
                        "remediation": "Update to latest jQuery version",
                        "references": ["https://jquery.com"],
                        "affected_files": ["index.html", "admin.html"],
                        "cwe_id": 1104
                    }
                ],
                "total_vulnerabilities": 1
            },
            "technologies": ["PHP", "MySQL", "jQuery"],
            "tech_stack": {
                "frontend": ["jQuery", "Bootstrap"],
                "backend": ["PHP"],
                "database": ["MySQL"]
            }
        }
    
    @pytest.fixture
    def report_generator(self, project_data, scan_data, scan_results_zap):
        """Create a ReportGenerator instance."""
        return ReportGenerator(project_data, scan_data, scan_results_zap)
    
    def test_initialization(self, report_generator, project_data, scan_data):
        """Test ReportGenerator initialization."""
        assert report_generator.project == project_data
        assert report_generator.scan == scan_data
        assert report_generator.results is not None
    
    def test_generate_json_report(self, report_generator, tmp_path):
        """Test JSON report generation."""
        output_path = tmp_path / "report.json"
        
        result = report_generator.generate("json", output_path)
        
        assert result == output_path
        assert output_path.exists()
        
        # Verify JSON content
        with open(output_path, 'r') as f:
            report_data = json.load(f)
        
        assert "metadata" in report_data
        assert "project" in report_data
        assert "scan" in report_data
        assert "results" in report_data
        assert "summary" in report_data
        assert "vulnerabilities" in report_data
        
        assert report_data["project"]["name"] == "Test Security Project"
        assert len(report_data["vulnerabilities"]) == 2
    
    def test_generate_html_report(self, report_generator, tmp_path):
        """Test HTML report generation."""
        output_path = tmp_path / "report.html"
        
        result = report_generator.generate("html", output_path)
        
        assert result == output_path
        assert output_path.exists()
        
        # Verify HTML content
        content = output_path.read_text()
        
        # Check key elements
        assert "<title>Security Report - Test Security Project</title>" in content
        assert "Executive Summary" in content
        assert "Project Information" in content
        assert "Vulnerability Distribution" in content
        assert "Detailed Findings" in content
        assert "Recommendations" in content
        
        # Check project details
        assert "Test Client Corp" in content
        assert "https://test.example.com" in content
        
        # Check vulnerabilities
        assert "SQL Injection" in content
        assert "Cross-Site Scripting" in content
    
    @patch('src.core.report_generator.HAS_WEASYPRINT', False)
    def test_generate_pdf_without_weasyprint(self, report_generator, tmp_path):
        """Test PDF generation fallback when WeasyPrint is not available."""
        output_path = tmp_path / "report.pdf"
        
        result = report_generator.generate("pdf", output_path)
        
        # Should fall back to HTML
        assert result.suffix == '.html'
        assert result.exists()
    
    def test_extract_vulnerabilities_zap_format(self, report_generator):
        """Test vulnerability extraction from ZAP format."""
        vulns = report_generator._extract_vulnerabilities()
        
        assert len(vulns) == 2
        assert vulns[0]["name"] == "SQL Injection"
        assert vulns[0]["risk"] == "High"
        assert vulns[0]["cwe"] == 89
        assert len(vulns[0]["instances"]) == 2
        
        assert vulns[1]["name"] == "Cross-Site Scripting"
        assert vulns[1]["risk"] == "Medium"
    
    def test_extract_vulnerabilities_tech_format(self, project_data, scan_data, 
                                               scan_results_tech):
        """Test vulnerability extraction from technology scanner format."""
        generator = ReportGenerator(project_data, scan_data, scan_results_tech)
        vulns = generator._extract_vulnerabilities()
        
        assert len(vulns) == 1
        assert vulns[0]["name"] == "Outdated jQuery"
        assert vulns[0]["risk"] == "Medium"
        assert vulns[0]["cwe"] == 1104
        assert len(vulns[0]["instances"]) == 2
    
    def test_generate_summary(self, report_generator):
        """Test summary generation."""
        summary = report_generator._generate_summary()
        
        assert summary["total_vulnerabilities"] == 31  # 3+8+15+5
        assert summary["critical_findings"] == 3  # High vulnerabilities
        assert summary["unique_issues"] == 2  # Number of unique vulnerabilities
        assert "scan_coverage" in summary
    
    def test_risk_level_calculation(self, report_generator):
        """Test risk level determination."""
        assert report_generator._get_risk_level(85) == "high"
        assert report_generator._get_risk_level(65) == "medium"
        assert report_generator._get_risk_level(25) == "low"
    
    def test_format_duration(self, report_generator):
        """Test duration formatting."""
        assert report_generator._format_duration(45.5) == "45.5 seconds"
        assert report_generator._format_duration(150) == "2.5 minutes"
        assert report_generator._format_duration(7200) == "2.0 hours"
    
    def test_severity_mapping(self, report_generator):
        """Test severity level mapping."""
        assert report_generator._map_severity("critical") == "Critical"
        assert report_generator._map_severity("high") == "High"
        assert report_generator._map_severity("medium") == "Medium"
        assert report_generator._map_severity("low") == "Low"
        assert report_generator._map_severity("info") == "Informational"
        assert report_generator._map_severity("unknown") == "Low"
    
    def test_technology_counting(self, project_data, scan_data, scan_results_tech):
        """Test technology detection counting."""
        generator = ReportGenerator(project_data, scan_data, scan_results_tech)
        
        tech_count = generator._count_technologies()
        assert tech_count == 3  # PHP, MySQL, jQuery
    
    def test_format_instances(self, report_generator):
        """Test instance formatting."""
        instances = [
            {"uri": "https://example.com/1"},
            {"uri": "https://example.com/2"},
            {"uri": "https://example.com/3"},
            {"uri": "https://example.com/4"},
            {"uri": "https://example.com/5"},
            {"uri": "https://example.com/6"}
        ]
        
        html = report_generator._format_instances(instances)
        
        assert "<h4>Affected Locations</h4>" in html
        assert "https://example.com/1" in html
        assert "https://example.com/5" in html
        assert "... and 1 more" in html  # Should show first 5 + count of remaining
    
    def test_recommendations_generation(self, report_generator):
        """Test recommendation generation based on findings."""
        summary = {
            "critical_findings": 3,
            "total_vulnerabilities": 31
        }
        
        html = report_generator._generate_recommendations_html(summary)
        
        assert "Address Critical Vulnerabilities" in html
        assert "3 critical/high severity vulnerabilities" in html
        assert "Review Medium Risk Findings" in html
        assert "Regular Security Scanning" in html
    
    def test_unsupported_format(self, report_generator, tmp_path):
        """Test handling of unsupported report format."""
        output_path = tmp_path / "report.xml"
        
        with pytest.raises(ValueError, match="Unsupported format: xml"):
            report_generator.generate("xml", output_path)
    
    @patch('src.core.report_generator.HAS_MATPLOTLIB', True)
    @patch('src.core.report_generator.plt')
    def test_chart_generation(self, mock_plt, report_generator):
        """Test chart generation when matplotlib is available."""
        mock_plt.figure.return_value = None
        mock_plt.pie.return_value = None
        mock_plt.savefig.return_value = None
        
        chart_data = report_generator._generate_vuln_pie_chart()
        
        assert chart_data is not None
        mock_plt.figure.assert_called_once()
        mock_plt.pie.assert_called_once()
    
    def test_empty_vulnerabilities(self, project_data, scan_data):
        """Test handling of scan with no vulnerabilities."""
        empty_results = {"alerts": []}
        generator = ReportGenerator(project_data, scan_data, empty_results)
        
        vulns = generator._extract_vulnerabilities()
        assert len(vulns) == 0
        
        html = generator._generate_findings_html(vulns)
        assert "No vulnerabilities found" in html