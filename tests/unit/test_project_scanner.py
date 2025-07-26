"""Unit tests for ProjectScanner class."""

import pytest
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.core.project_scanner import ProjectScanner
from src.core.project_manager import ProjectManager


class TestProjectScanner:
    """Test cases for ProjectScanner."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_path = tempfile.mkdtemp()
        yield Path(temp_path)
        shutil.rmtree(temp_path)
    
    @pytest.fixture
    def project_manager(self, temp_dir):
        """Create a ProjectManager instance."""
        return ProjectManager(base_dir=temp_dir)
    
    @pytest.fixture
    def project_scanner(self, project_manager):
        """Create a ProjectScanner instance."""
        return ProjectScanner(project_manager)
    
    @pytest.fixture
    def test_project(self, project_manager):
        """Create a test project."""
        return project_manager.create_project(
            name="Test Security Project",
            client_name="Test Client",
            target_url="https://test.example.com",
            description="Test project for scanner"
        )
    
    def test_initialization(self, project_scanner, project_manager):
        """Test ProjectScanner initialization."""
        assert project_scanner.project_manager == project_manager
        assert project_scanner.active_project is None
        assert project_scanner.project_dir is None
        assert project_scanner.temp_dir is None
    
    def test_set_project(self, project_scanner, test_project):
        """Test setting active project."""
        # Set valid project
        result = project_scanner.set_project(test_project.id)
        assert result is True
        assert project_scanner.active_project.id == test_project.id
        assert project_scanner.project_dir is not None
        assert project_scanner.temp_dir is not None
        
        # Test project environment setup
        config_file = project_scanner.project_dir / "config" / "scan_config.json"
        assert config_file.exists()
        
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        assert "scan_defaults" in config
        assert "exclusions" in config
        assert config["authentication"]["type"] == "none"
        
        # Test invalid project
        result = project_scanner.set_project("non-existent-id")
        assert result is False
    
    @patch('src.core.project_scanner.ZAPClient')
    @patch('src.core.project_scanner.SecurityScanner')
    def test_scan_quick(self, mock_scanner_class, mock_zap_client, project_scanner, test_project):
        """Test quick scan execution."""
        # Setup
        project_scanner.set_project(test_project.id)
        
        # Mock scanner
        mock_scanner = Mock()
        mock_scanner.quick_scan.return_value = {
            "alerts": [
                {"name": "Test Alert", "risk": "High"}
            ],
            "scan_duration": 100.5
        }
        mock_scanner_class.return_value = mock_scanner
        
        # Run scan
        results = project_scanner.scan(scan_type="quick")
        
        # Verify
        assert "project" in results
        assert results["project"]["id"] == test_project.id
        mock_scanner.quick_scan.assert_called_once_with(test_project.target_url)
        
        # Check scan was saved
        scans = project_scanner.project_manager.get_project_scans(test_project.id)
        assert len(scans) == 1
        assert scans[0].scan_type == "quick"
    
    @patch('src.core.project_scanner.TechnologyAwareScanner')
    @patch('src.core.project_scanner.ZAPClient')
    def test_scan_technology(self, mock_zap_client, mock_tech_scanner_class, 
                           project_scanner, test_project):
        """Test technology-aware scan."""
        # Setup
        project_scanner.set_project(test_project.id)
        
        # Mock scanner
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {
            "analysis": {
                "unique_vulnerabilities": [
                    {
                        "vulnerability": {
                            "name": "SQL Injection",
                            "severity": "high"
                        }
                    }
                ],
                "total_vulnerabilities": 1
            },
            "scan_duration": 200.0
        }
        mock_tech_scanner_class.return_value = mock_scanner
        
        # Run scan
        results = project_scanner.scan(scan_type="technology")
        
        # Verify
        assert "project" in results
        mock_scanner.scan.assert_called_once()
    
    def test_scan_with_options(self, project_scanner, test_project):
        """Test scan with custom options."""
        project_scanner.set_project(test_project.id)
        
        # Update project config
        config_file = project_scanner.project_dir / "config" / "scan_config.json"
        config = {
            "scan_defaults": {
                "timeout": 600,
                "max_depth": 5
            },
            "custom_headers": {
                "X-Custom-Header": "test-value"
            },
            "exclusions": ["*.pdf", "*.jpg"],
            "authentication": {"type": "none"}
        }
        
        with open(config_file, 'w') as f:
            json.dump(config, f)
        
        # Reload config
        project_scanner._setup_project_environment()
        
        assert project_scanner.project_config["scan_defaults"]["timeout"] == 600
        assert project_scanner.project_config["custom_headers"]["X-Custom-Header"] == "test-value"
    
    @patch('src.core.project_scanner.ZAPClient')
    def test_authentication_configuration(self, mock_zap_class, project_scanner, test_project):
        """Test authentication configuration."""
        project_scanner.set_project(test_project.id)
        
        # Mock ZAP client
        mock_zap = Mock()
        mock_zap.zap = Mock()
        mock_zap.zap.core = Mock()
        mock_zap.zap.context = Mock()
        mock_zap.zap.authentication = Mock()
        mock_zap.zap.users = Mock()
        mock_zap.zap.replacer = Mock()
        
        mock_zap.zap.context.new_context.return_value = "1"
        mock_zap.zap.users.new_user.return_value = "1"
        
        # Test form-based auth
        auth_config = {
            "type": "form",
            "login_url": "https://test.example.com/login",
            "login_data": "username={%username%}&password={%password%}",
            "username": "testuser",
            "password": "testpass"
        }
        
        project_scanner._configure_authentication(mock_zap, auth_config)
        
        mock_zap.zap.context.new_context.assert_called_once()
        mock_zap.zap.authentication.set_authentication_method.assert_called_once()
        mock_zap.zap.users.new_user.assert_called_once()
        
        # Test bearer token auth
        mock_zap.reset_mock()
        
        bearer_config = {
            "type": "bearer",
            "token": "test-token-123"
        }
        
        project_scanner._configure_authentication(mock_zap, bearer_config)
        
        mock_zap.zap.replacer.add_rule.assert_called_once()
        call_args = mock_zap.zap.replacer.add_rule.call_args[1]
        assert call_args["replacement"] == "Bearer test-token-123"
    
    def test_vulnerability_count_calculation(self, project_scanner, test_project):
        """Test vulnerability count calculation."""
        project_scanner.set_project(test_project.id)
        
        # Test ZAP format
        zap_results = {
            "alerts": [
                {"risk": "High"},
                {"risk": "High"},
                {"risk": "Medium"},
                {"risk": "Low"},
                {"risk": "Informational"}
            ]
        }
        
        counts = project_scanner._calculate_vulnerability_count(zap_results)
        assert counts["High"] == 2
        assert counts["Medium"] == 1
        assert counts["Low"] == 1
        assert counts["Informational"] == 1
        
        # Test technology scanner format
        tech_results = {
            "analysis": {
                "unique_vulnerabilities": [
                    {"vulnerability": {"severity": "high"}},
                    {"vulnerability": {"severity": "medium"}},
                    {"vulnerability": {"severity": "medium"}},
                    {"vulnerability": {"severity": "low"}}
                ]
            }
        }
        
        counts = project_scanner._calculate_vulnerability_count(tech_results)
        assert counts["High"] == 1
        assert counts["Medium"] == 2
        assert counts["Low"] == 1
    
    def test_risk_score_calculation(self, project_scanner, test_project):
        """Test risk score calculation."""
        project_scanner.set_project(test_project.id)
        
        # Test with explicit risk score
        results = {"risk_score": 75.5}
        score = project_scanner._calculate_risk_score(results)
        assert score == 75.5
        
        # Test calculation from vulnerabilities
        results = {
            "alerts": [
                {"risk": "High"},
                {"risk": "High"},
                {"risk": "Medium"},
                {"risk": "Low"}
            ]
        }
        
        score = project_scanner._calculate_risk_score(results)
        # 2*10 + 1*5 + 1*2 = 27
        assert score == 27.0
    
    @patch('src.core.project_scanner.ReportGenerator')
    def test_generate_report(self, mock_generator_class, project_scanner, 
                           test_project, project_manager):
        """Test report generation."""
        project_scanner.set_project(test_project.id)
        
        # Create a mock scan result
        scan_data = {"alerts": [{"name": "Test", "risk": "High"}]}
        scan_file = project_scanner.project_dir / "scans" / "test_scan.json"
        scan_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(scan_file, 'w') as f:
            json.dump(scan_data, f)
        
        # Add scan to project
        scan_result = project_manager.add_scan_result(
            project_id=test_project.id,
            scan_type="test",
            vulnerability_count={"High": 1},
            risk_score=10.0,
            report_path=str(scan_file),
            duration=100.0
        )
        
        # Mock report generator
        mock_generator = Mock()
        mock_generator.generate.return_value = Path("/tmp/report.html")
        mock_generator_class.return_value = mock_generator
        
        # Generate report
        report_path = project_scanner.generate_report(format="html")
        
        # Verify
        mock_generator_class.assert_called_once()
        mock_generator.generate.assert_called_once()
        assert "html" in mock_generator.generate.call_args[0]
    
    def test_scan_isolation(self, project_scanner, project_manager):
        """Test that scans are isolated between projects."""
        # Create two projects
        project1 = project_manager.create_project(
            name="Project 1",
            client_name="Client 1",
            target_url="https://example1.com"
        )
        
        project2 = project_manager.create_project(
            name="Project 2",
            client_name="Client 2",
            target_url="https://example2.com"
        )
        
        # Set project 1
        project_scanner.set_project(project1.id)
        temp_dir1 = project_scanner.temp_dir
        
        # Set project 2
        project_scanner.set_project(project2.id)
        temp_dir2 = project_scanner.temp_dir
        
        # Temp directories should be different
        assert temp_dir1 != temp_dir2
    
    def test_scan_without_active_project(self, project_scanner):
        """Test scanning without setting a project."""
        with pytest.raises(RuntimeError, match="No active project set"):
            project_scanner.scan()
    
    def test_generate_report_without_scans(self, project_scanner, test_project):
        """Test report generation when no scans exist."""
        project_scanner.set_project(test_project.id)
        
        with pytest.raises(ValueError, match="No scans found"):
            project_scanner.generate_report()