"""Integration tests for CLI commands."""

import pytest
import tempfile
import shutil
from pathlib import Path
from click.testing import CliRunner
from unittest.mock import patch, Mock

from src.cli.project_commands import project
from src.cli.client_commands import client
from src.core.project_manager import ProjectManager


class TestProjectCLI:
    """Integration tests for project CLI commands."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_path = tempfile.mkdtemp()
        yield Path(temp_path)
        shutil.rmtree(temp_path)
    
    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()
    
    @pytest.fixture
    def mock_manager(self, temp_dir):
        """Create a mock project manager."""
        with patch('src.cli.project_commands.ProjectManager') as mock:
            manager = ProjectManager(base_dir=temp_dir)
            mock.return_value = manager
            yield manager
    
    def test_project_create_command(self, runner, mock_manager):
        """Test project create command."""
        result = runner.invoke(project, [
            'create',
            '--name', 'Test Project',
            '--client', 'Test Client',
            '--url', 'https://example.com',
            '--description', 'Test description',
            '--tags', 'security',
            '--tags', 'web'
        ])
        
        assert result.exit_code == 0
        assert "✓ Created project: Test Project" in result.output
        assert "Client: Test Client" in result.output
        assert "Target: https://example.com" in result.output
    
    def test_project_list_command(self, runner, mock_manager):
        """Test project list command."""
        # Create some projects
        mock_manager.create_project(
            name="Project 1",
            client_name="Client A",
            target_url="https://example1.com"
        )
        mock_manager.create_project(
            name="Project 2",
            client_name="Client B",
            target_url="https://example2.com"
        )
        
        # Test list all
        result = runner.invoke(project, ['list'])
        assert result.exit_code == 0
        assert "Project 1" in result.output
        assert "Project 2" in result.output
        
        # Test list with filter
        result = runner.invoke(project, ['list', '--client', 'Client A'])
        assert result.exit_code == 0
        assert "Project 1" in result.output
        assert "Project 2" not in result.output
        
        # Test JSON output
        result = runner.invoke(project, ['list', '--format', 'json'])
        assert result.exit_code == 0
        assert '"name": "Project 1"' in result.output
    
    def test_project_info_command(self, runner, mock_manager):
        """Test project info command."""
        # Create a project
        project_obj = mock_manager.create_project(
            name="Test Project",
            client_name="Test Client",
            target_url="https://example.com",
            description="Test description",
            tags=["security", "web"]
        )
        
        # Test full ID
        result = runner.invoke(project, ['info', project_obj.id])
        assert result.exit_code == 0
        assert "Project: Test Project" in result.output
        assert "Client: Test Client" in result.output
        assert "Target URL: https://example.com" in result.output
        assert "Description:" in result.output
        assert "Tags: security, web" in result.output
        
        # Test partial ID
        partial_id = project_obj.id[:8]
        result = runner.invoke(project, ['info', partial_id])
        assert result.exit_code == 0
        assert "Project: Test Project" in result.output
    
    def test_project_update_command(self, runner, mock_manager):
        """Test project update command."""
        # Create a project
        project_obj = mock_manager.create_project(
            name="Original Name",
            client_name="Client",
            target_url="https://example.com"
        )
        
        # Update project
        result = runner.invoke(project, [
            'update', project_obj.id[:8],
            '--name', 'Updated Name',
            '--status', 'completed',
            '--add-tag', 'updated',
            '--add-tag', 'modified'
        ])
        
        assert result.exit_code == 0
        assert "✓ Updated project: Updated Name" in result.output
        
        # Verify update
        updated = mock_manager.get_project(project_obj.id)
        assert updated.name == "Updated Name"
        assert updated.status == "completed"
        assert "updated" in updated.tags
    
    def test_project_history_command(self, runner, mock_manager):
        """Test project history command."""
        # Create project with scans
        project_obj = mock_manager.create_project(
            name="Test Project",
            client_name="Client",
            target_url="https://example.com"
        )
        
        # Add scan results
        mock_manager.add_scan_result(
            project_id=project_obj.id,
            scan_type="quick",
            vulnerability_count={"High": 1, "Medium": 2, "Low": 3},
            risk_score=25.0,
            report_path="/scan1.json",
            duration=100.0
        )
        
        result = runner.invoke(project, ['history', project_obj.id[:8]])
        assert result.exit_code == 0
        assert "Scan history for: Test Project" in result.output
        assert "quick" in result.output
        assert "25.0" in result.output
    
    @patch('src.cli.project_commands.SecurityScanner')
    def test_project_scan_command(self, mock_scanner_class, runner, mock_manager):
        """Test project scan command."""
        # Create project
        project_obj = mock_manager.create_project(
            name="Test Project",
            client_name="Client",
            target_url="https://example.com"
        )
        
        # Mock scanner
        mock_scanner = Mock()
        mock_scanner.full_scan.return_value = {
            "alerts": [{"name": "Test", "risk": "High"}]
        }
        mock_scanner.calculate_risk_score.return_value = 50.0
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(project, [
            'scan', project_obj.id[:8],
            '--type', 'full'
        ])
        
        assert result.exit_code == 0
        assert "Starting full scan for project: Test Project" in result.output
        assert "Scan completed" in result.output
        assert "Risk Score:" in result.output
    
    def test_project_archive_command(self, runner, mock_manager):
        """Test project archive command."""
        # Create project
        project_obj = mock_manager.create_project(
            name="Test Project",
            client_name="Client",
            target_url="https://example.com"
        )
        
        result = runner.invoke(project, ['archive', project_obj.id[:8]])
        assert result.exit_code == 0
        assert "✓ Archived project: Test Project" in result.output
        
        # Verify archived
        archived = mock_manager.get_project(project_obj.id)
        assert archived.status == "archived"
    
    def test_project_delete_command(self, runner, mock_manager):
        """Test project delete command."""
        # Create project
        project_obj = mock_manager.create_project(
            name="Test Project",
            client_name="Client",
            target_url="https://example.com"
        )
        
        # Test soft delete
        result = runner.invoke(project, ['delete', project_obj.id[:8]])
        assert result.exit_code == 0
        assert "✓ Marked project as deleted: Test Project" in result.output
        
        # Test permanent delete with confirmation
        project_obj2 = mock_manager.create_project(
            name="Test Project 2",
            client_name="Client",
            target_url="https://example2.com"
        )
        
        result = runner.invoke(project, [
            'delete', project_obj2.id[:8],
            '--permanent'
        ], input='y\n')
        
        assert result.exit_code == 0
        assert "✓ Permanently deleted project: Test Project 2" in result.output
    
    @patch('src.cli.project_commands.ProjectScanner')
    def test_project_report_command(self, mock_scanner_class, runner, mock_manager):
        """Test project report command."""
        # Create project with scan
        project_obj = mock_manager.create_project(
            name="Test Project",
            client_name="Client",
            target_url="https://example.com"
        )
        
        # Mock scanner
        mock_scanner = Mock()
        mock_scanner.set_project.return_value = True
        mock_scanner.generate_report.return_value = Path("/tmp/report.html")
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(project, [
            'report', project_obj.id[:8],
            '--format', 'html'
        ])
        
        assert result.exit_code == 0
        assert "✓ Report generated:" in result.output
        assert "Report type: HTML" in result.output


class TestClientCLI:
    """Integration tests for client CLI commands."""
    
    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_path = tempfile.mkdtemp()
        yield Path(temp_path)
        shutil.rmtree(temp_path)
    
    @pytest.fixture
    def mock_manager(self, temp_dir):
        """Create a mock project manager."""
        with patch('src.cli.client_commands.ProjectManager') as mock:
            manager = ProjectManager(base_dir=temp_dir)
            mock.return_value = manager
            yield manager
    
    def test_client_add_command(self, runner, mock_manager):
        """Test client add command."""
        result = runner.invoke(client, [
            'add',
            '--name', 'ACME Corp',
            '--email', 'contact@acme.com',
            '--phone', '+1-555-1234',
            '--company', 'ACME Corporation',
            '--notes', 'Important client'
        ])
        
        assert result.exit_code == 0
        assert "✓ Added client: ACME Corp" in result.output
        assert "Email: contact@acme.com" in result.output
        assert "Company: ACME Corporation" in result.output
    
    def test_client_list_command(self, runner, mock_manager):
        """Test client list command."""
        # Add clients via direct DB access
        import sqlite3
        import uuid
        from datetime import datetime
        
        with sqlite3.connect(mock_manager.db_path) as conn:
            conn.execute("""
                INSERT INTO clients (id, name, contact_email, company, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                "Test Client",
                "test@example.com",
                "Test Corp",
                datetime.now().isoformat()
            ))
        
        result = runner.invoke(client, ['list'])
        assert result.exit_code == 0
        assert "Test Client" in result.output
        assert "Test Corp" in result.output
        assert "test@example.com" in result.output
    
    def test_client_info_command(self, runner, mock_manager):
        """Test client info command."""
        # Create client and projects
        import sqlite3
        import uuid
        from datetime import datetime
        
        client_name = "Test Client"
        
        # Add client
        with sqlite3.connect(mock_manager.db_path) as conn:
            conn.execute("""
                INSERT INTO clients (id, name, contact_email, company, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                client_name,
                "test@example.com",
                "Test Corp",
                "Important notes",
                datetime.now().isoformat()
            ))
        
        # Create projects for client
        mock_manager.create_project(
            name="Project 1",
            client_name=client_name,
            target_url="https://example1.com"
        )
        
        result = runner.invoke(client, ['info', client_name])
        assert result.exit_code == 0
        assert f"Client: {client_name}" in result.output
        assert "Email: test@example.com" in result.output
        assert "Company: Test Corp" in result.output
        assert "Notes:" in result.output
        assert "Important notes" in result.output
        assert "Projects (1):" in result.output
        assert "Project 1" in result.output
    
    def test_client_update_command(self, runner, mock_manager):
        """Test client update command."""
        # Add client
        import sqlite3
        import uuid
        from datetime import datetime
        
        client_name = "Test Client"
        
        with sqlite3.connect(mock_manager.db_path) as conn:
            conn.execute("""
                INSERT INTO clients (id, name, created_at)
                VALUES (?, ?, ?)
            """, (
                str(uuid.uuid4()),
                client_name,
                datetime.now().isoformat()
            ))
        
        result = runner.invoke(client, [
            'update', client_name,
            '--email', 'new@example.com',
            '--company', 'New Corp'
        ])
        
        assert result.exit_code == 0
        assert f"✓ Updated client: {client_name}" in result.output
    
    def test_client_report_command(self, runner, mock_manager):
        """Test client report command."""
        # Create client with projects and scans
        client_name = "Test Client"
        
        project = mock_manager.create_project(
            name="Test Project",
            client_name=client_name,
            target_url="https://example.com"
        )
        
        mock_manager.add_scan_result(
            project_id=project.id,
            scan_type="full",
            vulnerability_count={"High": 2, "Medium": 5},
            risk_score=45.0,
            report_path="/scan.json",
            duration=300.0
        )
        
        result = runner.invoke(client, [
            'report', client_name,
            '--format', 'summary'
        ])
        
        assert result.exit_code == 0
        assert "Client Security Report" in result.output
        assert f"Client: {client_name}" in result.output
        assert "Total Projects: 1" in result.output
        assert "Total Scans: 1" in result.output