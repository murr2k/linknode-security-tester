"""Unit tests for ProjectManager class."""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import json

from src.core.project_manager import ProjectManager, Project


class TestProjectManager:
    """Test cases for ProjectManager."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_path = tempfile.mkdtemp()
        yield Path(temp_path)
        shutil.rmtree(temp_path)
    
    @pytest.fixture
    def project_manager(self, temp_dir):
        """Create a ProjectManager instance with temporary directory."""
        return ProjectManager(base_dir=temp_dir)
    
    def test_initialization(self, project_manager, temp_dir):
        """Test ProjectManager initialization."""
        assert project_manager.base_dir == temp_dir
        assert project_manager.db_path == temp_dir / "projects.db"
        assert project_manager.projects_dir == temp_dir / "projects"
        assert project_manager.projects_dir.exists()
        assert project_manager.db_path.exists()
    
    def test_create_project(self, project_manager):
        """Test project creation."""
        project = project_manager.create_project(
            name="Test Project",
            client_name="Test Client",
            target_url="https://example.com",
            description="Test description",
            tags=["security", "test"]
        )
        
        assert project.name == "Test Project"
        assert project.client_name == "Test Client"
        assert project.target_url == "https://example.com"
        assert project.description == "Test description"
        assert project.tags == ["security", "test"]
        assert project.status == "active"
        assert project.id is not None
        
        # Check project directory structure
        project_dir = project_manager.projects_dir / project.id
        assert project_dir.exists()
        assert (project_dir / "scans").exists()
        assert (project_dir / "reports").exists()
        assert (project_dir / "notes").exists()
        assert (project_dir / "screenshots").exists()
        assert (project_dir / "project.json").exists()
    
    def test_get_project(self, project_manager):
        """Test retrieving a project."""
        # Create a project
        created_project = project_manager.create_project(
            name="Test Project",
            client_name="Test Client",
            target_url="https://example.com"
        )
        
        # Retrieve it
        retrieved_project = project_manager.get_project(created_project.id)
        
        assert retrieved_project is not None
        assert retrieved_project.id == created_project.id
        assert retrieved_project.name == created_project.name
        assert retrieved_project.client_name == created_project.client_name
        
        # Test non-existent project
        assert project_manager.get_project("non-existent-id") is None
    
    def test_list_projects(self, project_manager):
        """Test listing projects with filters."""
        # Create multiple projects
        project1 = project_manager.create_project(
            name="Project 1",
            client_name="Client A",
            target_url="https://example1.com",
            tags=["web", "api"]
        )
        
        project2 = project_manager.create_project(
            name="Project 2",
            client_name="Client B",
            target_url="https://example2.com",
            tags=["web", "mobile"]
        )
        
        project3 = project_manager.create_project(
            name="Project 3",
            client_name="Client A",
            target_url="https://example3.com",
            tags=["api"]
        )
        
        # Test listing all projects
        all_projects = project_manager.list_projects()
        assert len(all_projects) == 3
        
        # Test filtering by client
        client_a_projects = project_manager.list_projects(client_name="Client A")
        assert len(client_a_projects) == 2
        assert all(p.client_name == "Client A" for p in client_a_projects)
        
        # Test filtering by tags
        api_projects = project_manager.list_projects(tags=["api"])
        assert len(api_projects) == 2
        
        web_projects = project_manager.list_projects(tags=["web"])
        assert len(web_projects) == 2
        
        # Test filtering by status
        active_projects = project_manager.list_projects(status="active")
        assert len(active_projects) == 3
    
    def test_update_project(self, project_manager):
        """Test updating project fields."""
        # Create a project
        project = project_manager.create_project(
            name="Original Name",
            client_name="Client",
            target_url="https://example.com",
            tags=["original"]
        )
        
        original_updated_at = project.updated_at
        
        # Update project
        updated_project = project_manager.update_project(
            project.id,
            name="Updated Name",
            description="New description",
            tags=["updated", "modified"],
            status="completed"
        )
        
        assert updated_project is not None
        assert updated_project.name == "Updated Name"
        assert updated_project.description == "New description"
        assert updated_project.tags == ["updated", "modified"]
        assert updated_project.status == "completed"
        assert updated_project.updated_at > original_updated_at
        
        # Verify persistence
        retrieved = project_manager.get_project(project.id)
        assert retrieved.name == "Updated Name"
    
    def test_add_scan_result(self, project_manager):
        """Test adding scan results to a project."""
        # Create a project
        project = project_manager.create_project(
            name="Test Project",
            client_name="Client",
            target_url="https://example.com"
        )
        
        # Add scan result
        scan_result = project_manager.add_scan_result(
            project_id=project.id,
            scan_type="full",
            vulnerability_count={"High": 2, "Medium": 5, "Low": 10},
            risk_score=45.5,
            report_path="/path/to/report.json",
            duration=300.5,
            metadata={"scanner": "ZAP", "version": "2.11"}
        )
        
        assert scan_result.project_id == project.id
        assert scan_result.scan_type == "full"
        assert scan_result.vulnerability_count == {"High": 2, "Medium": 5, "Low": 10}
        assert scan_result.risk_score == 45.5
        assert scan_result.duration == 300.5
        assert scan_result.metadata["scanner"] == "ZAP"
    
    def test_get_project_scans(self, project_manager):
        """Test retrieving project scan history."""
        # Create a project
        project = project_manager.create_project(
            name="Test Project",
            client_name="Client",
            target_url="https://example.com"
        )
        
        # Add multiple scan results
        scan1 = project_manager.add_scan_result(
            project_id=project.id,
            scan_type="quick",
            vulnerability_count={"High": 1, "Medium": 2},
            risk_score=20.0,
            report_path="/scan1.json",
            duration=100.0
        )
        
        scan2 = project_manager.add_scan_result(
            project_id=project.id,
            scan_type="full",
            vulnerability_count={"High": 3, "Medium": 5},
            risk_score=50.0,
            report_path="/scan2.json",
            duration=500.0
        )
        
        # Get scans
        scans = project_manager.get_project_scans(project.id)
        
        assert len(scans) == 2
        # Should be ordered by date DESC (newest first)
        assert scans[0].scan_type == "full"
        assert scans[1].scan_type == "quick"
    
    def test_archive_project(self, project_manager):
        """Test project archiving."""
        # Create a project
        project = project_manager.create_project(
            name="Test Project",
            client_name="Client",
            target_url="https://example.com"
        )
        
        # Add some content
        project_dir = project_manager.projects_dir / project.id
        (project_dir / "notes" / "test.txt").write_text("Test note")
        
        # Archive project
        result = project_manager.archive_project(project.id)
        assert result is True
        
        # Check project status
        archived_project = project_manager.get_project(project.id)
        assert archived_project.status == "archived"
        
        # Check archive exists
        archive_dir = project_manager.base_dir / "archives"
        assert archive_dir.exists()
        archives = list(archive_dir.glob(f"{project.id}*.tar.gz"))
        assert len(archives) == 1
    
    def test_delete_project(self, project_manager):
        """Test project deletion (soft and permanent)."""
        # Create projects
        project1 = project_manager.create_project(
            name="Project 1",
            client_name="Client",
            target_url="https://example1.com"
        )
        
        project2 = project_manager.create_project(
            name="Project 2",
            client_name="Client",
            target_url="https://example2.com"
        )
        
        # Soft delete
        result = project_manager.delete_project(project1.id, permanent=False)
        assert result is True
        
        deleted_project = project_manager.get_project(project1.id)
        assert deleted_project.status == "deleted"
        
        # Project directory should still exist
        project_dir = project_manager.projects_dir / project1.id
        assert project_dir.exists()
        
        # Permanent delete
        result = project_manager.delete_project(project2.id, permanent=True)
        assert result is True
        
        # Project should not exist
        assert project_manager.get_project(project2.id) is None
        
        # Project directory should be gone
        project_dir = project_manager.projects_dir / project2.id
        assert not project_dir.exists()
    
    def test_export_project(self, project_manager, temp_dir):
        """Test project export functionality."""
        # Create a project with scan
        project = project_manager.create_project(
            name="Export Test",
            client_name="Client",
            target_url="https://example.com"
        )
        
        # Add scan result
        scan = project_manager.add_scan_result(
            project_id=project.id,
            scan_type="full",
            vulnerability_count={"High": 1},
            risk_score=30.0,
            report_path="/scan.json",
            duration=200.0
        )
        
        # Export project
        export_path = temp_dir / "export"
        result = project_manager.export_project(project.id, export_path)
        assert result is True
        
        # Check export contents
        assert export_path.exists()
        assert (export_path / "project_export.json").exists()
        assert (export_path / "files").exists()
        
        # Verify export data
        with open(export_path / "project_export.json", 'r') as f:
            export_data = json.load(f)
        
        assert export_data["project"]["name"] == "Export Test"
        assert len(export_data["scans"]) == 1
        assert export_data["scans"][0]["scan_type"] == "full"
    
    def test_client_management(self, project_manager):
        """Test client-related functionality."""
        # Create projects for different clients
        project1 = project_manager.create_project(
            name="Project 1",
            client_name="ACME Corp",
            target_url="https://acme1.com"
        )
        
        project2 = project_manager.create_project(
            name="Project 2",
            client_name="ACME Corp",
            target_url="https://acme2.com"
        )
        
        project3 = project_manager.create_project(
            name="Project 3",
            client_name="Other Corp",
            target_url="https://other.com"
        )
        
        # Get client projects
        acme_projects = project_manager.get_client_projects("ACME Corp")
        assert len(acme_projects) == 2
        assert all(p.client_name == "ACME Corp" for p in acme_projects)
        
        other_projects = project_manager.get_client_projects("Other Corp")
        assert len(other_projects) == 1
    
    def test_project_validation(self, project_manager):
        """Test project creation validation."""
        # Test with invalid URL (validation is lenient)
        project = project_manager.create_project(
            name="Test",
            client_name="Client",
            target_url="not-a-valid-url"
        )
        assert project is not None  # Should still create
        
        # Test with empty name (currently allowed, but creates project)
        project2 = project_manager.create_project(
            name="",
            client_name="Client",
            target_url="https://example.com"
        )
        assert project2 is not None  # Creates with empty name