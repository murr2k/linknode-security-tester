"""Project management system for organizing security audits."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import shutil
import uuid

@dataclass
class Project:
    """Security audit project."""
    id: str
    name: str
    client_name: str
    target_url: str
    description: str
    created_at: str
    updated_at: str
    status: str  # active, completed, archived
    tags: List[str]
    metadata: Dict[str, Any]
    
    @classmethod
    def create(cls, name: str, client_name: str, target_url: str, 
               description: str = "", tags: List[str] = None) -> 'Project':
        """Create a new project."""
        now = datetime.now().isoformat()
        return cls(
            id=str(uuid.uuid4()),
            name=name,
            client_name=client_name,
            target_url=target_url,
            description=description,
            created_at=now,
            updated_at=now,
            status="active",
            tags=tags or [],
            metadata={}
        )


@dataclass
class ScanResult:
    """Individual scan result."""
    id: str
    project_id: str
    scan_type: str
    scan_date: str
    duration: float
    vulnerability_count: Dict[str, int]
    risk_score: float
    report_path: str
    metadata: Dict[str, Any]


class ProjectManager:
    """Manages security audit projects."""
    
    def __init__(self, base_dir: Path = None):
        """Initialize project manager.
        
        Args:
            base_dir: Base directory for projects (defaults to ~/.linknode-security)
        """
        self.base_dir = base_dir or Path.home() / ".linknode-security"
        self.base_dir.mkdir(exist_ok=True)
        
        self.db_path = self.base_dir / "projects.db"
        self.projects_dir = self.base_dir / "projects"
        self.projects_dir.mkdir(exist_ok=True)
        
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    client_name TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    tags TEXT,
                    metadata TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    duration REAL,
                    vulnerability_count TEXT,
                    risk_score REAL,
                    report_path TEXT,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects (id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    contact_email TEXT,
                    contact_phone TEXT,
                    company TEXT,
                    notes TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_project_client ON projects(client_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_project_status ON projects(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_project ON scan_results(project_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_results(scan_date)")
    
    def create_project(self, name: str, client_name: str, target_url: str,
                      description: str = "", tags: List[str] = None) -> Project:
        """Create a new project.
        
        Args:
            name: Project name
            client_name: Client name
            target_url: Target URL for security testing
            description: Project description
            tags: Project tags
            
        Returns:
            Created project
        """
        project = Project.create(name, client_name, target_url, description, tags)
        
        # Create project directory
        project_dir = self.projects_dir / project.id
        project_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (project_dir / "scans").mkdir(exist_ok=True)
        (project_dir / "reports").mkdir(exist_ok=True)
        (project_dir / "notes").mkdir(exist_ok=True)
        (project_dir / "screenshots").mkdir(exist_ok=True)
        
        # Save project config
        config_path = project_dir / "project.json"
        with open(config_path, 'w') as f:
            json.dump(asdict(project), f, indent=2)
        
        # Save to database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO projects (id, name, client_name, target_url, description,
                                    created_at, updated_at, status, tags, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                project.id, project.name, project.client_name, project.target_url,
                project.description, project.created_at, project.updated_at,
                project.status, json.dumps(project.tags), json.dumps(project.metadata)
            ))
        
        return project
    
    def get_project(self, project_id: str) -> Optional[Project]:
        """Get project by ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM projects WHERE id = ?", (project_id,)
            )
            row = cursor.fetchone()
            
            if row:
                return Project(
                    id=row[0],
                    name=row[1],
                    client_name=row[2],
                    target_url=row[3],
                    description=row[4],
                    created_at=row[5],
                    updated_at=row[6],
                    status=row[7],
                    tags=json.loads(row[8]),
                    metadata=json.loads(row[9])
                )
        return None
    
    def list_projects(self, client_name: Optional[str] = None,
                     status: Optional[str] = None,
                     tags: Optional[List[str]] = None) -> List[Project]:
        """List projects with optional filtering."""
        query = "SELECT * FROM projects WHERE 1=1"
        params = []
        
        if client_name:
            query += " AND client_name = ?"
            params.append(client_name)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY updated_at DESC"
        
        projects = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, params)
            for row in cursor:
                project = Project(
                    id=row[0],
                    name=row[1],
                    client_name=row[2],
                    target_url=row[3],
                    description=row[4],
                    created_at=row[5],
                    updated_at=row[6],
                    status=row[7],
                    tags=json.loads(row[8]),
                    metadata=json.loads(row[9])
                )
                
                # Filter by tags if specified
                if tags and not any(tag in project.tags for tag in tags):
                    continue
                    
                projects.append(project)
        
        return projects
    
    def update_project(self, project_id: str, **kwargs) -> Optional[Project]:
        """Update project fields."""
        project = self.get_project(project_id)
        if not project:
            return None
        
        # Update fields
        for key, value in kwargs.items():
            if hasattr(project, key):
                setattr(project, key, value)
        
        project.updated_at = datetime.now().isoformat()
        
        # Update database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE projects
                SET name = ?, client_name = ?, target_url = ?, description = ?,
                    updated_at = ?, status = ?, tags = ?, metadata = ?
                WHERE id = ?
            """, (
                project.name, project.client_name, project.target_url,
                project.description, project.updated_at, project.status,
                json.dumps(project.tags), json.dumps(project.metadata),
                project.id
            ))
        
        # Update project config file
        project_dir = self.projects_dir / project.id
        config_path = project_dir / "project.json"
        with open(config_path, 'w') as f:
            json.dump(asdict(project), f, indent=2)
        
        return project
    
    def add_scan_result(self, project_id: str, scan_type: str,
                       vulnerability_count: Dict[str, int], risk_score: float,
                       report_path: str, duration: float,
                       metadata: Dict[str, Any] = None) -> ScanResult:
        """Add scan result to project."""
        scan_result = ScanResult(
            id=str(uuid.uuid4()),
            project_id=project_id,
            scan_type=scan_type,
            scan_date=datetime.now().isoformat(),
            duration=duration,
            vulnerability_count=vulnerability_count,
            risk_score=risk_score,
            report_path=report_path,
            metadata=metadata or {}
        )
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO scan_results (id, project_id, scan_type, scan_date,
                                        duration, vulnerability_count, risk_score,
                                        report_path, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_result.id, scan_result.project_id, scan_result.scan_type,
                scan_result.scan_date, scan_result.duration,
                json.dumps(scan_result.vulnerability_count), scan_result.risk_score,
                scan_result.report_path, json.dumps(scan_result.metadata)
            ))
        
        # Update project's updated_at
        self.update_project(project_id, updated_at=datetime.now().isoformat())
        
        return scan_result
    
    def get_project_scans(self, project_id: str) -> List[ScanResult]:
        """Get all scan results for a project."""
        scans = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM scan_results WHERE project_id = ? ORDER BY scan_date DESC",
                (project_id,)
            )
            for row in cursor:
                scans.append(ScanResult(
                    id=row[0],
                    project_id=row[1],
                    scan_type=row[2],
                    scan_date=row[3],
                    duration=row[4],
                    vulnerability_count=json.loads(row[5]),
                    risk_score=row[6],
                    report_path=row[7],
                    metadata=json.loads(row[8])
                ))
        return scans
    
    def archive_project(self, project_id: str) -> bool:
        """Archive a project."""
        project = self.update_project(project_id, status="archived")
        if project:
            # Create archive
            project_dir = self.projects_dir / project_id
            archive_dir = self.base_dir / "archives"
            archive_dir.mkdir(exist_ok=True)
            
            archive_path = archive_dir / f"{project_id}_{datetime.now().strftime('%Y%m%d')}.tar.gz"
            
            import tarfile
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(project_dir, arcname=project_id)
            
            return True
        return False
    
    def delete_project(self, project_id: str, permanent: bool = False) -> bool:
        """Delete a project."""
        project = self.get_project(project_id)
        if not project:
            return False
        
        if permanent:
            # Delete from database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM scan_results WHERE project_id = ?", (project_id,))
                conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            
            # Delete files
            project_dir = self.projects_dir / project_id
            if project_dir.exists():
                shutil.rmtree(project_dir)
        else:
            # Soft delete - just change status
            self.update_project(project_id, status="deleted")
        
        return True
    
    def get_client_projects(self, client_name: str) -> List[Project]:
        """Get all projects for a client."""
        return self.list_projects(client_name=client_name)
    
    def get_project_dir(self, project_id: str) -> Optional[Path]:
        """Get project directory path."""
        project = self.get_project(project_id)
        if project:
            return self.projects_dir / project_id
        return None
    
    def export_project(self, project_id: str, export_path: Path) -> bool:
        """Export project data."""
        project = self.get_project(project_id)
        if not project:
            return False
        
        project_dir = self.projects_dir / project_id
        scans = self.get_project_scans(project_id)
        
        export_data = {
            "project": asdict(project),
            "scans": [asdict(scan) for scan in scans],
            "export_date": datetime.now().isoformat()
        }
        
        # Create export directory
        export_path.mkdir(parents=True, exist_ok=True)
        
        # Export metadata
        with open(export_path / "project_export.json", 'w') as f:
            json.dump(export_data, f, indent=2)
        
        # Copy project files
        if project_dir.exists():
            shutil.copytree(project_dir, export_path / "files", dirs_exist_ok=True)
        
        return True