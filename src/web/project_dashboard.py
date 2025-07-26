"""Web dashboard for project management and reporting."""

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from typing import Optional, List, Dict, Any
import json
import asyncio
import uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from ..core.project_manager import ProjectManager
from ..core.project_scanner import ProjectScanner
from ..core.report_generator import ReportGenerator

app = FastAPI(title="Security Project Dashboard")

# Set up templates
templates_dir = Path(__file__).parent / "templates"
templates_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory=str(templates_dir))

# Static files
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Initialize project manager and scanner
project_manager = ProjectManager()
project_scanner = ProjectScanner(project_manager)

# Background task executor
executor = ThreadPoolExecutor(max_workers=4)

# Active scans tracking
active_scans = {}


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard showing all projects."""
    projects = project_manager.list_projects()
    
    # Calculate statistics
    stats = {
        "total_projects": len(projects),
        "active_projects": len([p for p in projects if p.status == "active"]),
        "total_clients": len(set(p.client_name for p in projects)),
        "recent_scans": []
    }
    
    # Get recent scans across all projects
    for project in projects[:5]:  # Last 5 projects
        scans = project_manager.get_project_scans(project.id)
        if scans:
            stats["recent_scans"].append({
                "project_name": project.name,
                "scan_date": scans[0].scan_date,
                "risk_score": scans[0].risk_score
            })
    
    # Get unique clients for filter
    clients = list(set(p.client_name for p in projects))
    
    return templates.TemplateResponse("enhanced_dashboard.html", {
        "request": request,
        "projects": projects,
        "stats": stats,
        "clients": clients
    })


@app.get("/api/projects")
async def get_projects(client: Optional[str] = None, status: Optional[str] = None):
    """API endpoint to get projects."""
    projects = project_manager.list_projects(client_name=client, status=status)
    return [
        {
            "id": p.id,
            "name": p.name,
            "client": p.client_name,
            "url": p.target_url,
            "status": p.status,
            "updated": p.updated_at,
            "tags": p.tags
        }
        for p in projects
    ]


@app.get("/api/project/{project_id}")
async def get_project(project_id: str):
    """Get detailed project information."""
    project = project_manager.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    scans = project_manager.get_project_scans(project_id)
    
    return {
        "project": {
            "id": project.id,
            "name": project.name,
            "client": project.client_name,
            "url": project.target_url,
            "description": project.description,
            "status": project.status,
            "created": project.created_at,
            "updated": project.updated_at,
            "tags": project.tags
        },
        "scans": [
            {
                "id": s.id,
                "type": s.scan_type,
                "date": s.scan_date,
                "duration": s.duration,
                "risk_score": s.risk_score,
                "vulnerabilities": s.vulnerability_count
            }
            for s in scans
        ]
    }


@app.get("/api/project/{project_id}/timeline")
async def get_project_timeline(project_id: str):
    """Get project scan timeline data."""
    scans = project_manager.get_project_scans(project_id)
    
    timeline_data = []
    for scan in scans:
        timeline_data.append({
            "date": scan.scan_date,
            "risk_score": scan.risk_score,
            "high": scan.vulnerability_count.get("High", 0),
            "medium": scan.vulnerability_count.get("Medium", 0),
            "low": scan.vulnerability_count.get("Low", 0)
        })
    
    return timeline_data


@app.get("/api/clients")
async def get_clients():
    """Get list of all clients."""
    projects = project_manager.list_projects()
    clients = {}
    
    for project in projects:
        if project.client_name not in clients:
            clients[project.client_name] = {
                "name": project.client_name,
                "project_count": 0,
                "last_activity": project.updated_at
            }
        
        clients[project.client_name]["project_count"] += 1
        if project.updated_at > clients[project.client_name]["last_activity"]:
            clients[project.client_name]["last_activity"] = project.updated_at
    
    return list(clients.values())


@app.get("/project/{project_id}", response_class=HTMLResponse)
async def project_detail(request: Request, project_id: str):
    """Project detail page."""
    project = project_manager.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    scans = project_manager.get_project_scans(project_id)
    project_dir = project_manager.get_project_dir(project_id)
    
    # Get available reports
    reports = []
    if project_dir:
        reports_dir = project_dir / "reports"
        if reports_dir.exists():
            reports = [
                {
                    "name": f.name,
                    "size": f.stat().st_size,
                    "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                }
                for f in reports_dir.glob("*")
            ]
    
    return templates.TemplateResponse("project_detail.html", {
        "request": request,
        "project": project,
        "scans": scans,
        "reports": reports
    })


@app.post("/api/projects")
async def create_project(project_data: Dict[str, Any]):
    """Create a new project."""
    try:
        project = project_manager.create_project(
            name=project_data["name"],
            client_name=project_data["client_name"],
            target_url=project_data["target_url"],
            description=project_data.get("description", ""),
            tags=project_data.get("tags", [])
        )
        return {
            "id": project.id,
            "name": project.name,
            "status": "created"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/project/{project_id}/scan")
async def start_scan(project_id: str, scan_config: Dict[str, Any], background_tasks: BackgroundTasks):
    """Start a security scan for a project."""
    project = project_manager.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Generate job ID
    job_id = str(uuid.uuid4())
    
    # Track active scan
    active_scans[job_id] = {
        "project_id": project_id,
        "project_name": project.name,
        "scan_type": scan_config.get("scan_type", "quick"),
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "progress": 0
    }
    
    # Run scan in background
    background_tasks.add_task(run_scan_task, job_id, project_id, scan_config)
    
    return {
        "job_id": job_id,
        "status": "started",
        "message": f"Scan started for project {project.name}"
    }


@app.get("/api/scans/active")
async def get_active_scans():
    """Get list of currently running scans."""
    return list(active_scans.values())


@app.get("/api/scan/{job_id}/status")
async def get_scan_status(job_id: str):
    """Get status of a specific scan job."""
    if job_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return active_scans[job_id]


@app.post("/api/project/{project_id}/report")
async def generate_project_report(project_id: str, report_config: Dict[str, Any]):
    """Generate a report for a project."""
    project = project_manager.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    scans = project_manager.get_project_scans(project_id)
    if not scans:
        raise HTTPException(status_code=400, detail="No scans found for this project")
    
    # Generate report
    try:
        generator = ReportGenerator()
        report_format = report_config.get("format", "pdf")
        
        # Prepare scan data
        scan_data = []
        for scan in scans[:5]:  # Last 5 scans
            if scan.report_path and Path(scan.report_path).exists():
                with open(scan.report_path, 'r') as f:
                    scan_results = json.load(f)
                    scan_data.append({
                        "scan_type": scan.scan_type,
                        "scan_date": scan.scan_date,
                        "results": scan_results
                    })
        
        if not scan_data:
            raise HTTPException(status_code=400, detail="No scan data available")
        
        # Generate report
        report_path = generator.generate(
            scan_data=scan_data[0]["results"],  # Use latest scan
            project_info={
                "name": project.name,
                "client": project.client_name,
                "url": project.target_url,
                "scan_date": scan_data[0]["scan_date"]
            },
            format=report_format
        )
        
        if report_path and report_path.exists():
            return FileResponse(
                path=str(report_path),
                media_type='application/pdf' if report_format == 'pdf' else 'text/html',
                filename=f"security-report-{project_id}.{report_format}"
            )
        else:
            raise HTTPException(status_code=500, detail="Failed to generate report")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/project/{project_id}")
async def delete_project(project_id: str, permanent: bool = False):
    """Delete or archive a project."""
    result = project_manager.delete_project(project_id, permanent=permanent)
    if not result:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {
        "status": "deleted" if permanent else "archived",
        "project_id": project_id
    }


# Background task for running scans
def run_scan_task(job_id: str, project_id: str, scan_config: Dict[str, Any]):
    """Run a scan in the background."""
    try:
        # Set active project
        project_scanner.set_project(project_id)
        
        # Update progress based on scan type
        scan_type = scan_config.get("scan_type", "quick")
        
        # Simulate progress updates for different scan stages
        if scan_type == "quick":
            progress_stages = [
                (10, "Initializing scanner"),
                (20, "Target reconnaissance"), 
                (40, "Port scanning"),
                (60, "Service detection"),
                (80, "Basic vulnerability scan"),
                (90, "Generating report")
            ]
        elif scan_type == "full":
            progress_stages = [
                (5, "Initializing scanner"),
                (10, "Target reconnaissance"),
                (15, "DNS enumeration"),
                (30, "Port scanning (all ports)"),
                (40, "Service detection"),
                (45, "OS fingerprinting"),
                (60, "Vulnerability scanning"),
                (70, "Web application scan"),
                (80, "SSL/TLS analysis"),
                (85, "Security headers check"),
                (95, "Generating comprehensive report")
            ]
        elif scan_type == "technology":
            progress_stages = [
                (10, "Initializing scanner"),
                (20, "Technology detection"),
                (35, "Framework identification"),
                (50, "Version fingerprinting"),
                (65, "Known CVE checking"),
                (80, "Technology-specific tests"),
                (90, "Dependency analysis"),
                (95, "Generating report")
            ]
        else:  # compliance
            progress_stages = [
                (10, "Initializing scanner"),
                (20, "OWASP Top 10 checks"),
                (30, "Authentication testing"),
                (40, "Authorization testing"),
                (50, "Session management"),
                (60, "Input validation"),
                (75, "Security configuration"),
                (85, "Compliance mapping"),
                (95, "Generating compliance report")
            ]
        
        # Update progress for first stage
        active_scans[job_id]["progress"] = progress_stages[0][0]
        active_scans[job_id]["current_stage"] = progress_stages[0][1]
        
        # Run the actual scan (this would normally update progress internally)
        # For now, we'll simulate progress updates
        import time
        
        # Simulate scan execution with progress updates
        for progress, stage in progress_stages[1:]:
            time.sleep(2)  # Simulate work being done
            if job_id in active_scans:
                active_scans[job_id]["progress"] = progress
                active_scans[job_id]["current_stage"] = stage
        
        # Run the actual scan with timeout
        import signal
        from contextlib import contextmanager
        
        @contextmanager
        def timeout(seconds):
            def signal_handler(signum, frame):
                raise TimeoutError("Scan timed out")
            
            # Set the signal handler and alarm
            signal.signal(signal.SIGALRM, signal_handler)
            signal.alarm(seconds)
            try:
                yield
            finally:
                signal.alarm(0)
        
        try:
            # Set timeout based on scan type
            scan_timeout = {
                "quick": 300,      # 5 minutes
                "full": 1800,      # 30 minutes
                "technology": 600,  # 10 minutes
                "compliance": 900   # 15 minutes
            }.get(scan_type, 600)
            
            with timeout(scan_timeout):
                results = project_scanner.scan(scan_type=scan_type)
        except TimeoutError:
            raise Exception(f"Scan timed out after {scan_timeout} seconds")
        
        # Update scan status
        active_scans[job_id]["status"] = "completed"
        active_scans[job_id]["progress"] = 100
        active_scans[job_id]["completed_at"] = datetime.now().isoformat()
        active_scans[job_id]["results"] = {
            "risk_score": results.get("risk_score", 0),
            "vulnerabilities": results.get("vulnerability_count", {})
        }
        
        # Generate report if requested
        if scan_config.get("generate_report", False):
            try:
                generator = ReportGenerator()
                report_path = generator.generate(
                    scan_data=results,
                    project_info={
                        "name": results["project"]["name"],
                        "client": results["project"]["client_name"],
                        "url": results["project"]["target_url"],
                        "scan_date": datetime.now().isoformat()
                    },
                    format="pdf"
                )
                active_scans[job_id]["report_path"] = str(report_path)
            except Exception as e:
                print(f"Failed to generate report: {e}")
        
        # Remove from active scans after 5 minutes
        asyncio.create_task(cleanup_scan_job(job_id))
        
    except Exception as e:
        active_scans[job_id]["status"] = "failed"
        active_scans[job_id]["error"] = str(e)
        active_scans[job_id]["completed_at"] = datetime.now().isoformat()


async def cleanup_scan_job(job_id: str):
    """Remove completed scan job after delay."""
    await asyncio.sleep(300)  # 5 minutes
    if job_id in active_scans:
        del active_scans[job_id]


# App startup event
@app.on_event("startup")
async def startup_event():
    """Initialize the application."""
    print("Security Project Dashboard started")
    print(f"Dashboard URL: http://localhost:8000")
    
# App shutdown event  
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    executor.shutdown(wait=True)