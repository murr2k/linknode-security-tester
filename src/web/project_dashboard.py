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
import time
import threading
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
        
        # Prepare data for new ReportGenerator
        project_data = {
            "id": project.id,
            "name": project.name,
            "client": project.client_name,  # ReportGenerator expects 'client' not 'client_name'
            "url": project.target_url  # ReportGenerator expects 'url' not 'target_url'
        }
        
        scan_meta = {
            "type": scans[0].scan_type,  # ReportGenerator expects 'type' not 'scan_type'
            "date": scan_data[0]["scan_date"],  # ReportGenerator expects 'date' not 'scan_date'
            "duration": scans[0].duration,
            "risk_score": scans[0].risk_score,
            "vulnerabilities": scans[0].vulnerability_count,
            "id": scans[0].id  # Add scan ID as well
        }
        
        # Initialize report generator with required arguments
        generator = ReportGenerator(
            project_data=project_data,
            scan_data=scan_meta,
            scan_results=scan_data[0]["results"]
        )
        
        # Generate report
        home_dir = Path.home()
        output_dir = home_dir / f".linknode-security/projects/{project_id}/reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"report_{report_format}_{timestamp}"
        
        report_path = generator.generate(format=report_format, output_path=output_path)
        
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
    import threading
    
    try:
        # Set active project
        project_scanner.set_project(project_id)
        
        # Update progress based on scan type
        scan_type = scan_config.get("scan_type", "quick")
        
        # Initialize scan data
        active_scans[job_id]["progress"] = 5
        active_scans[job_id]["current_stage"] = "Initializing scanner"
        active_scans[job_id]["phase_details"] = {
            "current_phase": "Initialization",
            "phase_progress": 0,
            "urls_found": 0,
            "vulnerabilities_found": 0,
            "elapsed_time": 0,
            "activity": "Starting security scan..."
        }
        
        # Create a thread to update scan progress
        def update_scan_progress():
            start_time = time.time()
            phase_start = time.time()
            
            while job_id in active_scans and active_scans[job_id]["status"] == "running":
                elapsed = int(time.time() - start_time)
                phase_elapsed = int(time.time() - phase_start)
                
                # Update elapsed time
                active_scans[job_id]["phase_details"]["elapsed_time"] = elapsed
                active_scans[job_id]["phase_details"]["phase_elapsed"] = phase_elapsed
                
                # Check ZAP for actual progress
                try:
                    if project_scanner.current_scanner and hasattr(project_scanner.current_scanner, 'zap_client'):
                        zap = project_scanner.current_scanner.zap_client.zap
                        
                        # Get spider progress
                        spider_status = zap.spider.status()
                        if spider_status and int(spider_status) < 100:
                            active_scans[job_id]["current_stage"] = "Spider scan"
                            active_scans[job_id]["phase_details"]["current_phase"] = "Spider Scan"
                            active_scans[job_id]["phase_details"]["phase_progress"] = int(spider_status)
                            active_scans[job_id]["phase_details"]["activity"] = f"Crawling website... {spider_status}%"
                            active_scans[job_id]["progress"] = 10 + (int(spider_status) * 0.1)
                        
                        # Get AJAX spider progress
                        ajax_status = zap.ajaxSpider.status()
                        if ajax_status and ajax_status != "stopped":
                            active_scans[job_id]["current_stage"] = "AJAX spider scan"
                            active_scans[job_id]["phase_details"]["current_phase"] = "AJAX Spider Scan"
                            active_scans[job_id]["phase_details"]["activity"] = "Analyzing JavaScript and dynamic content..."
                            active_scans[job_id]["progress"] = 20
                        
                        # Get URL count
                        urls_in_scope = len(zap.core.urls())
                        active_scans[job_id]["phase_details"]["urls_found"] = urls_in_scope
                        
                        # Get alert count
                        alerts = zap.core.alerts()
                        active_scans[job_id]["phase_details"]["vulnerabilities_found"] = len(alerts)
                    
                except Exception as e:
                    print(f"Progress update error: {e}")
                
                time.sleep(2)  # Update every 2 seconds
        
        # Start progress updater in background
        progress_thread = threading.Thread(target=update_scan_progress)
        progress_thread.daemon = True
        progress_thread.start()
        
        # Run the actual scan
        try:
            results = project_scanner.scan(scan_type=scan_type)
        except Exception as e:
            # Log the error but continue to update scan status
            print(f"Scan error: {e}")
            import traceback
            traceback.print_exc()
            raise
        
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
                # Prepare data for report generator
                project_data = {
                    "name": results["project"]["name"],
                    "client_name": results["project"]["client"],
                    "target_url": project_scanner.active_project.target_url,
                    "id": project_id
                }
                
                scan_data = {
                    "scan_type": scan_type,
                    "scan_date": datetime.now().isoformat(),
                    "duration": results.get("scan_duration", 0)
                }
                
                # Initialize report generator with required arguments
                generator = ReportGenerator(
                    project_data=project_data,
                    scan_data=scan_data,
                    scan_results=results
                )
                
                # Generate report
                home_dir = Path.home()
                output_dir = home_dir / f".linknode-security/projects/{project_id}/reports"
                output_dir.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = output_dir / f"report_{scan_type}_{timestamp}"
                
                report_path = generator.generate(format="pdf", output_path=output_path)
                active_scans[job_id]["report_path"] = str(report_path)
                print(f"Report generated: {report_path}")
            except Exception as e:
                print(f"Failed to generate report: {e}")
                import traceback
                traceback.print_exc()
        
        # Remove from active scans after 5 minutes
        # Note: Can't use asyncio in thread pool, schedule cleanup differently
        import threading
        def delayed_cleanup():
            time.sleep(300)  # 5 minutes
            if job_id in active_scans:
                del active_scans[job_id]
        
        cleanup_thread = threading.Thread(target=delayed_cleanup)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
    except Exception as e:
        active_scans[job_id]["status"] = "failed"
        active_scans[job_id]["error"] = str(e)
        active_scans[job_id]["completed_at"] = datetime.now().isoformat()


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