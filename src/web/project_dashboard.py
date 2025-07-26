"""Web dashboard for project management and reporting."""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from typing import Optional, List
import json
from datetime import datetime

from ..core.project_manager import ProjectManager

app = FastAPI(title="Security Project Dashboard")

# Set up templates
templates_dir = Path(__file__).parent / "templates"
templates_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory=str(templates_dir))

# Static files
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Initialize project manager
project_manager = ProjectManager()


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
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "projects": projects,
        "stats": stats
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


# Create basic HTML templates
dashboard_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Project Dashboard</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 0;
            background: #f5f5f5;
        }
        .header {
            background: #2c3e50;
            color: white;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        .stat-label {
            color: #7f8c8d;
            margin-top: 5px;
        }
        .projects-table {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #ecf0f1;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 12px;
            border-top: 1px solid #ecf0f1;
        }
        .status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
        }
        .status-active {
            background: #d4edda;
            color: #155724;
        }
        .status-completed {
            background: #cce5ff;
            color: #004085;
        }
        .status-archived {
            background: #f8d7da;
            color: #721c24;
        }
        .risk-score {
            font-weight: bold;
        }
        .risk-high { color: #e74c3c; }
        .risk-medium { color: #f39c12; }
        .risk-low { color: #27ae60; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Project Dashboard</h1>
    </div>
    
    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_projects }}</div>
                <div class="stat-label">Total Projects</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.active_projects }}</div>
                <div class="stat-label">Active Projects</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_clients }}</div>
                <div class="stat-label">Total Clients</div>
            </div>
        </div>
        
        <div class="projects-table">
            <table>
                <thead>
                    <tr>
                        <th>Project</th>
                        <th>Client</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Last Updated</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for project in projects %}
                    <tr>
                        <td><strong>{{ project.name }}</strong></td>
                        <td>{{ project.client_name }}</td>
                        <td>{{ project.target_url }}</td>
                        <td>
                            <span class="status status-{{ project.status }}">
                                {{ project.status }}
                            </span>
                        </td>
                        <td>{{ project.updated_at }}</td>
                        <td>
                            <a href="/project/{{ project.id }}">View Details</a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>
"""

project_detail_template = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ project.name }} - Project Details</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 0;
            background: #f5f5f5;
        }
        .header {
            background: #2c3e50;
            color: white;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .project-info {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .scan-history {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .info-row {
            display: flex;
            margin-bottom: 10px;
        }
        .info-label {
            font-weight: bold;
            width: 150px;
            color: #7f8c8d;
        }
        .vulnerability-counts {
            display: flex;
            gap: 15px;
        }
        .vuln-count {
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
        }
        .vuln-high {
            background: #fee;
            color: #c00;
        }
        .vuln-medium {
            background: #ffeaa7;
            color: #d63031;
        }
        .vuln-low {
            background: #dfe6e9;
            color: #2d3436;
        }
        #timeline-chart {
            height: 300px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ project.name }}</h1>
        <a href="/" style="color: white;">← Back to Dashboard</a>
    </div>
    
    <div class="container">
        <div class="project-info">
            <h2>Project Information</h2>
            <div class="info-row">
                <div class="info-label">Client:</div>
                <div>{{ project.client_name }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Target URL:</div>
                <div>{{ project.target_url }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Status:</div>
                <div>{{ project.status }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Created:</div>
                <div>{{ project.created_at }}</div>
            </div>
            {% if project.description %}
            <div class="info-row">
                <div class="info-label">Description:</div>
                <div>{{ project.description }}</div>
            </div>
            {% endif %}
        </div>
        
        <div class="scan-history">
            <h2>Scan History</h2>
            <table style="width: 100%;">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Type</th>
                        <th>Duration</th>
                        <th>Risk Score</th>
                        <th>Vulnerabilities</th>
                    </tr>
                </thead>
                <tbody>
                    {% for scan in scans %}
                    <tr>
                        <td>{{ scan.scan_date }}</td>
                        <td>{{ scan.scan_type }}</td>
                        <td>{{ scan.duration }}s</td>
                        <td>{{ scan.risk_score }}/100</td>
                        <td>
                            <div class="vulnerability-counts">
                                <span class="vuln-count vuln-high">
                                    H: {{ scan.vulnerability_count.get('High', 0) }}
                                </span>
                                <span class="vuln-count vuln-medium">
                                    M: {{ scan.vulnerability_count.get('Medium', 0) }}
                                </span>
                                <span class="vuln-count vuln-low">
                                    L: {{ scan.vulnerability_count.get('Low', 0) }}
                                </span>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <div id="timeline-chart"></div>
        </div>
    </div>
    
    <script>
        // Fetch and display timeline chart
        fetch(`/api/project/{{ project.id }}/timeline`)
            .then(response => response.json())
            .then(data => {
                // Chart rendering would go here
                console.log('Timeline data:', data);
            });
    </script>
</body>
</html>
"""

# Save templates
(templates_dir / "dashboard.html").write_text(dashboard_template)
(templates_dir / "project_detail.html").write_text(project_detail_template)