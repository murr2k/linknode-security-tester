"""CLI commands for client management."""

import click
from typing import Optional
from tabulate import tabulate
from datetime import datetime

from ..core.project_manager import ProjectManager


@click.group()
@click.pass_context
def client(ctx):
    """Manage clients."""
    ctx.ensure_object(dict)
    ctx.obj['manager'] = ProjectManager()


@client.command()
@click.option('--name', required=True, help='Client name')
@click.option('--email', help='Contact email')
@click.option('--phone', help='Contact phone')
@click.option('--company', help='Company name')
@click.option('--notes', help='Additional notes')
@click.pass_context
def add(ctx, name: str, email: Optional[str], phone: Optional[str], 
        company: Optional[str], notes: Optional[str]):
    """Add a new client."""
    manager = ctx.obj['manager']
    
    import sqlite3
    import uuid
    
    client_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()
    
    try:
        with sqlite3.connect(manager.db_path) as conn:
            conn.execute("""
                INSERT INTO clients (id, name, contact_email, contact_phone, 
                                   company, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (client_id, name, email, phone, company, notes, created_at))
        
        click.echo(f"✓ Added client: {name}")
        click.echo(f"  ID: {client_id}")
        if email:
            click.echo(f"  Email: {email}")
        if company:
            click.echo(f"  Company: {company}")
    
    except sqlite3.IntegrityError:
        click.echo(f"Error: Client '{name}' already exists")


@client.command()
@click.pass_context
def list(ctx):
    """List all clients."""
    manager = ctx.obj['manager']
    
    import sqlite3
    
    with sqlite3.connect(manager.db_path) as conn:
        cursor = conn.execute("""
            SELECT c.*, COUNT(p.id) as project_count
            FROM clients c
            LEFT JOIN projects p ON c.name = p.client_name
            GROUP BY c.id
            ORDER BY c.name
        """)
        
        clients = cursor.fetchall()
    
    if not clients:
        click.echo("No clients found")
        return
    
    headers = ['Name', 'Company', 'Email', 'Projects', 'Created']
    rows = []
    
    for client in clients:
        rows.append([
            client[1],  # name
            client[4] or '-',  # company
            client[2] or '-',  # email
            client[7],  # project_count
            datetime.fromisoformat(client[6]).strftime('%Y-%m-%d')
        ])
    
    click.echo(tabulate(rows, headers=headers, tablefmt='grid'))


@client.command()
@click.argument('client_name')
@click.pass_context
def info(ctx, client_name: str):
    """Show detailed client information."""
    manager = ctx.obj['manager']
    
    import sqlite3
    
    # Get client info
    with sqlite3.connect(manager.db_path) as conn:
        cursor = conn.execute(
            "SELECT * FROM clients WHERE name = ?", (client_name,)
        )
        client_data = cursor.fetchone()
    
    if not client_data:
        click.echo(f"Client not found: {client_name}")
        return
    
    # Display client info
    click.echo(f"\n{'=' * 60}")
    click.echo(f"Client: {client_data[1]}")
    click.echo(f"{'=' * 60}")
    click.echo(f"ID: {client_data[0]}")
    if client_data[2]:  # email
        click.echo(f"Email: {client_data[2]}")
    if client_data[3]:  # phone
        click.echo(f"Phone: {client_data[3]}")
    if client_data[4]:  # company
        click.echo(f"Company: {client_data[4]}")
    click.echo(f"Added: {client_data[6]}")
    if client_data[5]:  # notes
        click.echo(f"\nNotes:\n{client_data[5]}")
    
    # Get client projects
    projects = manager.get_client_projects(client_name)
    
    if projects:
        click.echo(f"\nProjects ({len(projects)}):")
        click.echo("-" * 60)
        
        headers = ['Name', 'URL', 'Status', 'Last Updated']
        rows = []
        
        for project in projects:
            rows.append([
                project.name,
                project.target_url[:40] + '...' if len(project.target_url) > 40 else project.target_url,
                project.status,
                datetime.fromisoformat(project.updated_at).strftime('%Y-%m-%d %H:%M')
            ])
        
        click.echo(tabulate(rows, headers=headers, tablefmt='simple'))
        
        # Calculate statistics
        total_scans = 0
        total_vulns = {'High': 0, 'Medium': 0, 'Low': 0}
        
        for project in projects:
            scans = manager.get_project_scans(project.id)
            total_scans += len(scans)
            
            for scan in scans:
                for level, count in scan.vulnerability_count.items():
                    if level in total_vulns:
                        total_vulns[level] += count
        
        click.echo(f"\nStatistics:")
        click.echo(f"  Total scans performed: {total_scans}")
        click.echo(f"  Total vulnerabilities found:")
        click.echo(f"    High: {total_vulns['High']}")
        click.echo(f"    Medium: {total_vulns['Medium']}")
        click.echo(f"    Low: {total_vulns['Low']}")


@client.command()
@click.argument('client_name')
@click.option('--email', help='Update email')
@click.option('--phone', help='Update phone')
@click.option('--company', help='Update company')
@click.option('--notes', help='Update notes')
@click.pass_context
def update(ctx, client_name: str, email: Optional[str], phone: Optional[str],
          company: Optional[str], notes: Optional[str]):
    """Update client information."""
    manager = ctx.obj['manager']
    
    import sqlite3
    
    # Build update query
    updates = []
    params = []
    
    if email is not None:
        updates.append("contact_email = ?")
        params.append(email)
    if phone is not None:
        updates.append("contact_phone = ?")
        params.append(phone)
    if company is not None:
        updates.append("company = ?")
        params.append(company)
    if notes is not None:
        updates.append("notes = ?")
        params.append(notes)
    
    if not updates:
        click.echo("No updates specified")
        return
    
    params.append(client_name)
    
    with sqlite3.connect(manager.db_path) as conn:
        cursor = conn.execute(
            f"UPDATE clients SET {', '.join(updates)} WHERE name = ?",
            params
        )
        
        if cursor.rowcount == 0:
            click.echo(f"Client not found: {client_name}")
        else:
            click.echo(f"✓ Updated client: {client_name}")


@client.command()
@click.argument('client_name')
@click.option('--force', is_flag=True, help='Force delete without confirmation')
@click.pass_context
def delete(ctx, client_name: str, force: bool):
    """Delete a client."""
    manager = ctx.obj['manager']
    
    # Check for existing projects
    projects = manager.get_client_projects(client_name)
    
    if projects and not force:
        click.echo(f"Warning: Client '{client_name}' has {len(projects)} project(s)")
        click.echo("This will NOT delete the projects, but they will be orphaned.")
        if not click.confirm("Continue?"):
            return
    
    import sqlite3
    
    with sqlite3.connect(manager.db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM clients WHERE name = ?", (client_name,)
        )
        
        if cursor.rowcount == 0:
            click.echo(f"Client not found: {client_name}")
        else:
            click.echo(f"✓ Deleted client: {client_name}")
            if projects:
                click.echo(f"  Note: {len(projects)} project(s) still exist")


@client.command()
@click.argument('client_name')
@click.option('--format', 'output_format', 
              type=click.Choice(['summary', 'detailed', 'json']),
              default='summary', help='Report format')
@click.option('--output', help='Output file')
@click.pass_context
def report(ctx, client_name: str, output_format: str, output: Optional[str]):
    """Generate client security report."""
    manager = ctx.obj['manager']
    
    import json
    
    # Get client data
    projects = manager.get_client_projects(client_name)
    
    if not projects:
        click.echo(f"No projects found for client: {client_name}")
        return
    
    # Compile report data
    report_data = {
        "client": client_name,
        "generated": datetime.now().isoformat(),
        "projects": [],
        "summary": {
            "total_projects": len(projects),
            "total_scans": 0,
            "total_vulnerabilities": {'High': 0, 'Medium': 0, 'Low': 0},
            "average_risk_score": 0
        }
    }
    
    risk_scores = []
    
    for project in projects:
        scans = manager.get_project_scans(project.id)
        
        project_data = {
            "name": project.name,
            "url": project.target_url,
            "status": project.status,
            "scan_count": len(scans),
            "last_scan": scans[0].scan_date if scans else None,
            "vulnerabilities": {'High': 0, 'Medium': 0, 'Low': 0}
        }
        
        for scan in scans:
            for level, count in scan.vulnerability_count.items():
                if level in project_data["vulnerabilities"]:
                    project_data["vulnerabilities"][level] += count
                    report_data["summary"]["total_vulnerabilities"][level] += count
            
            if scan.risk_score > 0:
                risk_scores.append(scan.risk_score)
        
        report_data["projects"].append(project_data)
        report_data["summary"]["total_scans"] += len(scans)
    
    if risk_scores:
        report_data["summary"]["average_risk_score"] = sum(risk_scores) / len(risk_scores)
    
    # Generate output
    if output_format == 'json':
        output_text = json.dumps(report_data, indent=2)
    elif output_format == 'detailed':
        output_text = generate_detailed_report(report_data)
    else:  # summary
        output_text = generate_summary_report(report_data)
    
    if output:
        Path(output).write_text(output_text)
        click.echo(f"Report saved to: {output}")
    else:
        click.echo(output_text)


def generate_summary_report(data):
    """Generate summary text report."""
    report = f"""
Client Security Report
======================
Client: {data['client']}
Generated: {datetime.fromisoformat(data['generated']).strftime('%Y-%m-%d %H:%M')}

Summary
-------
Total Projects: {data['summary']['total_projects']}
Total Scans: {data['summary']['total_scans']}
Average Risk Score: {data['summary']['average_risk_score']:.1f}/100

Total Vulnerabilities Found:
  High: {data['summary']['total_vulnerabilities']['High']}
  Medium: {data['summary']['total_vulnerabilities']['Medium']}
  Low: {data['summary']['total_vulnerabilities']['Low']}

Projects
--------
"""
    
    for project in data['projects']:
        report += f"\n{project['name']} ({project['url']})\n"
        report += f"  Status: {project['status']}\n"
        report += f"  Scans: {project['scan_count']}\n"
        report += f"  Vulnerabilities: "
        report += f"H:{project['vulnerabilities']['High']} "
        report += f"M:{project['vulnerabilities']['Medium']} "
        report += f"L:{project['vulnerabilities']['Low']}\n"
    
    return report


def generate_detailed_report(data):
    """Generate detailed text report."""
    # Would include more detailed information
    # For now, return summary
    return generate_summary_report(data)