"""CLI commands for project management."""

import click
import json
from pathlib import Path
from typing import Optional
from datetime import datetime
from tabulate import tabulate

from ..core.project_manager import ProjectManager
from ..core.project_scanner import ProjectScanner
from ..scanners.security import SecurityScanner
from ..scanners.technology_aware_scanner import TechnologyAwareScanner
from ..integrations.zap_client import ZAPClient


@click.group()
@click.pass_context
def project(ctx):
    """Manage security audit projects."""
    ctx.ensure_object(dict)
    ctx.obj['manager'] = ProjectManager()


@project.command()
@click.option('--name', required=True, help='Project name')
@click.option('--client', required=True, help='Client name')
@click.option('--url', required=True, help='Target URL')
@click.option('--description', help='Project description')
@click.option('--tags', multiple=True, help='Project tags')
@click.pass_context
def create(ctx, name: str, client: str, url: str, description: str, tags: tuple):
    """Create a new security audit project."""
    manager = ctx.obj['manager']
    
    # Check if client has existing projects
    existing = manager.get_client_projects(client)
    if existing:
        click.echo(f"Client '{client}' has {len(existing)} existing project(s)")
    
    # Create project
    project = manager.create_project(
        name=name,
        client_name=client,
        target_url=url,
        description=description or "",
        tags=list(tags)
    )
    
    click.echo(f"✓ Created project: {project.name}")
    click.echo(f"  ID: {project.id}")
    click.echo(f"  Client: {project.client_name}")
    click.echo(f"  Target: {project.target_url}")
    click.echo(f"  Directory: {manager.get_project_dir(project.id)}")


@project.command()
@click.option('--client', help='Filter by client')
@click.option('--status', type=click.Choice(['active', 'completed', 'archived']), 
              help='Filter by status')
@click.option('--tag', multiple=True, help='Filter by tags')
@click.option('--format', 'output_format', 
              type=click.Choice(['table', 'json', 'simple']), 
              default='table', help='Output format')
@click.pass_context
def list(ctx, client: Optional[str], status: Optional[str], 
         tag: tuple, output_format: str):
    """List all projects."""
    manager = ctx.obj['manager']
    
    projects = manager.list_projects(
        client_name=client,
        status=status,
        tags=list(tag) if tag else None
    )
    
    if output_format == 'json':
        click.echo(json.dumps([{
            'id': p.id,
            'name': p.name,
            'client': p.client_name,
            'url': p.target_url,
            'status': p.status,
            'updated': p.updated_at
        } for p in projects], indent=2))
    elif output_format == 'simple':
        for p in projects:
            click.echo(f"{p.id}: {p.name} ({p.client_name}) - {p.status}")
    else:  # table
        if not projects:
            click.echo("No projects found")
            return
        
        headers = ['ID', 'Name', 'Client', 'URL', 'Status', 'Updated']
        rows = []
        for p in projects:
            rows.append([
                p.id[:8] + '...',
                p.name[:30],
                p.client_name,
                p.target_url[:40] + '...' if len(p.target_url) > 40 else p.target_url,
                p.status,
                datetime.fromisoformat(p.updated_at).strftime('%Y-%m-%d %H:%M')
            ])
        
        click.echo(tabulate(rows, headers=headers, tablefmt='grid'))


@project.command()
@click.argument('project_id')
@click.pass_context
def info(ctx, project_id: str):
    """Show detailed project information."""
    manager = ctx.obj['manager']
    
    # Try to find project by ID or partial ID
    projects = manager.list_projects()
    matching = [p for p in projects if p.id.startswith(project_id)]
    
    if not matching:
        click.echo(f"Project not found: {project_id}")
        return
    
    if len(matching) > 1:
        click.echo("Multiple projects match:")
        for p in matching:
            click.echo(f"  {p.id}: {p.name}")
        return
    
    project = matching[0]
    scans = manager.get_project_scans(project.id)
    
    click.echo(f"\n{'=' * 60}")
    click.echo(f"Project: {project.name}")
    click.echo(f"{'=' * 60}")
    click.echo(f"ID: {project.id}")
    click.echo(f"Client: {project.client_name}")
    click.echo(f"Target URL: {project.target_url}")
    click.echo(f"Status: {project.status}")
    click.echo(f"Created: {project.created_at}")
    click.echo(f"Updated: {project.updated_at}")
    
    if project.description:
        click.echo(f"\nDescription:\n{project.description}")
    
    if project.tags:
        click.echo(f"\nTags: {', '.join(project.tags)}")
    
    if scans:
        click.echo(f"\nScan History ({len(scans)} scans):")
        click.echo("-" * 60)
        
        for scan in scans[:5]:  # Show last 5 scans
            vuln_summary = []
            for level, count in scan.vulnerability_count.items():
                if count > 0:
                    vuln_summary.append(f"{level}: {count}")
            
            click.echo(f"  {scan.scan_date} - {scan.scan_type}")
            click.echo(f"    Risk Score: {scan.risk_score:.1f}/100")
            click.echo(f"    Vulnerabilities: {', '.join(vuln_summary)}")
            click.echo(f"    Duration: {scan.duration:.1f}s")
    
    project_dir = manager.get_project_dir(project.id)
    click.echo(f"\nProject Directory: {project_dir}")


@project.command()
@click.argument('project_id')
@click.option('--type', 'scan_type', 
              type=click.Choice(['full', 'quick', 'passive', 'active', 'tech']),
              default='full', help='Type of scan to run')
@click.option('--output', help='Output file for results')
@click.pass_context
def scan(ctx, project_id: str, scan_type: str, output: Optional[str]):
    """Run security scan for a project."""
    manager = ctx.obj['manager']
    
    # Find project
    projects = manager.list_projects()
    matching = [p for p in projects if p.id.startswith(project_id)]
    
    if not matching:
        click.echo(f"Project not found: {project_id}")
        return
    
    project = matching[0]
    project_dir = manager.get_project_dir(project.id)
    
    click.echo(f"Starting {scan_type} scan for project: {project.name}")
    click.echo(f"Target: {project.target_url}")
    
    # Initialize scanner based on type
    start_time = datetime.now()
    
    try:
        if scan_type == 'tech':
            # Technology-aware scan
            zap_client = ZAPClient()
            scanner = TechnologyAwareScanner(zap_client)
            results = scanner.scan(project.target_url, {
                'run_whatweb': True,
                'run_nikto': True,
                'run_zap': True,
                'run_free_apis': True
            })
        else:
            # Standard ZAP scan
            scanner = SecurityScanner()
            
            if scan_type == 'quick':
                results = scanner.quick_scan(project.target_url)
            elif scan_type == 'passive':
                results = scanner.passive_scan(project.target_url)
            elif scan_type == 'active':
                results = scanner.active_scan(project.target_url)
            else:  # full
                results = scanner.full_scan(project.target_url)
    
    except Exception as e:
        click.echo(f"Scan failed: {e}")
        return
    
    duration = (datetime.now() - start_time).total_seconds()
    
    # Calculate vulnerability counts
    vuln_count = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    
    if 'alerts' in results:
        for alert in results['alerts']:
            risk = alert.get('risk', 'Informational')
            vuln_count[risk] = vuln_count.get(risk, 0) + 1
    elif 'analysis' in results:
        # Technology-aware scanner format
        vuln_count['Total'] = results['analysis'].get('total_vulnerabilities', 0)
    
    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    scan_dir = project_dir / 'scans'
    scan_file = scan_dir / f"scan_{scan_type}_{timestamp}.json"
    
    with open(scan_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Calculate risk score
    risk_score = scanner.calculate_risk_score(results) if hasattr(scanner, 'calculate_risk_score') else 0
    
    # Add to database
    scan_result = manager.add_scan_result(
        project_id=project.id,
        scan_type=scan_type,
        vulnerability_count=vuln_count,
        risk_score=risk_score,
        report_path=str(scan_file),
        duration=duration
    )
    
    # Display results
    click.echo(f"\nScan completed in {duration:.1f} seconds")
    click.echo(f"Risk Score: {risk_score:.1f}/100")
    click.echo("\nVulnerabilities found:")
    for level, count in vuln_count.items():
        if count > 0:
            click.echo(f"  {level}: {count}")
    
    click.echo(f"\nResults saved to: {scan_file}")
    
    # Save to custom output if specified
    if output:
        output_path = Path(output)
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"Results also saved to: {output_path}")


@project.command()
@click.argument('project_id')
@click.option('--limit', default=10, help='Number of scans to show')
@click.pass_context
def history(ctx, project_id: str, limit: int):
    """Show scan history for a project."""
    manager = ctx.obj['manager']
    
    # Find project
    projects = manager.list_projects()
    matching = [p for p in projects if p.id.startswith(project_id)]
    
    if not matching:
        click.echo(f"Project not found: {project_id}")
        return
    
    project = matching[0]
    scans = manager.get_project_scans(project.id)
    
    if not scans:
        click.echo("No scans found for this project")
        return
    
    click.echo(f"\nScan history for: {project.name}")
    click.echo("=" * 80)
    
    headers = ['Date', 'Type', 'Duration', 'Risk Score', 'High', 'Medium', 'Low', 'Info']
    rows = []
    
    for scan in scans[:limit]:
        scan_date = datetime.fromisoformat(scan.scan_date)
        rows.append([
            scan_date.strftime('%Y-%m-%d %H:%M'),
            scan.scan_type,
            f"{scan.duration:.1f}s",
            f"{scan.risk_score:.1f}",
            scan.vulnerability_count.get('High', 0),
            scan.vulnerability_count.get('Medium', 0),
            scan.vulnerability_count.get('Low', 0),
            scan.vulnerability_count.get('Informational', 0)
        ])
    
    click.echo(tabulate(rows, headers=headers, tablefmt='grid'))


@project.command()
@click.argument('project_id')
@click.option('--status', type=click.Choice(['active', 'completed', 'archived']))
@click.option('--name', help='Update project name')
@click.option('--description', help='Update description')
@click.option('--add-tag', multiple=True, help='Add tags')
@click.option('--remove-tag', multiple=True, help='Remove tags')
@click.pass_context
def update(ctx, project_id: str, status: Optional[str], name: Optional[str],
          description: Optional[str], add_tag: tuple, remove_tag: tuple):
    """Update project details."""
    manager = ctx.obj['manager']
    
    # Find project
    projects = manager.list_projects()
    matching = [p for p in projects if p.id.startswith(project_id)]
    
    if not matching:
        click.echo(f"Project not found: {project_id}")
        return
    
    project = matching[0]
    
    # Build update dict
    updates = {}
    if status:
        updates['status'] = status
    if name:
        updates['name'] = name
    if description is not None:
        updates['description'] = description
    
    # Handle tags
    if add_tag or remove_tag:
        tags = set(project.tags)
        tags.update(add_tag)
        tags.difference_update(remove_tag)
        updates['tags'] = list(tags)
    
    if not updates:
        click.echo("No updates specified")
        return
    
    # Update project
    updated = manager.update_project(project.id, **updates)
    
    if updated:
        click.echo(f"✓ Updated project: {updated.name}")
        for key, value in updates.items():
            click.echo(f"  {key}: {value}")
    else:
        click.echo("Failed to update project")


@project.command()
@click.argument('project_id')
@click.option('--export-path', type=click.Path(), help='Export path')
@click.pass_context
def archive(ctx, project_id: str, export_path: Optional[str]):
    """Archive a completed project."""
    manager = ctx.obj['manager']
    
    # Find project
    projects = manager.list_projects()
    matching = [p for p in projects if p.id.startswith(project_id)]
    
    if not matching:
        click.echo(f"Project not found: {project_id}")
        return
    
    project = matching[0]
    
    # Export if path specified
    if export_path:
        export_dir = Path(export_path)
        if manager.export_project(project.id, export_dir):
            click.echo(f"✓ Exported project to: {export_dir}")
        else:
            click.echo("Failed to export project")
            return
    
    # Archive
    if manager.archive_project(project.id):
        click.echo(f"✓ Archived project: {project.name}")
    else:
        click.echo("Failed to archive project")


@project.command()
@click.argument('project_id')
@click.option('--permanent', is_flag=True, help='Permanently delete project and data')
@click.pass_context
def delete(ctx, project_id: str, permanent: bool):
    """Delete a project."""
    manager = ctx.obj['manager']
    
    # Find project
    projects = manager.list_projects()
    matching = [p for p in projects if p.id.startswith(project_id)]
    
    if not matching:
        click.echo(f"Project not found: {project_id}")
        return
    
    project = matching[0]
    
    # Confirm
    if permanent:
        click.echo(f"WARNING: This will permanently delete project '{project.name}' and all data!")
        if not click.confirm("Are you sure?"):
            return
    
    # Delete
    if manager.delete_project(project.id, permanent=permanent):
        if permanent:
            click.echo(f"✓ Permanently deleted project: {project.name}")
        else:
            click.echo(f"✓ Marked project as deleted: {project.name}")
    else:
        click.echo("Failed to delete project")


@project.command()
@click.argument('project_id')
@click.option('--scan-id', help='Specific scan ID (default: latest)')
@click.option('--format', 'output_format', 
              type=click.Choice(['html', 'pdf', 'json']), 
              default='html', help='Report format')
@click.option('--output', help='Output file path')
@click.pass_context
def report(ctx, project_id: str, scan_id: Optional[str], 
          output_format: str, output: Optional[str]):
    """Generate a security report for a project."""
    manager = ctx.obj['manager']
    
    # Find project
    projects = manager.list_projects()
    matching = [p for p in projects if p.id.startswith(project_id)]
    
    if not matching:
        click.echo(f"Project not found: {project_id}")
        return
    
    project = matching[0]
    
    # Initialize project scanner
    scanner = ProjectScanner(manager)
    if not scanner.set_project(project.id):
        click.echo("Failed to set project")
        return
    
    try:
        # Generate report
        report_path = scanner.generate_report(scan_id=scan_id, format=output_format)
        
        # Copy to custom output if specified
        if output:
            import shutil
            output_path = Path(output)
            shutil.copy2(report_path, output_path)
            click.echo(f"✓ Report generated: {output_path}")
        else:
            click.echo(f"✓ Report generated: {report_path}")
        
        # Show report location
        click.echo(f"\nReport type: {output_format.upper()}")
        if output_format == 'html':
            click.echo(f"View in browser: file://{report_path.absolute()}")
        
    except Exception as e:
        click.echo(f"Error generating report: {e}")
        return