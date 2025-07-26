#!/usr/bin/env python3
"""Create a project for Murray Kopit website security scan."""

from src.core.project_manager import ProjectManager
from src.core.project_scanner import ProjectScanner

# Initialize project manager
project_manager = ProjectManager()

# Create the project
project = project_manager.create_project(
    name="Murray Kopit Website Security Scan",
    client_name="Murray Kopit",
    target_url="https://murraykopit.com",
    description="Security assessment of personal website murraykopit.com",
    tags=["personal", "website", "security-scan"]
)

print(f"✓ Created project: {project.name}")
print(f"  Project ID: {project.id}")
print(f"  Client: {project.client_name}")
print(f"  Target URL: {project.target_url}")
print(f"  Status: {project.status}")
print(f"  Created: {project.created_at}")

# Initialize project scanner
scanner = ProjectScanner(project_manager)

# Set the active project
if scanner.set_project(project.id):
    print(f"\n✓ Project scanner initialized")
    print(f"  Project directory: {scanner.project_dir}")
    print(f"  Ready to run security scans")
else:
    print("\n✗ Failed to initialize project scanner")

print("\nProject created successfully! You can now run scans using the project ID.")
print(f"\nTo run a quick scan:")
print(f"  python3 main.py scan {project.target_url} --project-id {project.id}")
print(f"\nTo run a full scan:")
print(f"  python3 main.py scan {project.target_url} --scan-types security quality --project-id {project.id}")