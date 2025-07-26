# Project Management Guide

This guide covers the project management features introduced in v2.0.0 of Linknode Security Tester.

## Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
- [Project Lifecycle](#project-lifecycle)
- [Client Management](#client-management)
- [Scanning Workflows](#scanning-workflows)
- [Report Generation](#report-generation)
- [Best Practices](#best-practices)
- [Advanced Features](#advanced-features)

## Overview

The project management system allows you to:
- Organize security audits by project and client
- Track vulnerability trends over time
- Generate professional reports for clients
- Maintain isolated scanning environments
- Configure per-project authentication and settings

## Getting Started

### Creating Your First Project

```bash
# Create a new project
python main.py project create \
  --name "Website Security Audit" \
  --client "Example Corp" \
  --url "https://example.com" \
  --description "Initial security assessment" \
  --tags production --tags web
```

This creates:
- A unique project ID
- Project directory at `~/.linknode-security/projects/<project-id>/`
- Subdirectories for scans, reports, notes, and screenshots
- Initial configuration file

### Project Directory Structure

```
~/.linknode-security/
├── projects.db              # SQLite database
├── projects/
│   └── <project-id>/
│       ├── project.json     # Project metadata
│       ├── config/
│       │   └── scan_config.json
│       ├── scans/           # Scan results
│       ├── reports/         # Generated reports
│       ├── notes/           # Manual notes
│       └── screenshots/     # Evidence screenshots
└── archives/                # Archived projects
```

## Project Lifecycle

### 1. Planning Phase

Create a project with detailed information:

```bash
python main.py project create \
  --name "Q1 2024 Security Assessment" \
  --client "ACME Corporation" \
  --url "https://app.acme.com" \
  --description "Quarterly security audit including API endpoints" \
  --tags quarterly --tags api --tags webapp
```

### 2. Configuration Phase

Each project can have custom scan settings. Edit `~/.linknode-security/projects/<project-id>/config/scan_config.json`:

```json
{
  "scan_defaults": {
    "timeout": 600,
    "max_depth": 15,
    "parallel": true
  },
  "exclusions": [
    "*.pdf",
    "*.jpg",
    "/admin/*",
    "/logout"
  ],
  "custom_headers": {
    "X-API-Key": "your-api-key",
    "User-Agent": "Security-Audit-Bot"
  },
  "authentication": {
    "type": "form",
    "login_url": "https://app.acme.com/login",
    "login_data": "username={%username%}&password={%password%}",
    "username": "audit_user",
    "password": "secure_password"
  }
}
```

### 3. Scanning Phase

Run different types of scans based on your needs:

```bash
# Quick scan (passive only, ~5 minutes)
python main.py project scan <project-id> --type quick

# Full scan (active + passive, ~30-60 minutes)
python main.py project scan <project-id> --type full

# Technology detection scan
python main.py project scan <project-id> --type tech

# Custom scan with specific options
python main.py project scan <project-id> --type full --output custom-scan.json
```

### 4. Analysis Phase

View scan history and trends:

```bash
# Show project details and recent scans
python main.py project info <project-id>

# Show detailed scan history
python main.py project history <project-id> --limit 20

# List all projects with filters
python main.py project list --client "ACME Corporation" --status active
```

### 5. Reporting Phase

Generate professional reports:

```bash
# Generate HTML report (best for viewing)
python main.py project report <project-id> --format html

# Generate PDF report (best for sharing)
python main.py project report <project-id> --format pdf

# Generate JSON report (best for automation)
python main.py project report <project-id> --format json --output report.json

# Generate report for specific scan
python main.py project report <project-id> --scan-id <scan-id>
```

### 6. Completion Phase

Archive or export completed projects:

```bash
# Mark project as completed
python main.py project update <project-id> --status completed

# Archive project (creates compressed backup)
python main.py project archive <project-id>

# Export project data
python main.py project archive <project-id> --export-path /backup/acme-q1-2024/

# Soft delete (marks as deleted but keeps data)
python main.py project delete <project-id>

# Permanent delete (removes all data)
python main.py project delete <project-id> --permanent
```

## Client Management

### Managing Clients

```bash
# Add a new client
python main.py client add \
  --name "ACME Corporation" \
  --email "security@acme.com" \
  --phone "+1-555-0123" \
  --company "ACME Corp International" \
  --notes "Quarterly audits required, contact John Doe"

# List all clients
python main.py client list

# View client details and all projects
python main.py client info "ACME Corporation"

# Update client information
python main.py client update "ACME Corporation" \
  --email "newsecurity@acme.com" \
  --notes "New security contact: Jane Smith"
```

### Client Reporting

Generate comprehensive security reports for clients:

```bash
# Summary report (overview of all projects)
python main.py client report "ACME Corporation" --format summary

# Detailed report (includes all vulnerabilities)
python main.py client report "ACME Corporation" --format detailed

# Export as JSON for integration
python main.py client report "ACME Corporation" --format json --output acme-report.json
```

## Scanning Workflows

### Authenticated Scanning

For applications requiring login:

1. Configure authentication in `scan_config.json`
2. Set up form-based authentication:
   ```json
   {
     "authentication": {
       "type": "form",
       "login_url": "https://app.example.com/login",
       "login_data": "email={%username%}&password={%password%}",
       "username": "test@example.com",
       "password": "test123"
     }
   }
   ```

3. Or use bearer token authentication:
   ```json
   {
     "authentication": {
       "type": "bearer",
       "token": "eyJhbGciOiJIUzI1NiIs..."
     }
   }
   ```

### Progressive Scanning

Start with quick scans and progressively increase depth:

```bash
# Day 1: Quick passive scan
python main.py project scan <project-id> --type quick

# Day 2: Full passive scan
python main.py project scan <project-id> --type passive

# Day 3: Active scan (after client approval)
python main.py project scan <project-id> --type active

# Day 4: Full comprehensive scan
python main.py project scan <project-id> --type full
```

### API Testing

For API-focused projects:

1. Configure API headers:
   ```json
   {
     "custom_headers": {
       "Authorization": "Bearer token",
       "X-API-Version": "v2",
       "Content-Type": "application/json"
     }
   }
   ```

2. Run technology-aware scan:
   ```bash
   python main.py project scan <project-id> --type tech
   ```

## Report Generation

### Report Types

1. **Executive Summary** (HTML/PDF)
   - High-level risk overview
   - Critical findings summary
   - Recommended actions
   - Trend analysis

2. **Technical Report** (HTML/PDF)
   - Detailed vulnerability descriptions
   - Proof of concept examples
   - Remediation steps
   - CWE/WASC references

3. **Data Export** (JSON)
   - Machine-readable format
   - Integration with other tools
   - Custom processing

### Customizing Reports

Reports include:
- Project and client information
- Executive summary with risk score
- Vulnerability distribution charts
- Detailed findings by severity
- Recommendations based on findings
- Scan metadata and coverage

### Report Delivery

```bash
# Generate and email report (requires email configuration)
python main.py project report <project-id> --format pdf --email security@client.com

# Generate multiple formats
python main.py project report <project-id> --format html
python main.py project report <project-id> --format pdf
python main.py project report <project-id> --format json
```

## Best Practices

### 1. Project Naming Convention

Use descriptive names with dates:
- "ACME Corp Q1 2024 Security Audit"
- "Example.com API Security Assessment 2024-01"
- "Production Web App Quarterly Scan - Jan 2024"

### 2. Tagging Strategy

Use consistent tags for better organization:
- Environment: `production`, `staging`, `development`
- Type: `web`, `api`, `mobile`
- Frequency: `quarterly`, `monthly`, `annual`
- Compliance: `pci-dss`, `hipaa`, `sox`

### 3. Scan Scheduling

- **Monthly**: Quick scans for critical applications
- **Quarterly**: Full comprehensive scans
- **After deployments**: Targeted scans on changed components
- **Annual**: Complete infrastructure assessment

### 4. Documentation

Add notes to projects:
```bash
# Create a note file
echo "Discovered new API endpoint during scan" > note.txt

# Copy to project notes
cp note.txt ~/.linknode-security/projects/<project-id>/notes/
```

### 5. Evidence Collection

Save screenshots and evidence:
```bash
# Copy screenshots to project
cp screenshot.png ~/.linknode-security/projects/<project-id>/screenshots/
```

## Advanced Features

### Bulk Operations

```bash
# Archive all completed projects
for project in $(python main.py project list --status completed --format simple | cut -d: -f1); do
  python main.py project archive $project
done

# Generate reports for all active projects
for project in $(python main.py project list --status active --format simple | cut -d: -f1); do
  python main.py project report $project --format pdf
done
```

### Integration with CI/CD

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Security Scan
        run: |
          python main.py project scan ${{ secrets.PROJECT_ID }} --type full
      - name: Generate Report
        run: |
          python main.py project report ${{ secrets.PROJECT_ID }} --format pdf
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.pdf
```

### Database Queries

The SQLite database can be queried directly for custom reports:

```sql
-- Find high-risk projects
SELECT p.name, p.client_name, MAX(s.risk_score) as max_risk
FROM projects p
JOIN scan_results s ON p.id = s.project_id
WHERE p.status = 'active'
GROUP BY p.id
HAVING max_risk > 70
ORDER BY max_risk DESC;

-- Vulnerability trends by client
SELECT p.client_name, 
       s.scan_date,
       SUM(json_extract(s.vulnerability_count, '$.High')) as high_vulns
FROM projects p
JOIN scan_results s ON p.id = s.project_id
GROUP BY p.client_name, date(s.scan_date)
ORDER BY p.client_name, s.scan_date;
```

### Backup and Recovery

```bash
# Backup entire project database
cp ~/.linknode-security/projects.db ~/.linknode-security/projects.db.backup

# Backup specific project
tar -czf project-backup.tar.gz ~/.linknode-security/projects/<project-id>/

# Restore project
tar -xzf project-backup.tar.gz -C ~/.linknode-security/projects/
```

## Troubleshooting

### Common Issues

1. **Project not found**
   - Use partial project ID: `python main.py project info abc123`
   - List all projects: `python main.py project list`

2. **Scan fails with authentication error**
   - Verify credentials in `scan_config.json`
   - Test login manually in browser
   - Check for session timeout settings

3. **Report generation fails**
   - Ensure at least one scan exists
   - Check disk space for reports directory
   - Verify WeasyPrint is installed for PDF generation

4. **Database locked error**
   - Close other instances of the tool
   - Check file permissions
   - Use `fuser ~/.linknode-security/projects.db` to find processes

### Debug Mode

Enable debug logging:
```bash
export LINKNODE_DEBUG=true
python main.py project scan <project-id>
```

## Security Considerations

1. **Credential Storage**: Store passwords securely using environment variables or secret management tools
2. **Access Control**: Restrict access to `~/.linknode-security/` directory
3. **Data Retention**: Implement retention policies for old projects
4. **Scan Authorization**: Always obtain written permission before scanning
5. **Report Distribution**: Use encrypted channels for report delivery

---

For more information, see the [main README](../README.md) or [Architecture Guide](ARCHITECTURE.md).