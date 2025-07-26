# Linknode Security Tester

A comprehensive website quality and penetration testing tool powered by OWASP ZAP technology. Designed to perform automated security assessments, identify vulnerabilities, and provide actionable remediation guidance.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![OWASP ZAP](https://img.shields.io/badge/OWASP%20ZAP-2.14.0+-green.svg)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)
![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🚀 Features

### Core Security Testing
- **Automated Security Scanning**: Comprehensive vulnerability detection using OWASP ZAP
- **OWASP Top 10 Compliance**: Check for the most critical web application security risks
- **Spider Crawling**: Automatic discovery of all accessible pages and endpoints
- **Active & Passive Scanning**: Both non-intrusive analysis and active vulnerability testing
- **Technology Detection**: Identify frameworks, libraries, and potential vulnerabilities
- **Risk Scoring**: Intelligent risk assessment with prioritized remediation guidance

### Project Management (v2.0+)
- **Project Organization**: Organize security audits by project and client
- **Scan History**: Track all scans with vulnerability trends over time
- **Client Management**: Manage multiple clients and their projects
- **Isolated Scanning**: Each project has its own isolated scanning environment
- **Custom Configurations**: Per-project scan settings and authentication

### Reporting & Export
- **Professional Reports**: Generate HTML, PDF, and JSON reports with executive summaries
- **Vulnerability Analytics**: Charts and graphs showing vulnerability distribution
- **Export & Archive**: Export project data and archive completed assessments
- **Custom Branding**: Add your logo and customize report templates

### Integration Features
- **Docker Support**: Easy deployment with Docker Compose
- **CLI Interface**: Full-featured command-line interface
- **Web Dashboard**: Browser-based project management interface
- **CI/CD Ready**: GitHub Actions and Jenkins integration support
- **API Access**: RESTful API for automation

## 📋 Prerequisites

- Python 3.10 or higher
- Docker and Docker Compose
- 4GB RAM minimum (8GB recommended)
- Internet connection for package installation

## 🛠️ Installation

### Quick Start (Recommended)

```bash
# Clone the repository
git clone https://github.com/murr2k/linknode-security-tester.git
cd linknode-security-tester

# Run the setup script
chmod +x setup.sh
./setup.sh
```

### Manual Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start OWASP ZAP
docker run -u zap -p 8080:8080 -d owasp/zap2docker-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=changeme
```

### Docker Compose Installation

```bash
# Start all services
docker-compose up -d

# Run a scan
docker-compose exec linknode-tester python main.py scan https://example.com
```

## 💻 Usage

### Project Management

#### Create a New Project
```bash
# Create a security audit project
python main.py project create \
  --name "Q1 Security Audit" \
  --client "ACME Corp" \
  --url "https://acme.example.com" \
  --description "Quarterly security assessment" \
  --tags web --tags api

# List all projects
python main.py project list

# View project details
python main.py project info <project-id>
```

#### Run Project-Based Scans
```bash
# Run a full security scan for a project
python main.py project scan <project-id> --type full

# Quick scan
python main.py project scan <project-id> --type quick

# Technology-aware scan
python main.py project scan <project-id> --type tech
```

#### Generate Reports
```bash
# Generate HTML report (default)
python main.py project report <project-id>

# Generate PDF report
python main.py project report <project-id> --format pdf

# Generate JSON report with custom output
python main.py project report <project-id> --format json --output /path/to/report.json
```

### Client Management

```bash
# Add a new client
python main.py client add \
  --name "ACME Corp" \
  --email "security@acme.com" \
  --company "ACME Corporation"

# List all clients
python main.py client list

# View client details and project history
python main.py client info "ACME Corp"

# Generate client security report
python main.py client report "ACME Corp" --format detailed
```

### Basic Security Scanning (Legacy)

```bash
# Scan a website
python main.py scan https://example.com

# Save results to file
python main.py scan https://example.com -o results.json

# Specify output format
python main.py scan https://example.com -o report.html -f html

# Check for OWASP Top 10 vulnerabilities
python main.py check-owasp https://example.com
```

### Web Dashboard

```bash
# Start the web interface
python main.py serve

# Access at http://localhost:8000
# View project dashboard, manage clients, and generate reports
```

### Managing ZAP Daemon

```bash
# Start ZAP daemon
python main.py start-zap

# Stop ZAP daemon
python main.py stop-zap
```

## 📊 Project Structure

```
linknode-security-tester/
├── src/
│   ├── core/
│   │   ├── project_manager.py      # Project & client management
│   │   ├── project_scanner.py      # Project-aware scanning
│   │   └── report_generator.py     # Enhanced report generation
│   ├── cli/
│   │   ├── project_commands.py     # Project CLI commands
│   │   └── client_commands.py      # Client CLI commands
│   ├── web/
│   │   └── project_dashboard.py    # Web dashboard
│   └── scanners/
│       ├── security.py             # Security scanning
│       └── technology_aware_scanner.py  # Tech detection
├── tests/
│   ├── unit/                       # Unit tests
│   └── integration/                # Integration tests
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PROJECT_MANAGEMENT.md
│   └── API.md
└── examples/
    └── report_demo.py              # Report generation examples
```

## 📈 Understanding Results

### Risk Levels

- **High**: Critical vulnerabilities requiring immediate attention
- **Medium**: Important issues that should be addressed soon
- **Low**: Minor issues and best practice recommendations
- **Informational**: Non-security findings for awareness

### Risk Score

The tool calculates a risk score from 0-100 based on:
- Number of vulnerabilities found
- Severity of each vulnerability
- Confidence level of findings
- Historical trends (for projects)

### Sample Report Output

```json
{
  "project": {
    "name": "Q1 Security Audit",
    "client": "ACME Corp",
    "url": "https://acme.example.com"
  },
  "scan": {
    "date": "2024-01-26T14:30:00",
    "type": "full",
    "duration": 1800.5,
    "risk_score": 45.6,
    "vulnerabilities": {
      "High": 2,
      "Medium": 5,
      "Low": 8,
      "Informational": 3
    }
  },
  "summary": {
    "total_vulnerabilities": 18,
    "critical_findings": 2,
    "technologies_detected": 5
  }
}
```

## 🏗️ Architecture

The tool follows a modular architecture with project isolation:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│     CLI     │────▶│   Project   │────▶│   Scanner   │
└─────────────┘     │   Manager   │     └─────────────┘
       │            └─────────────┘            │
       │                   │                   ▼
       ▼                   ▼            ┌─────────────┐
┌─────────────┐     ┌─────────────┐     │ ZAP Client  │
│     Web     │     │   Report    │     └─────────────┘
│  Dashboard  │     │  Generator  │
└─────────────┘     └─────────────┘
```

## 🔧 Configuration

### Global Configuration (`config.yaml`)

```yaml
zap:
  api_key: "your-api-key"
  host: "localhost"
  port: 8080

scanning:
  timeout: 300
  max_depth: 10
  threads: 5

reporting:
  include_screenshots: true
  risk_threshold: "medium"
  
project_management:
  base_dir: "~/.linknode-security"
  archive_completed: true
  auto_backup: true
```

### Per-Project Configuration

Each project can have its own `scan_config.json`:

```json
{
  "scan_defaults": {
    "timeout": 600,
    "max_depth": 15
  },
  "exclusions": ["*.pdf", "*.jpg", "/admin/*"],
  "custom_headers": {
    "Authorization": "Bearer token",
    "X-Custom-Header": "value"
  },
  "authentication": {
    "type": "form",
    "login_url": "https://example.com/login",
    "username": "testuser",
    "password": "encrypted_password"
  }
}
```

## 📝 Version History & Roadmap

### Version Numbering Scheme

We follow Semantic Versioning (SemVer): `MAJOR.MINOR.PATCH`

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backwards-compatible)
- **PATCH**: Bug fixes (backwards-compatible)

### Release History

#### v2.0.0 (2024-01-26) - Project Management Release
- ✅ Complete project management system
- ✅ Client management capabilities
- ✅ Enhanced report generation (HTML/PDF/JSON)
- ✅ Project-based scanning with isolation
- ✅ Web dashboard for project overview
- ✅ Comprehensive test suite
- ✅ CI/CD integration

#### v1.2.0 (2024-01-20) - Enhanced Scanning
- ✅ Technology-aware scanning
- ✅ Phase 1 tools integration (WhatWeb, Nikto)
- ✅ Free security API integrations
- ✅ Docker infrastructure improvements

#### v1.1.0 (2024-01-15) - Docker & Architecture
- ✅ Docker Compose support
- ✅ Modular architecture refactoring
- ✅ Enhanced CLI interface
- ✅ Basic API structure

#### v1.0.0 (2024-01-10) - Initial Release
- ✅ OWASP ZAP integration
- ✅ Basic security scanning
- ✅ CLI interface
- ✅ JSON output format
- ✅ Risk scoring system

### Upcoming Releases

#### v2.1.0 (Q1 2024) - Enhanced Reporting
- [ ] Custom report templates
- [ ] Email report delivery
- [ ] Vulnerability trending graphs
- [ ] Compliance mapping (PCI-DSS, HIPAA)

#### v2.2.0 (Q2 2024) - Automation & Integration
- [ ] Scheduled scanning
- [ ] Slack/Teams notifications
- [ ] JIRA integration
- [ ] API authentication methods

#### v3.0.0 (Q3 2024) - Enterprise Features
- [ ] Multi-user support with roles
- [ ] SSO integration
- [ ] Distributed scanning
- [ ] Custom vulnerability rules

### Future Vision
- [ ] AI-powered vulnerability analysis
- [ ] Automated remediation suggestions
- [ ] Integration with WAF solutions
- [ ] Mobile app security testing

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python run_tests.py

# Run with coverage report
python run_tests.py --coverage

# Run specific test module
python -m pytest tests/unit/test_project_manager.py -v
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for detailed guidelines.

## 📚 Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Project Management Guide](docs/PROJECT_MANAGEMENT.md)
- [API Reference](docs/API.md)
- [Security Best Practices](docs/SECURITY.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## ⚠️ Legal Notice

This tool is designed for security testing of web applications you own or have explicit permission to test. Using this tool against websites without permission is illegal and unethical.

**Always ensure you have proper authorization before scanning any website.**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Murray Kopit**
- GitHub: [@murr2k](https://github.com/murr2k)
- Email: murr2k@gmail.com

## 🙏 Acknowledgments

- [OWASP ZAP](https://www.zaproxy.org/) - The world's most widely used web app scanner
- [Linknode](https://linknode.com) - Energy monitoring platform used as test target
- Security community for feedback and contributions
- Built with AI-assisted development using Claude

## 🔒 Security

Found a security issue? Please email security@linknode-security.com instead of using the issue tracker.

---

**Note**: This tool is actively maintained and used in production environments. For enterprise support or custom features, please contact the author.
