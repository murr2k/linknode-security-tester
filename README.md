# Linknode Security Tester

A comprehensive website quality and penetration testing tool powered by OWASP ZAP technology. Designed to perform automated security assessments, identify vulnerabilities, and provide actionable remediation guidance.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![OWASP ZAP](https://img.shields.io/badge/OWASP%20ZAP-2.14.0+-green.svg)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🚀 Features

- **Automated Security Scanning**: Comprehensive vulnerability detection using OWASP ZAP
- **OWASP Top 10 Compliance**: Check for the most critical web application security risks
- **Spider Crawling**: Automatic discovery of all accessible pages and endpoints
- **Active & Passive Scanning**: Both non-intrusive analysis and active vulnerability testing
- **Risk Scoring**: Intelligent risk assessment with prioritized remediation guidance
- **Multiple Output Formats**: JSON, HTML, and PDF reports (HTML/PDF coming soon)
- **Docker Support**: Easy deployment with Docker Compose
- **Extensible Architecture**: Modular design for adding quality and performance scanners

## 📋 Prerequisites

- Python 3.10 or higher
- Docker and Docker Compose
- 2GB RAM minimum
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

### Basic Security Scan

```bash
# Scan a website
python main.py scan https://linknode.com

# Save results to file
python main.py scan https://linknode.com -o results.json

# Specify output format
python main.py scan https://linknode.com -o report.html -f html
```

### OWASP Top 10 Check

```bash
# Check for OWASP Top 10 vulnerabilities
python main.py check-owasp https://linknode.com
```

### Managing ZAP Daemon

```bash
# Start ZAP daemon
python main.py start-zap

# Stop ZAP daemon
python main.py stop-zap
```

### Web Dashboard (Coming Soon)

```bash
# Start the web interface
python main.py serve
# Access at http://localhost:8000
```

## 📊 Example: Testing linknode.com

```bash
# Run the example test script
python example_test_linknode.py
```

This will:
1. Initialize the security scanner
2. Spider crawl the website
3. Perform passive scanning
4. Generate a risk assessment
5. Create a remediation plan
6. Save results to `linknode_security_test_results.json`

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

### Sample Output

```json
{
  "target_url": "https://linknode.com",
  "total_alerts": 15,
  "risk_score": 45.6,
  "alerts_by_risk": {
    "High": 2,
    "Medium": 5,
    "Low": 8,
    "Informational": 0
  },
  "scan_duration": 120.5
}
```

## 🏗️ Architecture

The tool follows a modular architecture:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│     CLI     │────▶│ Orchestrator│────▶│   Scanner   │
└─────────────┘     └─────────────┘     └─────────────┘
                           │                     │
                           ▼                     ▼
                    ┌─────────────┐     ┌─────────────┐
                    │   Config    │     │ ZAP Client  │
                    └─────────────┘     └─────────────┘
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed information.

## 🔧 Configuration

Create a `config.yaml` file:

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
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 Roadmap

- [x] OWASP ZAP integration
- [x] Basic security scanning
- [x] CLI interface
- [x] Docker support
- [ ] Web dashboard
- [ ] Quality assessment (SEO, accessibility)
- [ ] Performance analysis
- [ ] HTML/PDF reports
- [ ] CI/CD integration
- [ ] Scheduled scanning
- [ ] Multi-target campaigns

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
- Built with AI-assisted development using Claude

---

**Note**: This tool was created as a demonstration of integrating OWASP ZAP for automated security testing. For production use, consider additional security measures and professional penetration testing services.