# Quick Start Guide

## Installation

### Option 1: Using Docker Compose (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/murr2k/linknode-security-tester.git
cd linknode-security-tester
```

2. Start all services:
```bash
docker-compose up -d
```

3. Run a scan:
```bash
docker-compose exec linknode-tester python main.py scan https://linknode.com
```

### Option 2: Local Installation

1. Run the setup script:
```bash
./setup.sh
```

2. Activate virtual environment:
```bash
source venv/bin/activate
```

3. Run a scan:
```bash
python main.py scan https://linknode.com
```

## Basic Usage

### Running a Security Scan

```bash
# Basic security scan
python main.py scan https://linknode.com

# Save results to file
python main.py scan https://linknode.com -o results.json

# Multiple scan types (when implemented)
python main.py scan https://linknode.com -t security -t quality -t performance
```

### Check for OWASP Top 10

```bash
python main.py check-owasp https://linknode.com
```

### Start Web Dashboard

```bash
python main.py serve
# Access at http://localhost:8000
```

## Example: Testing linknode.com

```bash
# 1. Start ZAP if not running
python main.py start-zap

# 2. Run comprehensive security scan
python main.py scan https://linknode.com -o linknode-security-report.json

# 3. Check OWASP compliance
python main.py check-owasp https://linknode.com

# 4. View results
cat linknode-security-report.json | jq '.summary'

# 5. Stop ZAP when done
python main.py stop-zap
```

## Understanding Results

### Security Scan Results

```json
{
  "summary": {
    "total_issues": 15,
    "high_risk_issues": 2,
    "medium_risk_issues": 5,
    "low_risk_issues": 8,
    "risk_score": 45.6,
    "recommendations": [
      "Address high-risk security vulnerabilities immediately",
      "Review and update security headers"
    ]
  }
}
```

### Risk Levels

- **High**: Critical vulnerabilities requiring immediate attention
- **Medium**: Important issues that should be addressed soon
- **Low**: Minor issues and best practice recommendations
- **Informational**: Non-security findings for awareness

## Next Steps

1. Review the full scan report
2. Prioritize high-risk vulnerabilities
3. Implement recommended fixes
4. Re-scan to verify remediation
5. Set up regular automated scans

## Troubleshooting

### ZAP Connection Error
```bash
# Check if ZAP is running
docker ps | grep zap

# View ZAP logs
docker logs linknode-zap

# Restart ZAP
docker-compose restart zap
```

### Permission Errors
```bash
# Fix scan results directory permissions
sudo chown -R $USER:$USER scan_results/
```

## Support

- Documentation: See `/docs` directory
- Issues: https://github.com/murr2k/linknode-security-tester/issues
- Email: murr2k@gmail.com