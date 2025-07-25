#!/bin/bash
# Set up Docker secrets for secure configuration

set -e

echo "========================================="
echo "Docker Secrets Setup"
echo "========================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Create secrets directory
mkdir -p secrets
chmod 700 secrets

# Function to generate secure random string
generate_secret() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Generate ZAP API key if not exists
if [ ! -f secrets/zap_api_key.txt ]; then
    echo -n "Generating secure ZAP API key..."
    ZAP_KEY=$(generate_secret)
    echo "$ZAP_KEY" > secrets/zap_api_key.txt
    chmod 600 secrets/zap_api_key.txt
    echo -e " ${GREEN}✓${NC}"
else
    echo -e "${YELLOW}ZAP API key already exists${NC}"
    ZAP_KEY=$(cat secrets/zap_api_key.txt)
fi

# Create scanner configuration
if [ ! -f secrets/scanner_config.json ]; then
    echo -n "Creating scanner configuration..."
    cat > secrets/scanner_config.json << EOF
{
  "security": {
    "enable_ssl_verification": true,
    "timeout_seconds": 300,
    "max_spider_depth": 10,
    "max_scan_duration": 1800
  },
  "reporting": {
    "include_false_positives": false,
    "confidence_threshold": "medium"
  },
  "api_keys": {
    "hostedscan": "",
    "shodan": "",
    "virustotal": ""
  }
}
EOF
    chmod 600 secrets/scanner_config.json
    echo -e " ${GREEN}✓${NC}"
else
    echo -e "${YELLOW}Scanner config already exists${NC}"
fi

# Create .env file for docker-compose
if [ ! -f .env ]; then
    echo -n "Creating .env file..."
    cat > .env << EOF
# Docker Registry Configuration
REGISTRY_PREFIX=ghcr.io/$(gh api user --jq .login 2>/dev/null || echo "murr2k")
VERSION=latest

# Security Configuration
ZAP_API_KEY=$ZAP_KEY
LOG_LEVEL=INFO

# Build Arguments
BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
VCS_REF=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

# Scanner Configuration
SCAN_TIMEOUT=1800
MAX_SPIDER_DEPTH=10
PARALLEL_SCANS=5
EOF
    chmod 600 .env
    echo -e " ${GREEN}✓${NC}"
else
    echo -e "${YELLOW}.env file already exists${NC}"
fi

# Create Docker secrets for swarm mode (optional)
if command -v docker &> /dev/null && docker info 2>/dev/null | grep -q "Swarm: active"; then
    echo ""
    echo "Docker Swarm detected. Creating swarm secrets..."
    
    # Create secrets in swarm
    docker secret create zap_api_key secrets/zap_api_key.txt 2>/dev/null || \
        echo -e "${YELLOW}Secret 'zap_api_key' already exists in swarm${NC}"
    
    docker secret create scanner_config secrets/scanner_config.json 2>/dev/null || \
        echo -e "${YELLOW}Secret 'scanner_config' already exists in swarm${NC}"
fi

# Add secrets to .gitignore
if ! grep -q "^secrets/" .gitignore 2>/dev/null; then
    echo -n "Adding secrets to .gitignore..."
    echo -e "\n# Docker secrets\nsecrets/\n.env" >> .gitignore
    echo -e " ${GREEN}✓${NC}"
fi

# Create example secrets for documentation
mkdir -p secrets/examples
cat > secrets/examples/zap_api_key.txt.example << EOF
your-zap-api-key-here
EOF

cat > secrets/examples/scanner_config.json.example << EOF
{
  "security": {
    "enable_ssl_verification": true,
    "timeout_seconds": 300,
    "max_spider_depth": 10,
    "max_scan_duration": 1800
  },
  "reporting": {
    "include_false_positives": false,
    "confidence_threshold": "medium"
  },
  "api_keys": {
    "hostedscan": "your-api-key-here",
    "shodan": "your-api-key-here",
    "virustotal": "your-api-key-here"
  }
}
EOF

# Show summary
echo ""
echo "========================================="
echo "Secrets Setup Complete!"
echo "========================================="
echo ""
echo "Created files:"
echo "  - secrets/zap_api_key.txt (mode 600)"
echo "  - secrets/scanner_config.json (mode 600)"
echo "  - .env (mode 600)"
echo "  - secrets/examples/* (documentation)"
echo ""
echo -e "${GREEN}ZAP API Key:${NC} $ZAP_KEY"
echo ""
echo "To use with docker-compose:"
echo "  docker-compose -f docker-compose.secure.yml up -d"
echo ""
echo -e "${YELLOW}Important:${NC} Keep the secrets/ directory secure!"
echo "These files contain sensitive information."