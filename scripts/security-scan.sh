#!/bin/bash
# Security scanning script for Docker images

set -e

echo "========================================="
echo "Docker Image Security Scan"
echo "========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
IMAGE_NAME="${1:-ghcr.io/murr2k/linknode-security-tester:latest}"
SCAN_DIR="security-scans"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create scan directory
mkdir -p "$SCAN_DIR"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install tool if not present
install_tool() {
    local tool=$1
    local install_cmd=$2
    
    if ! command_exists "$tool"; then
        echo -e "${YELLOW}Installing $tool...${NC}"
        eval "$install_cmd"
    fi
}

echo "Scanning image: $IMAGE_NAME"
echo ""

# 1. Trivy Scan (Vulnerability Scanner)
echo -e "${BLUE}Running Trivy vulnerability scan...${NC}"
if command_exists trivy; then
    trivy image \
        --severity HIGH,CRITICAL \
        --format json \
        --output "$SCAN_DIR/trivy_${TIMESTAMP}.json" \
        "$IMAGE_NAME"
    
    # Also generate human-readable report
    trivy image \
        --severity HIGH,CRITICAL \
        --format table \
        "$IMAGE_NAME" | tee "$SCAN_DIR/trivy_${TIMESTAMP}.txt"
    
    echo -e "${GREEN}✓ Trivy scan complete${NC}"
else
    echo -e "${YELLOW}Trivy not installed. Install with:${NC}"
    echo "  brew install trivy (macOS)"
    echo "  sudo snap install trivy (Linux)"
fi

echo ""

# 2. Hadolint (Dockerfile Linter)
echo -e "${BLUE}Running Hadolint on Dockerfile...${NC}"
if command_exists hadolint; then
    hadolint Dockerfile.secure \
        --format json > "$SCAN_DIR/hadolint_${TIMESTAMP}.json" || true
    
    hadolint Dockerfile.secure || true
    echo -e "${GREEN}✓ Hadolint scan complete${NC}"
else
    echo -e "${YELLOW}Hadolint not installed. Install with:${NC}"
    echo "  brew install hadolint (macOS)"
    echo "  wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64"
fi

echo ""

# 3. Docker Scout (if available)
echo -e "${BLUE}Running Docker Scout analysis...${NC}"
if docker scout version &>/dev/null; then
    docker scout cves "$IMAGE_NAME" > "$SCAN_DIR/scout_${TIMESTAMP}.txt" || true
    docker scout recommendations "$IMAGE_NAME" >> "$SCAN_DIR/scout_${TIMESTAMP}.txt" || true
    echo -e "${GREEN}✓ Docker Scout analysis complete${NC}"
else
    echo -e "${YELLOW}Docker Scout not available${NC}"
fi

echo ""

# 4. Grype (Alternative vulnerability scanner)
echo -e "${BLUE}Running Grype vulnerability scan...${NC}"
if command_exists grype; then
    grype "$IMAGE_NAME" \
        --output json \
        --file "$SCAN_DIR/grype_${TIMESTAMP}.json"
    
    grype "$IMAGE_NAME" | tee "$SCAN_DIR/grype_${TIMESTAMP}.txt"
    echo -e "${GREEN}✓ Grype scan complete${NC}"
else
    echo -e "${YELLOW}Grype not installed. Install with:${NC}"
    echo "  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
fi

echo ""

# 5. Syft (SBOM Generation)
echo -e "${BLUE}Generating Software Bill of Materials (SBOM)...${NC}"
if command_exists syft; then
    syft "$IMAGE_NAME" \
        -o spdx-json \
        --file "$SCAN_DIR/sbom_${TIMESTAMP}.json"
    
    syft "$IMAGE_NAME" \
        -o table \
        --file "$SCAN_DIR/sbom_${TIMESTAMP}.txt"
    
    echo -e "${GREEN}✓ SBOM generation complete${NC}"
else
    echo -e "${YELLOW}Syft not installed. Install with:${NC}"
    echo "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
fi

echo ""

# 6. Container Structure Test
echo -e "${BLUE}Running container structure tests...${NC}"
cat > "$SCAN_DIR/structure_test_${TIMESTAMP}.yaml" << EOF
schemaVersion: 2.0.0
commandTests:
  - name: "Python version"
    command: "python"
    args: ["--version"]
    expectedOutput: ["Python 3.11"]
  
  - name: "Non-root user"
    command: "whoami"
    expectedOutput: ["scanner"]
  
  - name: "Working directory"
    command: "pwd"
    expectedOutput: ["/app"]

fileExistenceTests:
  - name: "WhatWeb installed"
    path: "/opt/whatweb/whatweb"
    shouldExist: true
  
  - name: "Nikto installed"
    path: "/opt/nikto/program/nikto.pl"
    shouldExist: true
  
  - name: "Application files"
    path: "/app/main.py"
    shouldExist: true

metadataTest:
  labels:
    - key: "security.nonroot"
      value: "true"
    - key: "org.opencontainers.image.source"
      value: "https://github.com/murr2k/linknode-security-tester"
  
  user: "scanner"
  workdir: "/app"
EOF

if command_exists container-structure-test; then
    container-structure-test test \
        --image "$IMAGE_NAME" \
        --config "$SCAN_DIR/structure_test_${TIMESTAMP}.yaml" \
        | tee "$SCAN_DIR/structure_test_results_${TIMESTAMP}.txt"
    echo -e "${GREEN}✓ Container structure tests complete${NC}"
else
    echo -e "${YELLOW}container-structure-test not installed${NC}"
fi

echo ""

# 7. Security Policy Check
echo -e "${BLUE}Checking security policies...${NC}"
docker inspect "$IMAGE_NAME" --format '
Image: {{.RepoTags}}
User: {{.Config.User}}
Capabilities:
  - Drop: {{.Config.Labels}}
Security Options: {{.Config.SecurityOpts}}
Read-only root: {{.Config.ReadOnly}}
' > "$SCAN_DIR/security_policy_${TIMESTAMP}.txt"

# Summary Report
echo ""
echo "========================================="
echo "Security Scan Summary"
echo "========================================="
echo ""
echo "Scan results saved to: $SCAN_DIR/"
echo ""
echo "Files generated:"
ls -la "$SCAN_DIR"/*_${TIMESTAMP}* | awk '{print "  - " $9}'
echo ""

# Quick vulnerability summary
if [ -f "$SCAN_DIR/trivy_${TIMESTAMP}.json" ]; then
    CRITICAL=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$SCAN_DIR/trivy_${TIMESTAMP}.json" 2>/dev/null || echo "0")
    HIGH=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$SCAN_DIR/trivy_${TIMESTAMP}.json" 2>/dev/null || echo "0")
    
    echo "Vulnerability Summary (Trivy):"
    echo -e "  Critical: ${RED}$CRITICAL${NC}"
    echo -e "  High: ${YELLOW}$HIGH${NC}"
    echo ""
    
    if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 10 ]; then
        echo -e "${RED}⚠ Security issues found! Review scan results.${NC}"
        exit 1
    else
        echo -e "${GREEN}✓ Security scan passed!${NC}"
    fi
fi