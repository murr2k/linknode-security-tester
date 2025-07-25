#!/bin/bash
# Script to set up GitHub Container Registry authentication

set -e

echo "========================================="
echo "GitHub Container Registry Setup"
echo "========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if GitHub CLI is installed
if ! command -v gh &> /dev/null; then
    echo -e "${YELLOW}GitHub CLI (gh) is not installed.${NC}"
    echo "Install it from: https://cli.github.com/"
    echo ""
    echo "Or use manual setup:"
    echo "1. Create a Personal Access Token at: https://github.com/settings/tokens"
    echo "2. Select scopes: read:packages, write:packages, delete:packages"
    echo "3. Run: docker login ghcr.io -u YOUR_GITHUB_USERNAME"
    exit 1
fi

# Check if user is authenticated with GitHub CLI
if ! gh auth status &> /dev/null; then
    echo -e "${YELLOW}Not authenticated with GitHub CLI${NC}"
    echo "Running: gh auth login"
    gh auth login
fi

# Get GitHub username
GITHUB_USER=$(gh api user --jq .login)
echo -e "${GREEN}GitHub user: $GITHUB_USER${NC}"

# Create PAT for container registry
echo ""
echo "Creating Personal Access Token for GitHub Container Registry..."
echo "This token will have permissions for: read:packages, write:packages"

# Generate token with gh CLI
TOKEN=$(gh auth token)

# Login to GitHub Container Registry
echo ""
echo "Logging into GitHub Container Registry..."
echo $TOKEN | docker login ghcr.io -u $GITHUB_USER --password-stdin

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Successfully logged into ghcr.io${NC}"
else
    echo -e "${RED}✗ Failed to login to ghcr.io${NC}"
    exit 1
fi

# Create docker config for the project
echo ""
echo "Setting up Docker configuration..."

# Create .docker directory if it doesn't exist
mkdir -p .docker

# Create config.json with registry auth
cat > .docker/config.json << EOF
{
  "auths": {
    "ghcr.io": {}
  },
  "credHelpers": {
    "ghcr.io": "docker-credential-desktop"
  }
}
EOF

echo -e "${GREEN}✓ Docker configuration created${NC}"

# Test the setup
echo ""
echo "Testing registry access..."
docker pull ghcr.io/zaproxy/zaproxy:stable > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Registry access confirmed${NC}"
else
    echo -e "${YELLOW}⚠ Could not pull test image, but auth may still work${NC}"
fi

# Show next steps
echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "You can now:"
echo "1. Build secure image: docker build -f Dockerfile.secure -t ghcr.io/$GITHUB_USER/linknode-security-tester:latest ."
echo "2. Push to registry: docker push ghcr.io/$GITHUB_USER/linknode-security-tester:latest"
echo "3. Pull from registry: docker pull ghcr.io/$GITHUB_USER/linknode-security-tester:latest"
echo ""
echo "The image will be private by default since your repository is private."
echo ""
echo "To use in docker-compose, add to your .env file:"
echo "REGISTRY_PREFIX=ghcr.io/$GITHUB_USER"