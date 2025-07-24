#!/bin/bash

# Linknode Security Tester Setup Script

echo "========================================="
echo "Linknode Security Tester Setup"
echo "========================================="

# Check for required tools
check_requirement() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 is not installed. Please install $1 first."
        exit 1
    else
        echo "✅ $1 is installed"
    fi
}

echo -e "\nChecking requirements..."
check_requirement python3
check_requirement pip
check_requirement docker
check_requirement docker-compose

# Create virtual environment
echo -e "\nCreating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo -e "\nInstalling Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo -e "\nCreating directories..."
mkdir -p scan_results
mkdir -p templates
mkdir -p logs

# Generate default config if not exists
if [ ! -f config.yaml ]; then
    echo -e "\nGenerating default configuration..."
    cat > config.yaml << EOF
zap:
  api_key: "changeme"
  host: "localhost"
  port: 8080

scanning:
  timeout: 300
  max_depth: 10
  threads: 5

quality:
  lighthouse_enabled: true
  axe_enabled: true

reporting:
  include_screenshots: true
  risk_threshold: "medium"
EOF
    echo "✅ Created config.yaml"
fi

# Start ZAP daemon
echo -e "\nStarting OWASP ZAP daemon..."
docker-compose up -d zap

# Wait for ZAP to be ready
echo -e "\nWaiting for ZAP to be ready..."
sleep 10

# Test ZAP connection
echo -e "\nTesting ZAP connection..."
if curl -s "http://localhost:8080/JSON/core/view/version/?apikey=changeme" > /dev/null; then
    echo "✅ ZAP is running and accessible"
else
    echo "❌ Cannot connect to ZAP. Check docker logs."
    exit 1
fi

echo -e "\n========================================="
echo "Setup complete! 🎉"
echo ""
echo "To run a scan:"
echo "  python main.py scan https://linknode.com"
echo ""
echo "To start the web dashboard:"
echo "  python main.py serve"
echo ""
echo "To stop ZAP:"
echo "  docker-compose down"
echo "========================================="