# Docker Security Implementation Guide

## Overview

This guide documents the security-hardened Docker implementation for the Linknode Security Tester. We've implemented defense-in-depth with multiple security layers.

## Security Features Implemented

### 1. Multi-Stage Builds (`Dockerfile.secure`)
- **Minimal attack surface**: Final image contains only runtime dependencies
- **No build tools**: Compilers and development tools excluded from production
- **Size optimization**: Reduced from ~1GB to ~200MB

### 2. Non-Root Execution
- All containers run as non-privileged users
- UID/GID 1001 for custom `scanner` user
- No sudo or privilege escalation possible

### 3. Read-Only Filesystems
```yaml
read_only: true
tmpfs:
  - /tmp:size=100M
```
- Root filesystem is read-only
- Temporary directories use tmpfs (RAM)
- Writable volumes explicitly mounted where needed

### 4. Capability Dropping
```yaml
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE  # Only if absolutely needed
```
- All Linux capabilities dropped by default
- Only essential capabilities added back

### 5. Resource Limits
```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
```
- Prevents resource exhaustion attacks
- Ensures predictable performance

### 6. Network Isolation

#### Architecture:
```
Internet <-> DMZ Network <-> Scanner Network <-> Internal Networks
                                |                       |
                                |                    ZAP Network
                                |                    Tools Network
                                |                    Storage Network
                                v
                           Target Network (Outbound only)
```

#### Network Policies:
- **DMZ Network** (172.20.0.0/24): External-facing services
- **Scanner Network** (172.21.0.0/24): Internal control plane
- **ZAP Network** (172.22.0.0/24): Isolated ZAP proxy
- **Tools Network** (172.23.0.0/24): Security tools
- **Target Network** (172.24.0.0/24): Outbound scanning only
- **Storage Network** (172.25.0.0/24): Results storage

### 7. Secrets Management

#### Docker Secrets:
```bash
./scripts/setup-secrets.sh
```
- Generates secure random keys
- Stores in `secrets/` directory (mode 600)
- Never committed to Git

#### Environment Variables:
```bash
# .env file (not in Git)
ZAP_API_KEY=<generated-secret>
REGISTRY_PREFIX=ghcr.io/username
```

### 8. Image Scanning

#### Automated CI/CD:
- Trivy vulnerability scanning
- Hadolint Dockerfile linting
- SBOM generation
- Results uploaded to GitHub Security

#### Local Scanning:
```bash
./scripts/security-scan.sh <image-name>
```

### 9. GitHub Container Registry

Private container registry with:
- Automatic privacy (follows repo visibility)
- Integrated authentication
- Vulnerability scanning
- Package versioning

## Quick Start

### 1. Initial Setup
```bash
# Set up GitHub Container Registry
./scripts/setup-ghcr.sh

# Generate secrets
./scripts/setup-secrets.sh

# Build secure image
docker build -f Dockerfile.secure -t ghcr.io/<username>/linknode-security-tester:latest .

# Run security scan
./scripts/security-scan.sh ghcr.io/<username>/linknode-security-tester:latest

# Push to registry
docker push ghcr.io/<username>/linknode-security-tester:latest
```

### 2. Run Secure Stack
```bash
# Basic secure setup
docker-compose -f docker-compose.secure.yml up -d

# Full isolated network setup
docker-compose -f docker-compose.isolated.yml --profile full up -d

# With test target
docker-compose -f docker-compose.isolated.yml --profile test up -d
```

### 3. Run Individual Tools
```bash
# Build tool images
docker build -f Dockerfile.tools --target whatweb-runtime -t whatweb:secure .
docker build -f Dockerfile.tools --target nikto-runtime -t nikto:secure .

# Run tools
docker run --rm whatweb:secure https://example.com
docker run --rm nikto:secure -h https://example.com
```

## Security Best Practices

### 1. Image Building
- Always use specific base image tags (not `:latest`)
- Verify base image signatures
- Scan images before deployment
- Rebuild regularly for security patches

### 2. Runtime Security
- Never run containers as root
- Always drop capabilities
- Use read-only filesystems
- Implement resource limits
- Enable security options:
  ```yaml
  security_opt:
    - no-new-privileges:true
    - seccomp:unconfined  # Only if needed
  ```

### 3. Network Security
- Use internal networks for service communication
- Bind ports only to localhost: `127.0.0.1:8080:8080`
- Implement network segmentation
- Disable inter-container communication where possible

### 4. Secrets Handling
- Never hardcode secrets
- Use Docker secrets or environment files
- Rotate keys regularly
- Audit access logs

### 5. Monitoring
- Enable Docker logging
- Monitor resource usage
- Set up health checks
- Track security events

## Troubleshooting

### Permission Denied Errors
```bash
# Check user permissions
docker exec <container> whoami
docker exec <container> id

# Fix volume permissions
sudo chown -R 1001:1001 ./results
```

### Network Connectivity Issues
```bash
# Test network isolation
docker exec scanner ping zap  # Should work
docker exec zap ping scanner   # Should fail (one-way)

# Check network configuration
docker network ls
docker network inspect <network-name>
```

### Security Scan Failures
```bash
# Update scanning tools
brew upgrade trivy hadolint

# Check for false positives
trivy image --ignore-unfixed <image>
```

## Advanced Configuration

### Custom Security Policies
Create `.trivyignore` for acceptable vulnerabilities:
```
# Acceptable vulnerabilities
CVE-2021-12345
CVE-2022-67890
```

### Dockerfile Linting Rules
Create `.hadolint.yaml`:
```yaml
ignored:
  - DL3008  # Pin versions in apt-get
  - DL3009  # Delete apt-get lists
trustedRegistries:
  - ghcr.io
  - docker.io
```

### Network Policies (Kubernetes)
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scanner-policy
spec:
  podSelector:
    matchLabels:
      app: scanner
  policyTypes:
    - Ingress
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: zap
      ports:
        - protocol: TCP
          port: 8080
```

## Compliance

Our implementation follows:
- CIS Docker Benchmark
- NIST Container Security Guidelines
- OWASP Container Security Top 10
- PCI DSS container requirements (where applicable)

## Future Enhancements

1. **Runtime Security**
   - Falco for runtime threat detection
   - AppArmor/SELinux profiles
   - Admission controllers

2. **Supply Chain Security**
   - Signed images with Cosign
   - Policy enforcement with OPA
   - SLSA compliance

3. **Zero Trust Architecture**
   - mTLS between services
   - Service mesh integration
   - Identity-based access control