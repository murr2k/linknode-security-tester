# Branch Protection Rules Setup

This document outlines the recommended branch protection rules for the main branch.

## How to Configure

Go to Settings → Branches → Add rule

### Branch name pattern
- `main`

### Protection Rules

#### ✅ Require a pull request before merging
- [x] Require approvals: 1
- [x] Dismiss stale pull request approvals when new commits are pushed
- [x] Require review from CODEOWNERS

#### ✅ Require status checks to pass before merging
- [x] Require branches to be up to date before merging
- Required status checks:
  - `build-and-scan` (Docker Security Build)
  - `test-project-management` (Tests)
  - `CodeQL` (Security Analysis)

#### ✅ Require conversation resolution before merging
- [x] All conversations must be resolved

#### ✅ Security Settings
- [x] Do not allow bypassing the above settings
- [x] Restrict who can push to matching branches (optional)

### Code Scanning Alert Thresholds

In Settings → Code security and analysis → Code scanning:

1. **Check runs failure threshold**: Set to "High or higher"
   - This means only High and Critical severity alerts will block merges
   - Medium and Low severity alerts will be shown but won't block

2. **Enable Copilot Autofix** for:
   - CodeQL alerts
   - Third-party tool alerts

### Additional Security Recommendations

1. **Enable Dependabot**:
   - Security updates: Automatic
   - Version updates: Create PRs for review

2. **Secret scanning**:
   - Push protection: Already enabled ✅
   - Alert notifications: Enable for organization owners

3. **Private vulnerability reporting**:
   - Enable to allow security researchers to privately report vulnerabilities

## Automation Script

You can use GitHub CLI to set up these rules:

```bash
# Install GitHub CLI if not already installed
# brew install gh (macOS) or see https://cli.github.com/

# Authenticate
gh auth login

# Create branch protection rule
gh api repos/:owner/:repo/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["build-and-scan","test-project-management","CodeQL"]}' \
  --field enforce_admins=false \
  --field required_pull_request_reviews='{"required_approving_review_count":1,"dismiss_stale_reviews":true}' \
  --field restrictions=null \
  --field allow_force_pushes=false \
  --field allow_deletions=false
```

## For Single Developer Projects

If you're the only developer, you might want to adjust:
- Set required approvals to 0 (but still require PR)
- Enable "Allow specified actors to bypass required pull requests" and add yourself
- Keep all security checks required

This way you still get the benefit of CI/CD checks without blocking yourself.