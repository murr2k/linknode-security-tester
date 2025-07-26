# Branch Protection Rules Setup

This document outlines the recommended branch protection rules for the main branch.

## How to Configure

1. Go to **Settings** (in your repository)
2. Under **Code and automation**, click **Branches**
3. Click **Add branch protection rule** (or **Add rule**)

### Branch name pattern
Enter: `main`

### Protection Settings

#### ✅ Require a pull request before merging
Check this box, then configure:
- **Require approvals**: Set to 1 (or 0 for solo projects)
- **Dismiss stale pull request approvals when new commits are pushed**: Check this
- **Require review from CODEOWNERS**: Optional

#### ✅ Require status checks to pass before merging
Check this box, then:
1. Check **Require branches to be up to date before merging**
2. Search for and select these status checks:
   - `Docker Security Build / build-and-scan`
   - `test-project-management`
   - `CodeQL / Analyze (python)`

Note: These checks will only appear after they've run at least once.

#### ✅ Require conversation resolution before merging
Check this box

#### ✅ Additional Settings (scroll down)
- **Do not allow bypassing the above settings**: Check this
- **Restrict who can push to matching branches**: Optional (adds extra security)
- **Allow force pushes**: Leave unchecked
- **Allow deletions**: Leave unchecked

Click **Create** or **Save changes**

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