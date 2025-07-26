# Branch Protection Rules Setup

This document outlines the recommended branch protection rules for the main branch.

## Prerequisites
**Important**: Status checks only appear after they've run at least once. The CodeQL workflow was just added, so it needs to run before it will appear in the status checks list.

### Trigger the workflows first:
```bash
# Option 1: Make a small change and push
echo "# trigger workflows" >> README.md
git add README.md && git commit -m "Trigger workflows" && git push

# Option 2: Manually trigger workflows in GitHub Actions tab
# Go to Actions → Select workflow → Run workflow
```

## How to Configure Branch Protection

1. Go to **Settings** (in your repository)
2. Under **Code and automation**, click **Branches**
3. Click **Add branch protection rule**

### Branch name pattern
Enter: `main`

## Recommended Settings

### ✅ Require a pull request before merging
- Check this box
- **Require approvals**: 
  - For team projects: Check this and set to 1
  - For solo projects: Leave unchecked (this still requires PR but no approvals)
- **Dismiss stale pull request approvals when new commits are pushed**: ✓ Check (if using approvals)
- **Require review from Code Owners**: Leave unchecked (unless you have CODEOWNERS file)
- **Require approval of the most recent reviewable push**: Leave unchecked

### ✅ Require status checks to pass before merging
- Check this box
- **Require branches to be up to date before merging**: ✓ Check
- **Status checks**: Search and add:
  - `build-and-scan` (from Docker Security Build workflow)
  - `test-project-management` 
  - `Analyze (python)` (from CodeQL workflow)
  
**Note**: If these don't appear, the workflows haven't run yet. Save the rule and come back after workflows run.

### ✅ Require conversation resolution before merging
- ✓ Check this box

### ⚠️ Optional Settings
- **Require signed commits**: Optional (good for security)
- **Require linear history**: Optional (prevents merge commits)
- **Require deployments to succeed**: Leave unchecked
- **Lock branch**: Leave unchecked

### ✅ Do not allow bypassing the above settings
- ✓ Check this (applies rules even to admins)

### ❌ Rules applied to everyone including administrators
- **Allow force pushes**: Leave unchecked
- **Allow deletions**: Leave unchecked

Click **Create** to save the rule.

## For Solo Developers

If you're working alone and find the PR requirement cumbersome:
1. Leave "Require approvals" unchecked (no approval needed)
2. Use GitHub CLI for quick PR workflow: `gh pr create --fill && gh pr merge --auto`
3. Or install GitHub Mobile app to merge PRs on the go

This way you still get all CI/CD checks without blocking yourself on approvals.

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