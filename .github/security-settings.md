# GitHub Security Settings Configuration

This guide matches the current GitHub Advanced Security interface.

## Navigation
Settings → Code security and analysis

## Advanced Security Features

### ✅ Private vulnerability reporting
- **Enable this**: Allows security researchers to privately report vulnerabilities
- Creates a private channel for responsible disclosure

### ✅ Dependency graph
- **Already enabled by default** for public repos
- Shows all your dependencies

### ✅ Dependabot

#### Dependabot alerts
- **Enable this**: Get notified about vulnerable dependencies
- Configure notifications in Settings → Notifications

#### Dependabot rules
- You have 1 rule enabled ✓
- Manage custom auto-triage rules for alerts

#### Dependabot security updates
- **Enable this**: Automatically creates PRs to fix vulnerabilities
- Alternative: Use Dependabot rules for more control

#### Grouped security updates
- **Enable this**: Groups updates into single PRs per package manager
- Reduces PR noise

#### Dependabot version updates
- **Optional**: Creates PRs for all dependency updates (not just security)
- Requires `dependabot.yml` configuration file

## Code Scanning

### ✅ CodeQL analysis
- **Status**: Default setup - Last scan 9 minutes ago ✓
- Already configured and running

### ✅ Copilot Autofix
- **Already On** ✓
- Provides AI-suggested fixes for security alerts

### ⚠️ Protection rules - Check runs failure threshold
**Important**: This controls which alerts block merging

Options:
- **None**: No alerts block merging
- **Errors only**: Only errors block (not security alerts)
- **High or higher**: High and Critical security alerts block ← **Recommended**
- **Medium or higher**: Medium, High, and Critical alerts block
- **Low or higher**: All security alerts block
- **All**: Everything blocks including notes

**Recommendation**: Set to "High or higher"

## Secret Protection

### ✅ Push protection
- **Already enabled** ✓
- Blocks commits containing secrets
- Essential for security

## Quick Setup Checklist

1. ✅ Private vulnerability reporting → Enable
2. ✅ Dependabot alerts → Enable
3. ✅ Dependabot security updates → Enable
4. ✅ Grouped security updates → Enable
5. ⚠️ Check runs failure threshold → Set to "High or higher"
6. ✅ Secret push protection → Already enabled

## For Solo Developers

Minimal setup:
- Enable all Dependabot features
- Set failure threshold to "High or higher"
- Keep push protection enabled

This gives you automated security without too much noise.