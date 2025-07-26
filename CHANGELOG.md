# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-01-26

### Added
- Complete project management system with SQLite backend
- Client management capabilities for organizing multiple clients
- Project-based scanning with isolated environments
- Enhanced report generation with HTML, PDF, and JSON formats
- Professional report templates with executive summaries
- Vulnerability distribution charts and analytics
- Per-project configuration and authentication settings
- Project archiving and export functionality
- Web dashboard for project overview (FastAPI-based)
- Comprehensive test suite with 57+ test cases
- CI/CD integration with GitHub Actions
- Project CLI commands: create, list, info, scan, report, archive, delete
- Client CLI commands: add, list, info, update, report
- Support for form-based and bearer token authentication
- Scan history tracking with vulnerability trends
- Risk scoring based on historical data
- Batch operations support
- Project isolation for concurrent scanning

### Changed
- Restructured codebase with modular architecture
- Updated main.py to include project and client commands
- Enhanced risk calculation with weighted scoring
- Improved CLI output with rich formatting
- Updated serve command to use project dashboard

### Fixed
- Import paths for better module organization
- Added missing tabulate dependency
- Improved error handling for edge cases

## [1.2.0] - 2024-01-20

### Added
- Technology-aware scanning capabilities
- Integration with Phase 1 security tools (WhatWeb, Nikto)
- Free security API integrations
- Enhanced vulnerability detection
- Tool output parsing and aggregation

### Changed
- Improved Docker infrastructure
- Enhanced scanner modularity
- Better error handling for external tools

### Fixed
- Docker container permission issues
- Tool timeout handling

## [1.1.0] - 2024-01-15

### Added
- Docker Compose support for easy deployment
- Modular architecture refactoring
- Enhanced CLI with rich output
- Basic API server structure
- Configuration file support (YAML)

### Changed
- Reorganized project structure
- Improved code modularity
- Better separation of concerns

### Fixed
- Cross-platform compatibility issues
- Configuration loading errors

## [1.0.0] - 2024-01-10

### Added
- Initial release with OWASP ZAP integration
- Basic security scanning functionality
- CLI interface with Click
- JSON output format
- Risk scoring system
- Spider crawling capability
- Active and passive scanning modes
- OWASP Top 10 vulnerability checking
- Basic remediation suggestions
- Example test script for linknode.com

### Security
- Added API key configuration for ZAP
- Implemented secure defaults

## [0.1.0] - 2024-01-05 (Pre-release)

### Added
- Project initialization
- Basic project structure
- Requirements definition
- Initial documentation

---

## Versioning Policy

This project uses Semantic Versioning (SemVer) with the following guidelines:

- **MAJOR** version (X.0.0): Incompatible API changes, major architectural changes
- **MINOR** version (0.X.0): New functionality in a backwards-compatible manner
- **PATCH** version (0.0.X): Backwards-compatible bug fixes

### Version History Summary

- **v2.x.x**: Enterprise features with project management
- **v1.x.x**: Core security scanning with OWASP ZAP
- **v0.x.x**: Initial development and prototyping