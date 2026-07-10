# Changelog

All notable changes to BBHUNT will be documented in this file.

## [2.0.0] - 2026-07-08

### Added
- Complete Python-based orchestration framework
- 7-phase automated bug bounty workflow
- TXT and JSON report generation
- 404 filtering at every pipeline stage
- Self-error handling with automatic retry
- Fedora KDE Plasma optimization
- Custom configuration via `lib/config.py`
- Result parsing and consolidation
- CI workflow with GitHub Actions

### Pipeline
- Phase 1: Subdomain enumeration (subfinder)
- Phase 2: Live host detection (httpx)
- Phase 3: DNS brute-forcing (puredns)
- Phase 4: URL collection (gau + waybackurls)
- Phase 5: Vulnerability scanning (nuclei)
- Phase 6: XSS detection (dalfox)
- Phase 7: Directory fuzzing (ffuf)

### Target
- whatnot program (HackerOne)
