# Changelog

All notable changes to BurpHub will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.1.0] - 2026-02-12

### Added
- **Security Hardening (OWASP Top 10 Audit)**:
  - Implemented SQL Injection prevention via column whitelisting in `DatabaseManager`.
  - Added XSS sanitization for heatmap tooltips and "Wrapped" slides.
  - Added HTTPS transport warning to the Burp extension.
  - Implemented Rate Limiting (10 requests/min) on the dashboard API.
  - Added standard security headers (CSP, X-Frame-Options, X-Content-Type-Options) to dashboard.
  - Added structured `[SECURITY]` logging for failed auth attempts and rate limiting.
- **BApp Store Readiness**:
  - Added `BApp-manifest.properties` for official Store submission.
  - Updated output streams to use Burp Suite `callbacks.getStderr()` for compliance.
- **Code Quality**:
  - Refactored `ActivityTracker` to use `EnumMap` (DRY principle).
  - Improved thread safety for UI updates using `SwingUtilities.invokeLater()`.

### Fixed
- Fixed H2 SQL syntax errors and resource leaks (unclosed Statements).
- Removed hardcoded API key fallbacks in dashboard.

[1.1.0]: https://github.com/luhmmy/BurpHub/releases/tag/v1.1.0
[1.0.0]: https://github.com/luhmmy/BurpHub/releases/tag/v1.0.0
