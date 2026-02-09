# Changelog

All notable changes to BurpHub will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2026-02-09

### Added
- Initial release of BurpHub
- Activity heatmap visualization (365 days, GitHub-style)
- Streak tracking (current and longest streak)
- Real-time tracking for 8 Burp Suite tools:
  - Proxy (intercepted requests)
  - Repeater (manual requests)
  - Intruder (attacks)
  - Scanner (automated scans)
  - Spider (crawling)
  - Logger (HTTP traffic)
  - Target (scope changes)
  - Extender (extension events)
- Local H2 database storage
- Dark theme UI matching Burp Suite aesthetics
- Cloud sync capability (optional)
- Session duration tracking
- Tool-specific activity counters

### Technical
- H2 database for reliable local storage
- IScopeChangeListener for Target tracking
- IHttpListener for HTTP tool tracking
- IProxyListener for Proxy tracking
- IExtensionStateListener for extension lifecycle

### Known Limitations
- Decoder, Comparer, and Sequencer cannot be tracked (Burp Suite API limitation)
- These tools display "N/A" with dimmed styling to indicate the limitation

[1.0.0]: https://github.com/YOURUSERNAME/BurpHub/releases/tag/v1.0.0
