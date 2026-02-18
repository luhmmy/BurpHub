# CV Project Write-ups

Here are professional descriptions for your two major projects, tailored for a technical CV or resume. I've focused on action verbs, technical specifics, and the impact of the work.

---

## 1. BurpHub | Burp Suite Security Activity Tracker
*Security Research Tool / Java Extension* | [GitHub Link](https://github.com/luhmmy/BurpHub)

- **Developed a Java-based Burp Suite extension** to gamify and visualize security testing activity using a GitHub-style 365-day heatmap and streak-tracking system.
- **Implemented real-time event listeners** using the Burp Suite Extender API to track activity across 8 core tools (Proxy, Repeater, Intruder, Scanner, etc.), managing complex state logic to ensure high data accuracy.
- **Architected a local-first data storage system** using the **H2 embedded database**, optimizing JAR packaging and ensuring cross-platform stability without external dependencies.
- **Integrated optional cloud synchronization** by building a secure REST API in Python/Flask, allowing users to sync local metrics to a web-based dashboard for remote progress tracking.
- **Enhanced user experience** with a professional dark-themed Swing UI, providing hunters with instant visual feedback and consistency metrics.

**Key Technologies:** Java, Burp Suite API, Maven, H2 (SQL), Python/Flask, Swing UI.

---

## 2. Slack LinkGuard | Automated URL Security Scanner
*Cybersecurity Bot / Slack Integration* | [GitHub Link](https://github.com/luhmmy/slack-linkguard)

- **Built a Python-powered Slack integration** designed to automatically detect and scan URLs in multi-channel environments for malicious activity.
- **Integrated the VirusTotal API** to perform automated threat intelligence lookups, providing real-time feedback and security alerts to users within the Slack interface.
- **Optimized performance through parallel processing**, implementing asynchronous URL scanning logic to handle multiple concurrent links without degrading bot response time.
- **Engineered a database migration** from SQLite to **PostgreSQL**, ensuring long-term data persistence and scalability for high-traffic workspace environments.
- **Implemented intelligent caching** to minimize redundant API calls, significantly reducing latency and operational costs while maintaining up-to-date threat data.

**Key Technologies:** Python (Bolt Framework), Slack API, VirusTotal API, PostgreSQL, Asynchronous Programming.

---

### Tips for your CV:
- **Links:** Be sure to replace those placeholder GitHub links with your actual URLs.
- **Impact:** If you have any stats (e.g., "Scanned 1,000+ URLs," "Used by X people," or "Found X bugs used in testing"), add those to the end of the bullet points.
- **Placement:** Put these under a "Projects" or "Open Source Contributions" section.
