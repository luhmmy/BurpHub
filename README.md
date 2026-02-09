# 🔥 BurpHub - Activity Tracker for Burp Suite

Track your security testing activity like GitHub contributions! BurpHub monitors your Burp Suite usage and displays beautiful statistics with activity heatmaps, streak tracking, and tool-specific metrics.

![BurpHub Dashboard](https://via.placeholder.com/800x400?text=BurpHub+Dashboard)

## ✨ Features

- **📊 Activity Heatmap** - GitHub-style 365-day activity visualization
- **🔥 Streak Tracking** - Current and longest streak counters
- **📈 Real-time Metrics** - Track 8 Burp Suite tools in real-time
- **💾 Local Database** - H2 database stores all data locally and privately
- **☁️ Cloud Sync** (Optional) - Sync to web dashboard for remote viewing
- **🎨 Dark Theme** - Matches Burp Suite's professional UI

## 🎯 Tracked Tools

**Actively Tracked (8 tools):**
- 🔍 Proxy - Intercepted requests
- 🔄 Repeater - Manual request repeats
- ⚔️ Intruder - Attack requests
- 🔬 Scanner - Automated scans
- 🕷️ Spider - Web crawling
- 📝 Logger - HTTP traffic
- 🎯 Target - Scope changes
- 🔌 Extender - Extension events

**Not Trackable (Burp API limitation):**
- 🔤 Decoder, ⚖️ Comparer, 🎲 Sequencer - Show "N/A"

## 📦 Installation

### Option 1: Manual Installation (All Burp Suite Versions)

1. **Download** the latest `BurpHub.jar` from [Releases](https://github.com/yourusername/BurpHub/releases)

2. **Load Extension** in Burp Suite:
   - Go to **Extensions** → **Add**
   - Extension type: **Java**
   - Select downloaded `BurpHub.jar`
   - Click **Next**

3. **Verify Installation**:
   - Check **Extensions** → **Output** for success message
   - New **BurpHub** tab should appear at the top

### Option 2: BApp Store (Coming Soon)

*Will be available directly in Burp Suite: Extensions → BApp Store → Search "BurpHub"*

## 🚀 Quick Start

1. **Install extension** (see above)
2. **Use Burp Suite normally** - BurpHub tracks automatically
3. **View stats** - Click the **BurpHub** tab
4. **Track streak** - Use Burp daily to build your streak!

## 🛠️ Requirements

- **Burp Suite** - Community or Professional Edition
- **Java** - Version 11 or higher
- **OS** - Windows, macOS, or Linux

## 📸 Screenshots

### Activity Dashboard
![Dashboard](https://via.placeholder.com/600x400?text=Activity+Dashboard)

### Streak Tracking
![Streaks](https://via.placeholder.com/600x400?text=Streak+Tracking)

## ☁️ Cloud Sync (Optional)

Sync your data to a web dashboard for remote viewing:

1. Deploy the cloud dashboard (see `dashboard/DEPLOY_GUIDE.md`)
2. Set Java properties when launching Burp:
   ```bash
   java -Dburphub.api.url=https://your-dashboard.com/sync \
        -Dburphub.api.key=your-secret-key \
        -jar burpsuite.jar
   ```

## 🗄️ Data Storage

BurpHub stores data locally in:
- **Windows**: `C:\Users\[username]\.burphub\burphub.db.mv.db`
- **macOS/Linux**: `~/.burphub/burphub.db.mv.db`

All data is stored **locally and privately**. Cloud sync is optional.

## 🔧 Building from Source

```bash
# Clone repository
git clone https://github.com/yourusername/BurpHub.git
cd BurpHub

# Build JAR
mvn clean package

# Output: target/BurpHub.jar
```

## 🐛 Troubleshooting

### Extension won't load
- Ensure Java 11+ is installed
- Check Burp's Extensions → Errors tab for details

### BurpHub tab not appearing
- Close and restart Burp Suite
- Delete database file and reload extension

### Database locked error
- Close Burp Suite completely
- Delete `~/.burphub/burphub.db.mv.db`
- Restart Burp and reload extension

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📄 License

MIT License - See [LICENSE](LICENSE) file

## 🙏 Credits

Created with ❤️ for the security testing community.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/BurpHub/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/BurpHub/discussions)

---

**⭐ If you find BurpHub useful, please star the repository!**
