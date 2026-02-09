# Part 2: BApp Store Submission (Long-term - Official Distribution)

## Overview

The **BApp Store** is PortSwigger's official Burp Suite extension marketplace. Extensions listed here get:
- ✅ One-click installation from within Burp Suite
- ✅ Highest trust and discoverability
- ✅ Automatic updates for users
- ✅ Official PortSwigger endorsement

**Timeline:** Review can take **weeks to months**. Do GitHub Release first for immediate availability!

---

## Step 1: Fork BAppStore Repository

1. **Go to**: https://github.com/PortSwigger/BappStore

2. **Click**: "Fork" button (top right)

3. **Create fork** to your account

This creates your own copy where you can add BurpHub.

---

## Step 2: Clone Your Fork

```powershell
# Clone your fork (replace YOUR_USERNAME)
git clone https://github.com/YOUR_USERNAME/BappStore.git
cd BappStore
```

---

## Step 3: Create BurpHub Extension Folder

```powershell
# Create directory for BurpHub
New-Item -ItemType Directory -Path "extender\BurpHub"
```

---

## Step 4: Create BappManifest.bmf

Create file: `extender\BurpHub\BappManifest.bmf`

```json
{
  "Name": "BurpHub",
  "ScreenVersion": "1.0.0",
  "SerialVersion": 1,
  "RepoName": "BurpHub",
  "Description": "Track your Burp Suite activity like GitHub contributions. Features activity heatmaps, streak tracking, and real-time metrics for 8 tools.",
  "Author": "Your Name",
  "Email": "your.email@example.com",
  "Flags": ["Java"],
  "Languages": ["Java"],
  "BappStore": "BappManifest.bmf",
  "MinBurpVersion": "2023.1",
  "Categories": ["Miscellaneous"],
  "GitHubRepo": "YOUR_USERNAME/BurpHub",
  "EntryPoint": "burphub.BurpHub",
  "BuildCommand": "mvn clean package -DskipTests",
  "JarFolder": "target"
}
```

**Important fields to update:**
- `Author` - Your name
- `Email` - Your email
- `GitHubRepo` - Your GitHub username/BurpHub

---

## Step 5: Create README.md for BAppStore

Create file: `extender\BurpHub\README.md`

```markdown
# BurpHub

Track your Burp Suite activity like GitHub contributions!

## Description

BurpHub monitors your Burp Suite usage and displays beautiful statistics with activity heatmaps, streak tracking, and tool-specific metrics.

## Features

- **Activity Heatmap** - GitHub-style 365-day activity visualization
- **Streak Tracking** - Current and longest streak counters
- **Real-time Metrics** - Track 8 Burp Suite tools in real-time
- **Local Database** - H2 database stores all data locally and privately
- **Cloud Sync** (Optional) - Sync to web dashboard for remote viewing
- **Dark Theme** - Matches Burp Suite's professional UI

## Tracked Tools

**Actively Tracked (8 tools):**
- Proxy, Repeater, Intruder, Scanner, Spider, Logger, Target, Extender

**Not Trackable (Burp API limitation):**
- Decoder, Comparer, Sequencer (display "N/A")

## Installation

Install directly from the BApp Store:
1. Burp Suite → Extensions → BApp Store
2. Search "BurpHub"
3. Click "Install"

## More Information

- GitHub: https://github.com/YOUR_USERNAME/BurpHub
- Issues: https://github.com/YOUR_USERNAME/BurpHub/issues

## License

MIT License
```

---

## Step 6: Add Screenshot (Required!)

PortSwigger requires at least one screenshot.

1. **Launch Burp with BurpHub**
2. **Take screenshot** of the BurpHub tab showing:
   - Activity heatmap
   - Streak counters
   - Tool statistics

3. **Save as**: `extender\BurpHub\screenshot.png`
   - Max size: 1920x1080
   - Format: PNG

---

## Step 7: Commit and Push to Your Fork

```powershell
# Commit your changes
git add extender/BurpHub/
git commit -m "Add BurpHub extension - Activity tracker for Burp Suite"
git push origin master
```

---

## Step 8: Create Pull Request

1. **Go to**: https://github.com/YOUR_USERNAME/BappStore

2. **Click**: "Contribute" → "Open pull request"

3. **Title**:
   ```
   Add BurpHub - Activity Tracker for Burp Suite
   ```

4. **Description**:
   ```markdown
   ## Extension Details
   
   **Name:** BurpHub
   **Version:** 1.0.0
   **Category:** Miscellaneous
   
   ## Description
   
   BurpHub tracks Burp Suite activity like GitHub contributions, featuring:
   - Activity heatmap (365 days)
   - Streak tracking
   - Real-time metrics for 8 tools
   - Local H2 database
   - Optional cloud sync
   
   ## Testing
   
   Tested on:
   - [x] Windows 11
   - [x] Burp Suite Community 2023.x
   - [x] Burp Suite Professional 2023.x
   - [x] Java 17
   
   ## Links
   
   - Repository: https://github.com/YOUR_USERNAME/BurpHub
   - Documentation: https://github.com/YOUR_USERNAME/BurpHub/blob/main/README.md
   - Installation Guide: https://github.com/YOUR_USERNAME/BurpHub/blob/main/INSTALLATION.md
   
   ## Notes
   
   This is my first BApp submission. Please let me know if any changes are needed!
   ```

5. **Click**: "Create pull request"

---

## Step 9: Wait for Review

**What happens next:**

1. **PortSwigger team reviews** your submission
2. They may request changes or ask questions
3. **You respond** to their feedback
4. **Once approved**, they merge your PR
5. **BurpHub appears** in the BApp Store!

**Timeline:**
- Typical: 2-8 weeks
- Can be longer during busy periods
- Check your GitHub notifications for updates

---

## Step 10: After Approval

Once merged:

1. **Users can install** via BApp Store in Burp Suite
2. **Monitor** GitHub issues for bug reports
3. **Update** as needed (increment version, create new PR)

---

## BApp Store Requirements Checklist

- [ ] BappManifest.bmf with correct metadata
- [ ] README.md describing the extension
- [ ] Screenshot.png showing the extension in action
- [ ] Working GitHub repository
- [ ] Builds successfully with specified build command
- [ ] Extension loads without errors in Burp Suite
- [ ] No security issues or malicious code
- [ ] Proper license (MIT recommended)

---

## Tips for Approval

✅ **Do:**
- Test thoroughly before submitting
- Include clear documentation
- Respond quickly to reviewer feedback
- Use semantic versioning (1.0.0, 1.1.0, etc.)

❌ **Don't:**
- Submit untested code
- Include broken links in documentation
- Ignore reviewer comments
- Submit malicious or poorly written code

---

## Updating Your Extension

When you release a new version:

1. Update version in `BappManifest.bmf`
2. Update `CHANGELOG.md` in your repo
3. Create new GitHub release
4. Create new PR to BappStore with updated manifest

---

## ✅ Checklist

- [ ] Forked BappStore repository
- [ ] Created BurpHub folder with required files
- [ ] Added screenshot
- [ ] Pushed to your fork
- [ ] Created pull request
- [ ] Monitoring GitHub for feedback

---

## 🎉 Summary

**GitHub Release** = Immediate availability (do first!)  
**BApp Store** = Official long-term distribution (do after)

Both complement each other:
- GitHub for immediate downloads
- BApp Store for built-in one-click installation

Good luck with your submission! 🚀
