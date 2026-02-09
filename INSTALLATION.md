# BurpHub Installation Guide

## For Regular Burp Suite Users

### Step 1: Download BurpHub

Download `BurpHub.jar` from the [latest release](https://github.com/yourusername/BurpHub/releases/latest)

### Step 2: Load Extension

1. **Launch Burp Suite** (Community or Professional)
2. Go to **Extensions** tab
3. Click **Add** button
4. Select **Extension Type**: Java
5. Click **Select file** and choose `BurpHub.jar`
6. Click **Next**

### Step 3: Verify

Check the **Output** sub-tab in Extensions. You should see:
```
===========================================
  BurpHub - Activity Tracker v1.0
  Track your security testing like GitHub!
===========================================
[+] Database initialized
[+] Activity tracker started
[+] UI tab added
[+] Listeners registered
[+] Session tracking started

[*] BurpHub is ready! Check the 'BurpHub' tab for stats.
```

A new **BurpHub** tab should appear at the top of Burp Suite.

---

## For Burploader Users

### Method 1: Standard Extension Loading (Recommended)

Even with burploader, you can load BurpHub the normal way:

1. Launch Burp (with or without burploader)
2. Follow the steps above (Extensions → Add → Java)

The extension works identically whether you use burploader or not.

### Method 2: Auto-load on Startup

To automatically load BurpHub every time Burp starts:

1. Create a Burp Suite project
2. Load BurpHub extension
3. Save the project
4. Open this project each time you launch Burp

---

## For Different Operating Systems

### Windows
```powershell
# JAR location after download
C:\Users\YourName\Downloads\BurpHub.jar

# Database location (auto-created)
C:\Users\YourName\.burphub\burphub.db.mv.db
```

### macOS
```bash
# JAR location after download
~/Downloads/BurpHub.jar

# Database location (auto-created)
~/.burphub/burphub.db.mv.db
```

### Linux
```bash
# JAR location after download
~/Downloads/BurpHub.jar

# Database location (auto-created)
~/.burphub/burphub.db.mv.db
```

---

## Verification Checklist

After installation, verify:

- [ ] No errors in Extensions → Errors tab
- [ ] Success message in Extensions → Output tab
- [ ] **BurpHub** tab visible at top of Burp
- [ ] Dashboard shows activity heatmap
- [ ] Streak counters visible (0 day streak initially)

---

## First-Time Setup

1. **Start using Burp normally** - BurpHub tracks automatically
2. **Send a test request** via Proxy or Repeater
3. **Check the BurpHub tab** - counters should update
4. **Build your streak** - Use Burp daily!

---

## Troubleshooting

### "Extension loaded successfully" but no BurpHub tab

**Solution:**
1. Close Burp Suite completely
2. Reopen Burp Suite
3. Check if tab appears

### Database locked error

**Solution:**
```powershell
# Windows
Remove-Item -Path "$env:USERPROFILE\.burphub\burphub.db.mv.db" -Force

# macOS/Linux
rm ~/.burphub/burphub.db.mv.db
```
Then restart Burp and reload extension.

### Java version errors

**Check Java version:**
```bash
java -version
```

**Required:** Java 11 or higher

### Extension fails to load

1. Check Extensions → Errors tab for details
2. Ensure you selected "Java" as extension type
3. Verify the JAR file isn't corrupted (re-download)

---

## Uninstallation

1. Extensions tab → Select **BurpHub**
2. Click **Remove** button
3. (Optional) Delete database:
   ```powershell
   # Windows
   Remove-Item -Recurse -Force "$env:USERPROFILE\.burphub"
   
   # macOS/Linux
   rm -rf ~/.burphub
   ```

---

## Need Help?

- 📖 [Full Documentation](https://github.com/yourusername/BurpHub)
- 🐛 [Report Issues](https://github.com/yourusername/BurpHub/issues)
- 💬 [Discussions](https://github.com/yourusername/BurpHub/discussions)
