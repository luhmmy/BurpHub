# BurpHub Cloud Sync Configuration

## How to Enable Cloud Sync

After deploying the dashboard to Render, configure Burp Suite to sync your data:

### 1. Get Your Credentials from Render

- **API URL**: `https://YOUR-APP-NAME.onrender.com/api/sync`
- **API Key**: Found in Render dashboard → Environment → `SYNC_API_KEY`

### 2. Configure Burp Suite

#### Windows
Create a file: `burp-cloud-sync.bat`
```batch
@echo off
java -Dburphub.api.url=https://YOUR-APP-NAME.onrender.com/api/sync ^
     -Dburphub.api.key=YOUR_API_KEY_HERE ^
     -jar "C:\Program Files\BurpSuitePro\burpsuite_pro.jar"
```

#### macOS/Linux
Create a file: `burp-cloud-sync.sh`
```bash
#!/bin/bash
java -Dburphub.api.url=https://YOUR-APP-NAME.onrender.com/api/sync \
     -Dburphub.api.key=YOUR_API_KEY_HERE \
     -jar /path/to/burpsuite_pro.jar
```

Make executable: `chmod +x burp-cloud-sync.sh`

### 3. Launch Burp Suite

Run your script instead of launching Burp directly:
```bash
# Windows
burp-cloud-sync.bat

# macOS/Linux
./burp-cloud-sync.sh
```

### 4. Verify Sync

When you close Burp Suite, check the Extender output:
```
[*] Syncing to cloud...
[+] Cloud sync successful!
```

Visit your dashboard URL to see your activity!

## Manual Sync (Optional)

If you want to sync without closing Burp, we can add a "Sync Now" button to the BurpHub tab. Let me know if you want this feature!

## Troubleshooting

**Sync failed**: Check your API URL and Key
**403 Error**: API Key is incorrect
**Connection timeout**: Render service might be sleeping (free tier). Visit the dashboard URL first to wake it up.
