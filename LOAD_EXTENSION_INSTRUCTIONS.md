# BurpHub Extension Loading Instructions

## Problem
The SQLite JDBC driver is not being packaged into the BurpHub JAR properly, causing a "No suitable driver found" error.

## Solution
Load **TWO JAR files** into Burp Suite:
1. The BurpHub extension JAR
2. The SQLite JDBC driver JAR (separately)

---

## Steps to Load BurpHub Extension

### 1. Remove Old Extension
1. In Burp Suite, go to **Extensions** → **Installed**
2. Find **BurpHub** (if loaded)
3. Click it and press **Remove**

### 2. Add SQLite Driver FIRST
1. Click **Add**
2. **Extension type**: Select **Java**
3. **Extension file**: Click **Select file...**
4. Navigate to: `C:\Users\DELL\Downloads\BurpHub\target\sqlite-jdbc-3.45.1.0.jar`
5. Click **Next**
6. It will load (no UI, just provides the driver classes)

### 3. Add BurpHub Extension SECOND
1. Click **Add** again
2. **Extension type**: Select **Java**
3. **Extension file**: Click **Select file...**
4. Navigate to: `C:\Users\DELL\Downloads\BurpHub\target\BurpHub.jar`
5. Click **Next**

### 4. Verify Success
After loading, you should see:
- ✅ **No errors** in the Errors tab
- ✅ **Initialization messages** in the Output tab
- ✅ **BurpHub tab** appears at the top of Burp Suite (next to Dashboard, Target, Proxy, etc.)

---

## Expected Output
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

---

## If It Still Fails
Check the **Errors** tab for any error messages and share them.
