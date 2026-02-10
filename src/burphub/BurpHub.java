package burphub;

import burp.*;
import java.io.PrintWriter;

/**
 * BurpHub - Track your security testing activity like GitHub contributions
 * 
 * A Burp Suite extension that monitors usage and stores metrics locally.
 */
public class BurpHub implements IBurpExtender, IProxyListener, IHttpListener,
        IExtensionStateListener, IScopeChangeListener, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private DatabaseManager database;
    private ActivityTracker tracker;
    private BurpHubTab uiTab;

    private long sessionStartTime;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // Set extension name
        callbacks.setExtensionName("BurpHub");

        stdout.println("===========================================");
        stdout.println("  BurpHub - Activity Tracker v1.0");
        stdout.println("  Track your security testing like GitHub!");
        stdout.println("===========================================");

        try {
            // Initialize database
            String path = getDataPath();
            stdout.println("[*] Using database path: " + path);
            database = new DatabaseManager(path);
            database.initialize();
            stdout.println("[+] Database initialized");

            // Initialize activity tracker
            tracker = new ActivityTracker(database);
            stdout.println("[+] Activity tracker started");

            // Track session start (MUST happen before UI initialization to update streak)
            sessionStartTime = System.currentTimeMillis();
            tracker.recordSessionStart();
            stdout.println("[+] Session tracking started");

            // Initialize UI tab
            uiTab = new BurpHubTab(callbacks, database, tracker);
            callbacks.addSuiteTab(this);
            stdout.println("[+] UI tab added");

            // Register listeners
            callbacks.registerProxyListener(this);
            callbacks.registerHttpListener(this);
            callbacks.registerExtensionStateListener(this);
            callbacks.registerScopeChangeListener(this);
            stdout.println("[+] Listeners registered");

            stdout.println("\n[*] BurpHub is ready! Check the 'BurpHub' tab for stats.");

        } catch (Exception e) {
            stderr.println("[-] Failed to initialize BurpHub: " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }

    /**
     * Get the data directory for storing the SQLite database
     */
    private String getDataPath() {
        String userHome = System.getProperty("user.home");
        String dataDir = userHome + "/.burphub";

        // Create directory if it doesn't exist
        java.io.File dir = new java.io.File(dataDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        return dataDir + "/burphub.db";
    }

    // ==================== IProxyListener ====================

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (tracker == null)
            return;

        if (messageIsRequest) {
            // Track intercepted request
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);

            String method = requestInfo.getMethod();
            tracker.recordInterceptedRequest(method);

            // Update UI
            if (uiTab != null) {
                uiTab.refreshStats();
            }
        } else {
            // Track response
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            byte[] response = messageInfo.getResponse();

            if (response != null) {
                IResponseInfo responseInfo = helpers.analyzeResponse(response);
                int statusCode = responseInfo.getStatusCode();
                tracker.recordResponseStatus(statusCode);
            }
        }
    }

    // ==================== IHttpListener ====================

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (tracker == null)
            return;

        if (messageIsRequest) {
            // Track which tool sent the request
            switch (toolFlag) {
                case IBurpExtenderCallbacks.TOOL_REPEATER:
                    tracker.recordRepeaterRequest();
                    break;
                case IBurpExtenderCallbacks.TOOL_INTRUDER:
                    tracker.recordIntruderRequest();
                    break;
                case IBurpExtenderCallbacks.TOOL_SCANNER:
                    tracker.recordScannerRequest();
                    break;
                case IBurpExtenderCallbacks.TOOL_SPIDER:
                    tracker.recordSpiderRequest();
                    break;
                case IBurpExtenderCallbacks.TOOL_DECODER:
                    tracker.recordDecoderOperation();
                    break;
                case IBurpExtenderCallbacks.TOOL_COMPARER:
                    tracker.recordComparerOperation();
                    break;
                case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                    tracker.recordSequencerOperation();
                    break;
                case IBurpExtenderCallbacks.TOOL_EXTENDER:
                    tracker.recordExtenderEvent();
                    break;
                case IBurpExtenderCallbacks.TOOL_TARGET:
                    tracker.recordTargetAddition();
                    break;
            }

            // Update UI periodically (not every request to save CPU)
            if (tracker.getTotalRequestsToday() % 10 == 0 && uiTab != null) {
                uiTab.refreshStats();
            }
        }
    }

    // ==================== IExtensionStateListener ====================

    @Override
    public void extensionUnloaded() {
        stdout.println("\n[*] BurpHub shutting down...");

        if (tracker != null) {
            // Calculate session duration
            long sessionMinutes = (System.currentTimeMillis() - sessionStartTime) / 60000;
            tracker.recordSessionEnd(sessionMinutes);
            stdout.println("[+] Session recorded: " + sessionMinutes + " minutes");
        }

        // Sync to cloud dashboard
        if (database != null) {
            stdout.println("[*] Syncing to cloud...");
            String apiUrl = System.getProperty("burphub.api.url");
            String apiKey = System.getProperty("burphub.api.key");

            if (apiUrl != null && apiKey != null) {
                boolean synced = CloudSync.syncData(apiUrl, apiKey, database);
                if (synced) {
                    stdout.println("[+] Cloud sync successful!");
                } else {
                    stdout.println("[-] Cloud sync failed. Data saved locally.");
                }
            } else {
                stdout.println("[*] No cloud sync configured. Data saved locally only.");
            }

            database.close();
            stdout.println("[+] Database closed");
        }

        stdout.println("[*] BurpHub unloaded. See you next time!");
    }

    // ==================== IScopeChangeListener ====================

    @Override
    public void scopeChanged() {
        if (tracker != null) {
            tracker.recordTargetAddition();

            // Update UI
            if (uiTab != null) {
                uiTab.refreshStats();
            }
        }
    }

    // ==================== ITab ====================

    @Override
    public String getTabCaption() {
        return "BurpHub";
    }

    @Override
    public java.awt.Component getUiComponent() {
        return uiTab.getPanel();
    }
}
