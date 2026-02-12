package burphub;

import burp.*;
import java.io.PrintWriter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.swing.SwingUtilities;

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
    private ScheduledExecutorService scheduler;

    private boolean filterInScopeEnabled = false;
    private long lastFilterCheckTime = 0;
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

            // Initial extension scan
            scanExtensions();
            stdout.println("[+] Third-party extensions scanned");

            // Start background sync (every 5 minutes)
            startBackgroundSync();
            stdout.println("[+] Background sync scheduler started");

            stdout.println("\n[*] BurpHub is ready! Check the 'BurpHub' tab for stats.");

        } catch (Exception e) {
            stderr.println("[-] Failed to initialize BurpHub: " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }

    /**
     * Get the data directory for storing the H2 database
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

        // OWASP A01: Respect user-defined scope
        if (!isRequestInScope(message.getMessageInfo())) {
            return;
        }

        if (messageIsRequest) {
            // Track intercepted request
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);

            String method = requestInfo.getMethod();
            tracker.recordInterceptedRequest(method);

            // Update UI on EDT
            if (uiTab != null) {
                SwingUtilities.invokeLater(() -> uiTab.refreshStats());
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

        // OWASP A01: Respect user-defined scope
        if (!isRequestInScope(messageInfo)) {
            return;
        }

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
                    // HACK: Use stack trace to identify the extension
                    String extName = identifyExtension();
                    tracker.recordExtensionActivity(extName);
                    tracker.recordExtenderEvent();
                    break;
                case IBurpExtenderCallbacks.TOOL_TARGET:
                    tracker.recordTargetAddition();
                    break;
            }

            // Update UI periodically on EDT (not every request to save CPU)
            if (tracker.getTotalRequestsToday() % 10 == 0 && uiTab != null) {
                SwingUtilities.invokeLater(() -> uiTab.refreshStats());
            }
        }
    }

    /**
     * Checks if a request should be recorded based on the "filter_in_scope"
     * setting.
     */
    private boolean isRequestInScope(IHttpRequestResponse messageInfo) {
        if (database == null)
            return true;

        try {
            // Cache filter status for 10 seconds to avoid heavy DB load
            if (System.currentTimeMillis() - lastFilterCheckTime > 10000) {
                String setting = database.getSetting("filter_in_scope", "false");
                filterInScopeEnabled = "true".equals(setting);
                lastFilterCheckTime = System.currentTimeMillis();
            }

            if (!filterInScopeEnabled) {
                return true; // Filtering not enabled, record always
            }

            if (messageInfo == null)
                return false;

            // Robust URL extraction
            IHttpService service = messageInfo.getHttpService();
            byte[] requestBytes = messageInfo.getRequest();

            if (service == null || requestBytes == null) {
                return false; // Can't determine scope without service/request
            }

            // Burp's analyzeRequest handles building the full URL correctly
            IRequestInfo requestInfo = helpers.analyzeRequest(service, requestBytes);
            java.net.URL url = requestInfo.getUrl();

            return callbacks.isInScope(url);

        } catch (Exception e) {
            // Safety: if filter is enabled but check fails, don't record
            return !filterInScopeEnabled;
        }
    }

    // ==================== IExtensionStateListener ====================

    @Override
    public void extensionUnloaded() {
        stdout.println("\n[*] BurpHub shutting down...");

        if (scheduler != null) {
            scheduler.shutdownNow();
        }

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
                boolean synced = CloudSync.syncData(apiUrl, apiKey, database, callbacks);
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

            // Update UI on EDT
            if (uiTab != null) {
                SwingUtilities.invokeLater(() -> uiTab.refreshStats());
            }
        }
    }

    // ==================== ITab ====================

    @Override
    public String getTabCaption() {
        return "BurpHub";
    }

    /**
     * Identify the calling extension using stack trace analysis
     */
    private String identifyExtension() {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        for (StackTraceElement element : stackTrace) {
            String className = element.getClassName();
            // Look for non-BurpHub, non-Burp internal classes
            if (!className.startsWith("burphub.") &&
                    !className.startsWith("java.") &&
                    !className.startsWith("sun.") &&
                    !className.startsWith("burp.IBurp") &&
                    !className.startsWith("burp.IProxy") &&
                    !className.startsWith("burp.IHttp") &&
                    !className.startsWith("burp.IRequest") &&
                    !className.startsWith("burp.IResponse") &&
                    !className.startsWith("burp.IMessage") &&
                    !className.startsWith("burp.IExtension") &&
                    !className.startsWith("burp.IContextMenu") &&
                    !className.equals("java.lang.Thread") &&
                    !className.contains(".ActivityTracker") &&
                    !className.contains(".CloudSync") &&
                    !className.contains(".DatabaseManager")) {

                // Extract "extension" name from class package
                // e.g. "burp.Autorize.Autorize" -> "Autorize"
                String[] parts = className.split("\\.");
                if (parts.length > 2) {
                    // Avoid returning purely "burp" or "internal"
                    if (parts[parts.length - 2].equalsIgnoreCase("burp"))
                        return parts[parts.length - 1];
                    return parts[parts.length - 2];
                }
                return parts[parts.length - 1];
            }
        }
        return "Unknown Tool";
    }

    private void startBackgroundSync() {
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            try {
                String apiUrl = System.getProperty("burphub.api.url");
                String apiKey = System.getProperty("burphub.api.key");

                if (apiUrl != null && apiKey != null && database != null) {
                    CloudSync.syncData(apiUrl, apiKey, database, callbacks);
                }
            } catch (Exception e) {
                // Background sync fail is silent to not disturb user
            }
        }, 2, 2, TimeUnit.MINUTES);
    }

    /**
     * Scan for all loaded extensions and register them
     */
    private void scanExtensions() {
        if (callbacks == null || tracker == null)
            return;

        // Since we can't get names directly from the API, we'll rely on
        // identifyExtension() during runtime traffic.
        // We register a generic entry to ensure the UI space is initialized.
        tracker.registerExtension("Extender Traffic");
    }

    @Override
    public java.awt.Component getUiComponent() {
        return uiTab.getPanel();
    }
}
