package burphub;

import java.sql.SQLException;

/**
 * ActivityTracker - Tracks and records Burp Suite activity events
 */
public class ActivityTracker {

    private DatabaseManager database;

    // In-memory counters for current session (for quick access)
    private int interceptedToday = 0;
    private int repeaterToday = 0;
    private int intruderToday = 0;
    private int scannerToday = 0;
    private int spiderToday = 0;
    private int decoderToday = 0;
    private int comparerToday = 0;
    private int sequencerToday = 0;
    private int extenderToday = 0;
    private int targetToday = 0;
    private int loggerToday = 0;

    public ActivityTracker(DatabaseManager database) {
        this.database = database;
        loadTodayStats();
    }

    /**
     * Load today's stats from database into memory
     */
    private void loadTodayStats() {
        try {
            DatabaseManager.DailyStats stats = database.getTodayStats();
            this.interceptedToday = stats.interceptedRequests;
            this.repeaterToday = stats.repeaterRequests;
            this.intruderToday = stats.intruderRequests;
            this.scannerToday = stats.scannerRequests;
            this.spiderToday = stats.spiderRequests;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ==================== Recording Methods ====================

    /**
     * Record session start
     */
    public void recordSessionStart() {
        try {
            database.ensureTodayExists();
            database.updateStreak();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record session end with duration
     */
    public void recordSessionEnd(long minutes) {
        try {
            database.addSessionTime(minutes);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record intercepted request (proxy)
     */
    public void recordInterceptedRequest(String method) {
        try {
            database.incrementDailyStat("intercepted_requests", 1);
            database.incrementMethodCount(method);
            interceptedToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record response status code
     */
    public void recordResponseStatus(int statusCode) {
        try {
            database.incrementStatusCount(statusCode);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record Repeater request
     */
    public void recordRepeaterRequest() {
        try {
            database.incrementDailyStat("repeater_requests", 1);
            repeaterToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record Intruder request
     */
    public void recordIntruderRequest() {
        try {
            database.incrementDailyStat("intruder_requests", 1);
            intruderToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record Scanner request
     */
    public void recordScannerRequest() {
        try {
            database.incrementDailyStat("scanner_requests", 1);
            scannerToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record Spider request
     */
    public void recordSpiderRequest() {
        try {
            database.incrementDailyStat("spider_requests", 1);
            spiderToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record Decoder operation
     */
    public void recordDecoderOperation() {
        try {
            database.incrementDailyStat("decoder_operations", 1);
            decoderToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record Comparer operation
     */
    public void recordComparerOperation() {
        try {
            database.incrementDailyStat("comparer_operations", 1);
            comparerToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record Sequencer operation
     */
    public void recordSequencerOperation() {
        try {
            database.incrementDailyStat("sequencer_operations", 1);
            sequencerToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record Extender event
     */
    public void recordExtenderEvent() {
        try {
            database.incrementDailyStat("extender_events", 1);
            extenderToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record Target addition
     */
    public void recordTargetAddition() {
        try {
            database.incrementDailyStat("target_additions", 1);
            targetToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Record Logger request
     */
    public void recordLoggerRequest() {
        try {
            database.incrementDailyStat("logger_requests", 1);
            loggerToday++;
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ==================== Getter Methods ====================

    public int getInterceptedToday() {
        return interceptedToday;
    }

    public int getRepeaterToday() {
        return repeaterToday;
    }

    public int getIntruderToday() {
        return intruderToday;
    }

    public int getScannerToday() {
        return scannerToday;
    }

    public int getSpiderToday() {
        return spiderToday;
    }

    public int getTotalRequestsToday() {
        return interceptedToday + repeaterToday + intruderToday + scannerToday + spiderToday;
    }

    // ==================== NEW TOOL GETTERS ====================

    /**
     * Get Decoder operations today
     * Note: Decoder doesn't trigger HTTP events, so this returns 0
     */
    public int getDecoderToday() {
        return decoderToday;
    }

    /**
     * Get Comparer operations today
     * Note: Comparer doesn't trigger HTTP events, so this returns 0
     */
    public int getComparerToday() {
        return comparerToday;
    }

    /**
     * Get Sequencer operations today
     * Note: Sequencer doesn't trigger HTTP events, so this returns 0
     */
    public int getSequencerToday() {
        return sequencerToday;
    }

    /**
     * Get Extender events today
     */
    public int getExtenderToday() {
        return extenderToday;
    }

    /**
     * Get Target scope additions today
     */
    public int getTargetToday() {
        return targetToday;
    }

    /**
     * Get Logger requests today (same as ALL HTTP traffic)
     */
    public int getLoggerToday() {
        return getTotalRequestsToday();
    }

    /**
     * Get the most used tool today
     */
    public String getMostUsedToolToday() {
        int max = 0;
        String tool = "None";

        if (interceptedToday > max) {
            max = interceptedToday;
            tool = "Proxy";
        }
        if (repeaterToday > max) {
            max = repeaterToday;
            tool = "Repeater";
        }
        if (intruderToday > max) {
            max = intruderToday;
            tool = "Intruder";
        }
        if (scannerToday > max) {
            max = scannerToday;
            tool = "Scanner";
        }
        if (spiderToday > max) {
            tool = "Spider";
        }

        return tool;
    }

    /**
     * Refresh stats from database
     */
    public void refresh() {
        loadTodayStats();
    }
}
