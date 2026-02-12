package burphub;

import java.sql.SQLException;
import java.util.EnumMap;

/**
 * ActivityTracker - Tracks and records Burp Suite activity events
 */
public class ActivityTracker {

    private DatabaseManager database;

    /**
     * Enum for all trackable Burp Suite tools with their DB column names
     */
    public enum Tool {
        PROXY("intercepted_requests"),
        REPEATER("repeater_requests"),
        INTRUDER("intruder_requests"),
        SCANNER("scanner_requests"),
        SPIDER("spider_requests"),
        DECODER("decoder_operations"),
        COMPARER("comparer_operations"),
        SEQUENCER("sequencer_operations"),
        EXTENDER("extender_events"),
        TARGET("target_additions"),
        LOGGER("logger_requests");

        public final String column;

        Tool(String column) {
            this.column = column;
        }
    }

    // In-memory counters for current session (for quick access)
    private final EnumMap<Tool, Integer> todayCounts = new EnumMap<>(Tool.class);
    private final java.util.Map<String, Integer> extenderCounts = new java.util.HashMap<>();

    public ActivityTracker(DatabaseManager database) {
        this.database = database;
        // Initialize all counters to 0
        for (Tool tool : Tool.values()) {
            todayCounts.put(tool, 0);
        }
        loadTodayStats();
    }

    /**
     * Load today's stats from database into memory
     */
    private void loadTodayStats() {
        try {
            DatabaseManager.DailyStats stats = database.getTodayStats();
            todayCounts.put(Tool.PROXY, stats.interceptedRequests);
            todayCounts.put(Tool.REPEATER, stats.repeaterRequests);
            todayCounts.put(Tool.INTRUDER, stats.intruderRequests);
            todayCounts.put(Tool.SCANNER, stats.scannerRequests);
            todayCounts.put(Tool.SPIDER, stats.spiderRequests);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Increment activity for a third-party extension
     */
    public void recordExtensionActivity(String name) {
        try {
            database.incrementExtensionActivity(name);
            extenderCounts.merge(name, 1, Integer::sum);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Inform tracker about a loaded extension
     */
    public void registerExtension(String name) {
        try {
            database.recordExtensionPresence(name);
            if (!extenderCounts.containsKey(name)) {
                extenderCounts.put(name, database.getExtensionActivity(name));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public java.util.Map<String, Integer> getExtenderCounts() {
        return extenderCounts;
    }

    /**
     * Generic method to record activity for any tool
     */
    public void recordToolActivity(Tool tool) {
        try {
            database.incrementDailyStat(tool.column, 1);
            todayCounts.merge(tool, 1, Integer::sum);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

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
     * Record intercepted request (proxy) — also tracks HTTP method
     */
    public void recordInterceptedRequest(String method) {
        try {
            database.incrementDailyStat(Tool.PROXY.column, 1);
            database.incrementMethodCount(method);
            todayCounts.merge(Tool.PROXY, 1, Integer::sum);
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

    // Convenience methods that delegate to recordToolActivity
    public void recordRepeaterRequest() {
        recordToolActivity(Tool.REPEATER);
    }

    public void recordIntruderRequest() {
        recordToolActivity(Tool.INTRUDER);
    }

    public void recordScannerRequest() {
        recordToolActivity(Tool.SCANNER);
    }

    public void recordSpiderRequest() {
        recordToolActivity(Tool.SPIDER);
    }

    public void recordDecoderOperation() {
        recordToolActivity(Tool.DECODER);
    }

    public void recordComparerOperation() {
        recordToolActivity(Tool.COMPARER);
    }

    public void recordSequencerOperation() {
        recordToolActivity(Tool.SEQUENCER);
    }

    public void recordExtenderEvent() {
        recordToolActivity(Tool.EXTENDER);
    }

    public void recordTargetAddition() {
        recordToolActivity(Tool.TARGET);
    }

    public void recordLoggerRequest() {
        recordToolActivity(Tool.LOGGER);
    }

    // ==================== Getter Methods ====================

    public int getCount(Tool tool) {
        return todayCounts.getOrDefault(tool, 0);
    }

    public int getInterceptedToday() {
        return getCount(Tool.PROXY);
    }

    public int getRepeaterToday() {
        return getCount(Tool.REPEATER);
    }

    public int getIntruderToday() {
        return getCount(Tool.INTRUDER);
    }

    public int getScannerToday() {
        return getCount(Tool.SCANNER);
    }

    public int getSpiderToday() {
        return getCount(Tool.SPIDER);
    }

    public int getDecoderToday() {
        return getCount(Tool.DECODER);
    }

    public int getComparerToday() {
        return getCount(Tool.COMPARER);
    }

    public int getSequencerToday() {
        return getCount(Tool.SEQUENCER);
    }

    public int getExtenderToday() {
        return getCount(Tool.EXTENDER);
    }

    public int getTargetToday() {
        return getCount(Tool.TARGET);
    }

    public int getTotalRequestsToday() {
        return getCount(Tool.PROXY) + getCount(Tool.REPEATER)
                + getCount(Tool.INTRUDER) + getCount(Tool.SCANNER)
                + getCount(Tool.SPIDER);
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
        Tool best = Tool.PROXY;
        int max = 0;

        Tool[] httpTools = { Tool.PROXY, Tool.REPEATER, Tool.INTRUDER, Tool.SCANNER, Tool.SPIDER };
        for (Tool tool : httpTools) {
            int count = getCount(tool);
            if (count > max) {
                max = count;
                best = tool;
            }
        }

        if (max == 0)
            return "None";

        return switch (best) {
            case PROXY -> "Proxy";
            case REPEATER -> "Repeater";
            case INTRUDER -> "Intruder";
            case SCANNER -> "Scanner";
            case SPIDER -> "Spider";
            default -> "None";
        };
    }

    /**
     * Refresh stats from database
     */
    public void refresh() {
        loadTodayStats();
    }
}
