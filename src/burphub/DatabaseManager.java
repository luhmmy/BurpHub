package burphub;

import java.sql.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Set;

/**
 * DatabaseManager - Handles H2 database operations for BurpHub
 */
public class DatabaseManager {

    private String dbPath;
    private Connection connection;

    // Use H2 database instead of SQLite
    private static final String DB_URL_PREFIX = "jdbc:h2:";
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ISO_LOCAL_DATE;

    // Whitelist of valid column names for SQL injection prevention
    private static final Set<String> VALID_COLUMNS = Set.of(
            "intercepted_requests", "repeater_requests", "intruder_requests",
            "scanner_requests", "spider_requests", "decoder_operations",
            "comparer_operations", "sequencer_operations", "extender_events",
            "target_additions", "logger_requests");

    public DatabaseManager(String dbPath) {
        this.dbPath = dbPath;
    }

    /**
     * Initialize database connection and create tables
     */
    public void initialize() throws SQLException {
        try {
            // Explicitly load the H2 JDBC driver
            Class.forName("org.h2.Driver");

            String url = DB_URL_PREFIX + dbPath;
            // OWASP A07: Use credentials for defense-in-depth (local DB)
            connection = DriverManager.getConnection(url, "burphub", "burphub_local");
            createTables();
        } catch (ClassNotFoundException e) {
            throw new SQLException("H2 JDBC driver not found in classpath", e);
        }
    }

    /**
     * Create database tables if they don't exist
     */
    private void createTables() throws SQLException {
        String[] createStatements = {
                // Daily statistics
                """
                        CREATE TABLE IF NOT EXISTS daily_stats (
                            date TEXT PRIMARY KEY,
                            intercepted_requests INTEGER DEFAULT 0,
                            repeater_requests INTEGER DEFAULT 0,
                            intruder_requests INTEGER DEFAULT 0,
                            scanner_requests INTEGER DEFAULT 0,
                            spider_requests INTEGER DEFAULT 0,
                            decoder_operations INTEGER DEFAULT 0,
                            comparer_operations INTEGER DEFAULT 0,
                            sequencer_operations INTEGER DEFAULT 0,
                            extender_events INTEGER DEFAULT 0,
                            target_additions INTEGER DEFAULT 0,
                            logger_requests INTEGER DEFAULT 0,
                            session_minutes INTEGER DEFAULT 0,
                            sessions_count INTEGER DEFAULT 0
                        )
                        """,

                // HTTP method counts per day
                """
                        CREATE TABLE IF NOT EXISTS method_counts (
                            date TEXT,
                            method TEXT,
                            count INTEGER DEFAULT 0,
                            PRIMARY KEY (date, method)
                        )
                        """,

                // Response status code counts per day
                """
                        CREATE TABLE IF NOT EXISTS status_counts (
                            date TEXT,
                            status_code INTEGER,
                            count INTEGER DEFAULT 0,
                            PRIMARY KEY (date, status_code)
                        )
                        """,

                // Streak tracking
                """
                        CREATE TABLE IF NOT EXISTS streaks (
                            id INTEGER PRIMARY KEY,
                            current_streak INTEGER DEFAULT 0,
                            longest_streak INTEGER DEFAULT 0,
                            last_active_date TEXT
                        )
                        """,
                // User settings and profile info
                """
                        CREATE TABLE IF NOT EXISTS settings (
                            setting_key TEXT PRIMARY KEY,
                            setting_value TEXT
                        )
                        """,
                // Tracked extensions (loaded by user)
                """
                        CREATE TABLE IF NOT EXISTS extensions (
                            name TEXT PRIMARY KEY,
                            install_date TEXT,
                            last_seen TEXT,
                            activity_count INTEGER DEFAULT 0
                        )
                        """
        };

        try (Statement stmt = connection.createStatement()) {
            for (String sql : createStatements) {
                stmt.execute(sql);
            }

            // Initialize streaks row ONLY if it doesn't already exist
            // (Using INSERT with NOT EXISTS to avoid overwriting existing streak data)
            stmt.execute("""
                        INSERT INTO streaks (id, current_streak, longest_streak, last_active_date)
                        SELECT 1, 0, 0, NULL
                        WHERE NOT EXISTS (SELECT 1 FROM streaks WHERE id = 1)
                    """);
        }
    }

    /**
     * Get today's date as string
     */
    public String today() {
        return LocalDate.now().format(DATE_FORMAT);
    }

    /**
     * Get database connection (for cloud sync)
     * Package-private to prevent external access that bypasses column whitelist
     */
    Connection getConnection() {
        return connection;
    }

    /**
     * Ensure today's row exists in daily_stats
     */
    public void ensureTodayExists() throws SQLException {
        String sql = """
                    MERGE INTO daily_stats (date)
                    KEY (date)
                    VALUES (?)
                """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, today());
            pstmt.executeUpdate();
        }
    }

    /**
     * Increment a column in daily_stats
     */
    public void incrementDailyStat(String column, int amount) throws SQLException {
        // Validate column name against whitelist to prevent SQL injection
        if (!VALID_COLUMNS.contains(column)) {
            throw new IllegalArgumentException("Invalid column name: " + column);
        }

        ensureTodayExists();

        String sql = "UPDATE daily_stats SET " + column + " = " + column + " + ? WHERE date = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, amount);
            pstmt.setString(2, today());
            pstmt.executeUpdate();
        }
    }

    /**
     * Increment HTTP method count
     */
    public void incrementMethodCount(String method) throws SQLException {
        // First try to update existing row
        String updateSql = "UPDATE method_counts SET count = count + 1 WHERE date = ? AND method = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(updateSql)) {
            pstmt.setString(1, today());
            pstmt.setString(2, method);
            int updated = pstmt.executeUpdate();
            if (updated > 0)
                return;
        }
        // Row doesn't exist — insert it
        String insertSql = "INSERT INTO method_counts (date, method, count) VALUES (?, ?, 1)";
        try (PreparedStatement pstmt = connection.prepareStatement(insertSql)) {
            pstmt.setString(1, today());
            pstmt.setString(2, method);
            pstmt.executeUpdate();
        }
    }

    /**
     * Increment status code count
     */
    public void incrementStatusCount(int statusCode) throws SQLException {
        // First try to update existing row
        String updateSql = "UPDATE status_counts SET count = count + 1 WHERE date = ? AND status_code = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(updateSql)) {
            pstmt.setString(1, today());
            pstmt.setInt(2, statusCode);
            int updated = pstmt.executeUpdate();
            if (updated > 0)
                return;
        }
        // Row doesn't exist — insert it
        String insertSql = "INSERT INTO status_counts (date, status_code, count) VALUES (?, ?, 1)";
        try (PreparedStatement pstmt = connection.prepareStatement(insertSql)) {
            pstmt.setString(1, today());
            pstmt.setInt(2, statusCode);
            pstmt.executeUpdate();
        }
    }

    /**
     * Add session time
     */
    public void addSessionTime(long minutes) throws SQLException {
        ensureTodayExists();

        String sql = """
                    UPDATE daily_stats
                    SET session_minutes = session_minutes + ?,
                        sessions_count = sessions_count + 1
                    WHERE date = ?
                """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setLong(1, minutes);
            pstmt.setString(2, today());
            pstmt.executeUpdate();
        }

        updateStreak();
    }

    /**
     * Update streak tracking
     */
    public void updateStreak() throws SQLException {
        String selectSql = "SELECT current_streak, longest_streak, last_active_date FROM streaks WHERE id = 1";
        String updateSql = "UPDATE streaks SET current_streak = ?, longest_streak = ?, last_active_date = ? WHERE id = 1";

        try (Statement stmt = connection.createStatement();
                ResultSet rs = stmt.executeQuery(selectSql)) {

            if (rs.next()) {
                int currentStreak = rs.getInt("current_streak");
                int longestStreak = rs.getInt("longest_streak");
                String lastActive = rs.getString("last_active_date");

                LocalDate todayDate = LocalDate.now();
                String todayStr = today();

                if (lastActive == null) {
                    // First activity ever
                    currentStreak = 1;
                } else if (lastActive.equals(todayStr)) {
                    // Already active today, no change
                } else {
                    LocalDate lastActiveDate = LocalDate.parse(lastActive, DATE_FORMAT);
                    long daysBetween = java.time.temporal.ChronoUnit.DAYS.between(lastActiveDate, todayDate);

                    if (daysBetween == 1) {
                        // Consecutive day - increase streak
                        currentStreak++;
                    } else {
                        // Streak broken - reset
                        currentStreak = 1;
                    }
                }

                // Update longest streak if current is higher
                if (currentStreak > longestStreak) {
                    longestStreak = currentStreak;
                }

                try (PreparedStatement pstmt = connection.prepareStatement(updateSql)) {
                    pstmt.setInt(1, currentStreak);
                    pstmt.setInt(2, longestStreak);
                    pstmt.setString(3, todayStr);
                    pstmt.executeUpdate();
                }
            }
        }
    }

    /**
     * Get today's statistics
     */
    public DailyStats getTodayStats() throws SQLException {
        ensureTodayExists();

        String sql = "SELECT * FROM daily_stats WHERE date = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, today());
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                return new DailyStats(
                        rs.getString("date"),
                        rs.getInt("intercepted_requests"),
                        rs.getInt("repeater_requests"),
                        rs.getInt("intruder_requests"),
                        rs.getInt("scanner_requests"),
                        rs.getInt("spider_requests"),
                        rs.getInt("session_minutes"),
                        rs.getInt("sessions_count"));
            }
        }

        return new DailyStats(today(), 0, 0, 0, 0, 0, 0, 0);
    }

    /**
     * Get streak information
     */
    public StreakInfo getStreakInfo() throws SQLException {
        String sql = "SELECT current_streak, longest_streak, last_active_date FROM streaks WHERE id = 1";

        try (Statement stmt = connection.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                int currentStreak = rs.getInt("current_streak");
                int longestStreak = rs.getInt("longest_streak");
                String lastActive = rs.getString("last_active_date");

                // Check if streak is stale (more than 1 day since last activity)
                if (lastActive != null) {
                    LocalDate lastActiveDate = LocalDate.parse(lastActive, DATE_FORMAT);
                    long daysBetween = java.time.temporal.ChronoUnit.DAYS.between(lastActiveDate, LocalDate.now());

                    if (daysBetween > 1) {
                        // More than 1 day has passed, the current streak is effectively 0
                        // until a new session starts it at 1.
                        currentStreak = 0;
                    }
                }

                return new StreakInfo(currentStreak, longestStreak, lastActive);
            }
        }

        return new StreakInfo(0, 0, null);
    }

    /**
     * Get total stats across all time
     */
    public TotalStats getTotalStats() throws SQLException {
        String sql = """
                    SELECT
                        COUNT(*) as active_days,
                        SUM(intercepted_requests) as total_intercepted,
                        SUM(repeater_requests) as total_repeater,
                        SUM(intruder_requests) as total_intruder,
                        SUM(scanner_requests) as total_scanner,
                        SUM(session_minutes) as total_minutes,
                        SUM(sessions_count) as total_sessions
                    FROM daily_stats
                """;

        try (Statement stmt = connection.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return new TotalStats(
                        rs.getInt("active_days"),
                        rs.getInt("total_intercepted"),
                        rs.getInt("total_repeater"),
                        rs.getInt("total_intruder"),
                        rs.getInt("total_scanner"),
                        rs.getInt("total_minutes"),
                        rs.getInt("total_sessions"));
            }
        }

        return new TotalStats(0, 0, 0, 0, 0, 0, 0);
    }

    /**
     * Get activity for last N days (for heatmap)
     */
    public java.util.Map<String, Integer> getActivityHeatmap(int days) throws SQLException {
        java.util.Map<String, Integer> heatmap = new java.util.LinkedHashMap<>();

        LocalDate today = LocalDate.now();
        for (int i = days - 1; i >= 0; i--) {
            String date = today.minusDays(i).format(DATE_FORMAT);
            heatmap.put(date, 0);
        }

        String sql = """
                    SELECT date, intercepted_requests + repeater_requests + intruder_requests + scanner_requests as total
                    FROM daily_stats
                    WHERE date >= ?
                    ORDER BY date
                """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, today.minusDays(days - 1).format(DATE_FORMAT));
            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {
                heatmap.put(rs.getString("date"), rs.getInt("total"));
            }
        }

        return heatmap;
    }

    /**
     * Close database connection
     */
    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ==================== Data Classes ====================

    public static class DailyStats {
        public final String date;
        public final int interceptedRequests;
        public final int repeaterRequests;
        public final int intruderRequests;
        public final int scannerRequests;
        public final int spiderRequests;
        public final int sessionMinutes;
        public final int sessionsCount;

        public DailyStats(String date, int intercepted, int repeater, int intruder,
                int scanner, int spider, int minutes, int sessions) {
            this.date = date;
            this.interceptedRequests = intercepted;
            this.repeaterRequests = repeater;
            this.intruderRequests = intruder;
            this.scannerRequests = scanner;
            this.spiderRequests = spider;
            this.sessionMinutes = minutes;
            this.sessionsCount = sessions;
        }

        public int getTotalRequests() {
            return interceptedRequests + repeaterRequests + intruderRequests + scannerRequests + spiderRequests;
        }
    }

    public static class StreakInfo {
        public final int currentStreak;
        public final int longestStreak;
        public final String lastActiveDate;

        public StreakInfo(int current, int longest, String lastActive) {
            this.currentStreak = current;
            this.longestStreak = longest;
            this.lastActiveDate = lastActive;
        }
    }

    public static class TotalStats {
        public final int activeDays;
        public final int totalIntercepted;
        public final int totalRepeater;
        public final int totalIntruder;
        public final int totalScanner;
        public final int totalMinutes;
        public final int totalSessions;

        public TotalStats(int days, int intercepted, int repeater, int intruder,
                int scanner, int minutes, int sessions) {
            this.activeDays = days;
            this.totalIntercepted = intercepted;
            this.totalRepeater = repeater;
            this.totalIntruder = intruder;
            this.totalScanner = scanner;
            this.totalMinutes = minutes;
            this.totalSessions = sessions;
        }

        public int getTotalRequests() {
            return totalIntercepted + totalRepeater + totalIntruder + totalScanner;
        }
    }

    // ==================== Wrap Data Classes ====================

    public static class MonthlyWrap {
        public final int year, month;
        public final int totalRequests;
        public final String topTool;
        public final int topToolCount;
        public final String mostActiveDay;
        public final int mostActiveDayCount;
        public final int totalMinutes;
        public final int activeDays;
        public final int daysInMonth;
        public final int prevMonthRequests;

        public MonthlyWrap(int year, int month, int totalRequests,
                String topTool, int topToolCount,
                String mostActiveDay, int mostActiveDayCount,
                int totalMinutes, int activeDays, int daysInMonth,
                int prevMonthRequests) {
            this.year = year;
            this.month = month;
            this.totalRequests = totalRequests;
            this.topTool = topTool;
            this.topToolCount = topToolCount;
            this.mostActiveDay = mostActiveDay;
            this.mostActiveDayCount = mostActiveDayCount;
            this.totalMinutes = totalMinutes;
            this.activeDays = activeDays;
            this.daysInMonth = daysInMonth;
            this.prevMonthRequests = prevMonthRequests;
        }

        public int getChangePercent() {
            if (prevMonthRequests == 0)
                return totalRequests > 0 ? 100 : 0;
            return (int) (((double) (totalRequests - prevMonthRequests) / prevMonthRequests) * 100);
        }
    }

    public static class YearlyWrap {
        public final int year;
        public final int totalRequests;
        public final String topTool;
        public final int topToolCount;
        public final String mostActiveDay;
        public final int mostActiveDayCount;
        public final String mostActiveMonth;
        public final int mostActiveMonthCount;
        public final int totalMinutes;
        public final int activeDays;
        public final int longestStreak;
        public final int[] monthlyTotals;

        public YearlyWrap(int year, int totalRequests,
                String topTool, int topToolCount,
                String mostActiveDay, int mostActiveDayCount,
                String mostActiveMonth, int mostActiveMonthCount,
                int totalMinutes, int activeDays, int longestStreak,
                int[] monthlyTotals) {
            this.year = year;
            this.totalRequests = totalRequests;
            this.topTool = topTool;
            this.topToolCount = topToolCount;
            this.mostActiveDay = mostActiveDay;
            this.mostActiveDayCount = mostActiveDayCount;
            this.mostActiveMonth = mostActiveMonth;
            this.mostActiveMonthCount = mostActiveMonthCount;
            this.totalMinutes = totalMinutes;
            this.activeDays = activeDays;
            this.longestStreak = longestStreak;
            this.monthlyTotals = monthlyTotals;
        }
    }

    public static class DailyWrap {
        public final String date;
        public final int totalRequests;
        public final String topTool;
        public final int topToolCount;
        public final int sessionMinutes;
        public final int sessionsCount;
        public final int status2xx;
        public final int status4xx;
        public final int status5xx;

        public DailyWrap(String date, int totalRequests, String topTool, int topToolCount,
                int sessionMinutes, int sessionsCount, int status2xx, int status4xx, int status5xx) {
            this.date = date;
            this.totalRequests = totalRequests;
            this.topTool = topTool;
            this.topToolCount = topToolCount;
            this.sessionMinutes = sessionMinutes;
            this.sessionsCount = sessionsCount;
            this.status2xx = status2xx;
            this.status4xx = status4xx;
            this.status5xx = status5xx;
        }
    }

    // ==================== Wrap Queries ====================

    public MonthlyWrap getMonthlyWrap(int year, int month) throws SQLException {
        String monthPrefix = String.format("%04d-%02d", year, month);
        LocalDate monthStart = LocalDate.of(year, month, 1);
        int daysInMonth = monthStart.lengthOfMonth();

        String sql = """
                    SELECT
                        COALESCE(SUM(intercepted_requests + repeater_requests + intruder_requests + scanner_requests + spider_requests), 0) as total,
                        COALESCE(SUM(intercepted_requests), 0) as proxy,
                        COALESCE(SUM(repeater_requests), 0) as repeater,
                        COALESCE(SUM(intruder_requests), 0) as intruder,
                        COALESCE(SUM(scanner_requests), 0) as scanner,
                        COALESCE(SUM(spider_requests), 0) as spider,
                        COALESCE(SUM(session_minutes), 0) as minutes,
                        COUNT(*) as active_days
                    FROM daily_stats
                    WHERE date LIKE ?
                    AND (intercepted_requests + repeater_requests + intruder_requests + scanner_requests + spider_requests) > 0
                """;

        int totalRequests = 0, proxy = 0, repeater = 0, intruder = 0, scanner = 0, spider = 0;
        int totalMinutes = 0, activeDays = 0;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, monthPrefix + "%");
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                totalRequests = rs.getInt("total");
                proxy = rs.getInt("proxy");
                repeater = rs.getInt("repeater");
                intruder = rs.getInt("intruder");
                scanner = rs.getInt("scanner");
                spider = rs.getInt("spider");
                totalMinutes = rs.getInt("minutes");
                activeDays = rs.getInt("active_days");
            }
        }

        // Find top tool
        String topTool = "None";
        int topToolCount = 0;
        int[][] tools = { { proxy, 0 }, { repeater, 1 }, { intruder, 2 }, { scanner, 3 }, { spider, 4 } };
        String[] toolNames = { "Proxy", "Repeater", "Intruder", "Scanner", "Spider" };
        for (int[] tool : tools) {
            if (tool[0] > topToolCount) {
                topToolCount = tool[0];
                topTool = toolNames[tool[1]];
            }
        }

        // Find most active day
        String mostActiveDay = "None";
        int mostActiveDayCount = 0;
        String daySql = """
                    SELECT date,
                        (intercepted_requests + repeater_requests + intruder_requests + scanner_requests + spider_requests) as total
                    FROM daily_stats WHERE date LIKE ?
                    ORDER BY total DESC LIMIT 1
                """;
        try (PreparedStatement pstmt = connection.prepareStatement(daySql)) {
            pstmt.setString(1, monthPrefix + "%");
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                mostActiveDay = rs.getString("date");
                mostActiveDayCount = rs.getInt("total");
            }
        }

        // Previous month comparison
        LocalDate prevMonth = monthStart.minusMonths(1);
        String prevPrefix = String.format("%04d-%02d", prevMonth.getYear(), prevMonth.getMonthValue());
        int prevMonthRequests = 0;
        String prevSql = """
                    SELECT COALESCE(SUM(intercepted_requests + repeater_requests + intruder_requests + scanner_requests + spider_requests), 0) as total
                    FROM daily_stats WHERE date LIKE ?
                """;
        try (PreparedStatement pstmt = connection.prepareStatement(prevSql)) {
            pstmt.setString(1, prevPrefix + "%");
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                prevMonthRequests = rs.getInt("total");
            }
        }

        return new MonthlyWrap(year, month, totalRequests, topTool, topToolCount,
                mostActiveDay, mostActiveDayCount, totalMinutes, activeDays, daysInMonth,
                prevMonthRequests);
    }

    public YearlyWrap getYearlyWrap(int year) throws SQLException {
        String yearPrefix = String.format("%04d", year);

        String sql = """
                    SELECT
                        COALESCE(SUM(intercepted_requests + repeater_requests + intruder_requests + scanner_requests + spider_requests), 0) as total,
                        COALESCE(SUM(intercepted_requests), 0) as proxy,
                        COALESCE(SUM(repeater_requests), 0) as repeater,
                        COALESCE(SUM(intruder_requests), 0) as intruder,
                        COALESCE(SUM(scanner_requests), 0) as scanner,
                        COALESCE(SUM(spider_requests), 0) as spider,
                        COALESCE(SUM(session_minutes), 0) as minutes,
                        COUNT(*) as active_days
                    FROM daily_stats WHERE date LIKE ?
                    AND (intercepted_requests + repeater_requests + intruder_requests + scanner_requests + spider_requests) > 0
                """;

        int totalRequests = 0, proxy = 0, repeater = 0, intruder = 0, scanner = 0, spider = 0;
        int totalMinutes = 0, activeDays = 0;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, yearPrefix + "%");
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                totalRequests = rs.getInt("total");
                proxy = rs.getInt("proxy");
                repeater = rs.getInt("repeater");
                intruder = rs.getInt("intruder");
                scanner = rs.getInt("scanner");
                spider = rs.getInt("spider");
                totalMinutes = rs.getInt("minutes");
                activeDays = rs.getInt("active_days");
            }
        }

        // Find top tool
        String topTool = "None";
        int topToolCount = 0;
        int[][] tools = { { proxy, 0 }, { repeater, 1 }, { intruder, 2 }, { scanner, 3 }, { spider, 4 } };
        String[] toolNames = { "Proxy", "Repeater", "Intruder", "Scanner", "Spider" };
        for (int[] tool : tools) {
            if (tool[0] > topToolCount) {
                topToolCount = tool[0];
                topTool = toolNames[tool[1]];
            }
        }

        // Most active day of the year
        String mostActiveDay = "None";
        int mostActiveDayCount = 0;
        String daySql = """
                    SELECT date,
                        (intercepted_requests + repeater_requests + intruder_requests + scanner_requests + spider_requests) as total
                    FROM daily_stats WHERE date LIKE ?
                    ORDER BY total DESC LIMIT 1
                """;
        try (PreparedStatement pstmt = connection.prepareStatement(daySql)) {
            pstmt.setString(1, yearPrefix + "%");
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                mostActiveDay = rs.getString("date");
                mostActiveDayCount = rs.getInt("total");
            }
        }

        // Monthly totals for bar chart
        int[] monthlyTotals = new int[12];
        String mostActiveMonth = "None";
        int mostActiveMonthCount = 0;
        String[] monthNames = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

        for (int m = 1; m <= 12; m++) {
            String mPrefix = String.format("%04d-%02d", year, m);
            String mSql = """
                        SELECT COALESCE(SUM(intercepted_requests + repeater_requests + intruder_requests + scanner_requests + spider_requests), 0) as total
                        FROM daily_stats WHERE date LIKE ?
                    """;
            try (PreparedStatement pstmt = connection.prepareStatement(mSql)) {
                pstmt.setString(1, mPrefix + "%");
                ResultSet rs = pstmt.executeQuery();
                if (rs.next()) {
                    monthlyTotals[m - 1] = rs.getInt("total");
                    if (monthlyTotals[m - 1] > mostActiveMonthCount) {
                        mostActiveMonthCount = monthlyTotals[m - 1];
                        mostActiveMonth = monthNames[m - 1];
                    }
                }
            }
        }

        int longestStreak = 0;
        try {
            StreakInfo info = getStreakInfo();
            longestStreak = info.longestStreak;
        } catch (Exception e) {
            /* ignore */ }

        return new YearlyWrap(year, totalRequests, topTool, topToolCount,
                mostActiveDay, mostActiveDayCount, mostActiveMonth, mostActiveMonthCount,
                totalMinutes, activeDays, longestStreak, monthlyTotals);
    }

    public DailyWrap getDailyWrap(String date) throws SQLException {
        DailyStats stats = null;
        String sql = "SELECT * FROM daily_stats WHERE date = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, date);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                stats = new DailyStats(
                        rs.getString("date"),
                        rs.getInt("intercepted_requests"),
                        rs.getInt("repeater_requests"),
                        rs.getInt("intruder_requests"),
                        rs.getInt("scanner_requests"),
                        rs.getInt("spider_requests"),
                        rs.getInt("session_minutes"),
                        rs.getInt("sessions_count"));
            }
        }

        if (stats == null) {
            return new DailyWrap(date, 0, "None", 0, 0, 0, 0, 0, 0);
        }

        // Find top tool for the day
        String topTool = "None";
        int topToolCount = 0;
        int[] counts = { stats.interceptedRequests, stats.repeaterRequests, stats.intruderRequests,
                stats.scannerRequests, stats.spiderRequests };
        String[] toolNames = { "Proxy", "Repeater", "Intruder", "Scanner", "Spider" };
        for (int i = 0; i < counts.length; i++) {
            if (counts[i] > topToolCount) {
                topToolCount = counts[i];
                topTool = toolNames[i];
            }
        }

        // Get status code breakdown
        int s2xx = 0, s4xx = 0, s5xx = 0;
        String statusSql = "SELECT status_code, count FROM status_counts WHERE date = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(statusSql)) {
            pstmt.setString(1, date);
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                int code = rs.getInt("status_code");
                int count = rs.getInt("count");
                if (code >= 200 && code < 300)
                    s2xx += count;
                else if (code >= 400 && code < 500)
                    s4xx += count;
                else if (code >= 500 && code < 600)
                    s5xx += count;
            }
        }

        return new DailyWrap(date, stats.getTotalRequests(), topTool, topToolCount,
                stats.sessionMinutes, stats.sessionsCount, s2xx, s4xx, s5xx);
    }

    public void recordExtensionPresence(String name) throws SQLException {
        String sql = """
                    MERGE INTO extensions (name, install_date, last_seen)
                    KEY (name)
                    VALUES (?, COALESCE((SELECT install_date FROM extensions WHERE name = ?), ?), ?)
                """;
        String today = today();
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, name);
            pstmt.setString(2, name);
            pstmt.setString(3, today);
            pstmt.setString(4, today);
            pstmt.executeUpdate();
        }
    }

    public void incrementExtensionActivity(String name) throws SQLException {
        String sql = "UPDATE extensions SET activity_count = activity_count + 1, last_seen = ? WHERE name = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, today());
            pstmt.setString(2, name);
            pstmt.executeUpdate();
        }
    }

    public java.util.List<String> getActiveExtensions() throws SQLException {
        java.util.List<String> list = new java.util.ArrayList<>();
        String sql = "SELECT name FROM extensions WHERE last_seen = ? ORDER BY name ASC";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, today());
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                list.add(rs.getString("name"));
            }
        }
        return list;
    }

    public int getExtensionActivity(String name) throws SQLException {
        String sql = "SELECT activity_count FROM extensions WHERE name = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, name);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next())
                return rs.getInt("activity_count");
        }
        return 0;
    }

    public String getSetting(String key, String defaultValue) throws SQLException {
        String sql = "SELECT setting_value FROM settings WHERE setting_key = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, key);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("setting_value");
                }
            }
        }
        return defaultValue;
    }

    /**
     * Update or insert a setting
     */
    public void setSetting(String key, String value) throws SQLException {
        String sql = "MERGE INTO settings (setting_key, setting_value) KEY(setting_key) VALUES (?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, key);
            pstmt.setString(2, value);
            pstmt.executeUpdate();
        }
    }

    /**
     * Data class for user profile
     */
    public static class UserProfile {
        public String handle;
        public String bio;
        public String github;

        public UserProfile(String handle, String bio, String github) {
            this.handle = handle;
            this.bio = bio;
            this.github = github;
        }
    }

    /**
     * Get user profile info
     */
    public UserProfile getUserProfile() throws SQLException {
        return new UserProfile(
                getSetting("profile_handle", ""),
                getSetting("profile_bio", ""),
                getSetting("profile_github", ""));
    }
}
