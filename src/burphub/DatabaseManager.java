package burphub;

import java.sql.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

/**
 * DatabaseManager - Handles SQLite database operations for BurpHub
 */
public class DatabaseManager {

    private String dbPath;
    private Connection connection;

    // Use H2 database instead of SQLite
    private static final String DB_URL_PREFIX = "jdbc:h2:";
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ISO_LOCAL_DATE;

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
            connection = DriverManager.getConnection(url);
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
                        """
        };

        try (Statement stmt = connection.createStatement()) {
            for (String sql : createStatements) {
                stmt.execute(sql);
            }

            // Initialize streaks row if not exists (H2 syntax)
            stmt.execute("""
                        MERGE INTO streaks (id, current_streak, longest_streak, last_active_date)
                        KEY (id)
                        VALUES (1, 0, 0, NULL)
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
     */
    public Connection getConnection() {
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
        String sql = """
                    INSERT INTO method_counts (date, method, count)
                    VALUES (?, ?, 1)
                    ON CONFLICT(date, method) DO UPDATE SET count = count + 1
                """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, today());
            pstmt.setString(2, method);
            pstmt.executeUpdate();
        }
    }

    /**
     * Increment status code count
     */
    public void incrementStatusCount(int statusCode) throws SQLException {
        String sql = """
                    INSERT INTO status_counts (date, status_code, count)
                    VALUES (?, ?, 1)
                    ON CONFLICT(date, status_code) DO UPDATE SET count = count + 1
                """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
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
}
