package burphub;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.sql.*;

/**
 * CloudSync - Syncs BurpHub data to cloud dashboard
 */
public class CloudSync {

    /**
     * Sync all data to cloud API
     */
    public static boolean syncData(String apiUrl, String apiKey, DatabaseManager database) {
        try {
            // Build JSON payload
            String jsonPayload = buildSyncPayload(database);

            // Send HTTP POST request
            URL url = new URL(apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-API-Key", apiKey);
            conn.setDoOutput(true);

            // Write payload
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonPayload.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // Check response
            int responseCode = conn.getResponseCode();
            conn.disconnect();

            return responseCode == 200;

        } catch (Exception e) {
            System.err.println("Cloud sync failed: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Build JSON payload from database
     */
    private static String buildSyncPayload(DatabaseManager database) throws SQLException {
        StringBuilder json = new StringBuilder();
        json.append("{");

        // Add daily stats
        json.append("\"daily_stats\":{");

        Connection conn = database.getConnection();
        try (Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM daily_stats ORDER BY date DESC LIMIT 90")) {

            boolean first = true;
            while (rs.next()) {
                if (!first)
                    json.append(",");
                first = false;

                String date = rs.getString("date");
                json.append("\"").append(date).append("\":{");
                json.append("\"intercepted_requests\":").append(rs.getInt("intercepted_requests")).append(",");
                json.append("\"repeater_requests\":").append(rs.getInt("repeater_requests")).append(",");
                json.append("\"intruder_requests\":").append(rs.getInt("intruder_requests")).append(",");
                json.append("\"scanner_requests\":").append(rs.getInt("scanner_requests")).append(",");
                json.append("\"spider_requests\":").append(rs.getInt("spider_requests")).append(",");
                json.append("\"decoder_operations\":").append(rs.getInt("decoder_operations")).append(",");
                json.append("\"comparer_operations\":").append(rs.getInt("comparer_operations")).append(",");
                json.append("\"sequencer_operations\":").append(rs.getInt("sequencer_operations")).append(",");
                json.append("\"extender_events\":").append(rs.getInt("extender_events")).append(",");
                json.append("\"target_additions\":").append(rs.getInt("target_additions")).append(",");
                json.append("\"logger_requests\":").append(rs.getInt("logger_requests")).append(",");
                json.append("\"session_minutes\":").append(rs.getInt("session_minutes")).append(",");
                json.append("\"sessions_count\":").append(rs.getInt("sessions_count"));
                json.append("}");
            }
        }

        json.append("},");

        // Add profile info
        json.append("\"profile\":{");
        DatabaseManager.UserProfile profile = database.getUserProfile();
        json.append("\"handle\":\"").append(escapeJson(profile.handle)).append("\",");
        json.append("\"bio\":\"").append(escapeJson(profile.bio)).append("\",");
        json.append("\"github\":\"").append(escapeJson(profile.github)).append("\"");
        json.append("},");

        // Add streak info
        json.append("\"streak\":{");
        DatabaseManager.StreakInfo streak = database.getStreakInfo();
        json.append("\"current_streak\":").append(streak.currentStreak).append(",");
        json.append("\"longest_streak\":").append(streak.longestStreak).append(",");
        json.append("\"last_active_date\":\"").append(streak.lastActiveDate != null ? streak.lastActiveDate : "")
                .append("\"");
        json.append("}");

        json.append("}");

        return json.toString();
    }

    /**
     * Escape JSON string
     */
    private static String escapeJson(String str) {
        if (str == null)
            return "";
        return str.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
