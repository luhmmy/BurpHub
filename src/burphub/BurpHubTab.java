package burphub;

import burp.IBurpExtenderCallbacks;
import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.sql.SQLException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * BurpHubTab - GitHub-style activity dashboard for Burp Suite
 */
public class BurpHubTab {

    private IBurpExtenderCallbacks callbacks;
    private DatabaseManager database;
    private ActivityTracker tracker;

    private JPanel mainPanel;
    private HeatmapPanel heatmapPanel;
    private JLabel streakLabel;
    private JLabel longestStreakLabel;
    private JLabel todayRequestsLabel;
    private JLabel totalRequestsLabel;
    private JLabel totalTimeLabel;
    private JLabel activeDaysLabel;

    // Tool-specific labels (original 5)
    private JLabel proxyLabel;
    private JLabel repeaterLabel;
    private JLabel intruderLabel;
    private JLabel scannerLabel;
    private JLabel spiderLabel;

    // New tools (6 additional)
    private JLabel decoderLabel;
    private JLabel comparerLabel;
    private JLabel sequencerLabel;
    private JLabel extenderLabel;
    private JLabel targetLabel;
    private JLabel loggerLabel;

    // Colors - Dark theme matching Burp Suite
    private static final Color BG_DARK = new Color(30, 30, 30);
    private static final Color BG_CARD = new Color(45, 45, 45);
    private static final Color TEXT_PRIMARY = new Color(230, 230, 230);
    private static final Color TEXT_SECONDARY = new Color(160, 160, 160);
    private static final Color ACCENT_ORANGE = new Color(255, 140, 0);
    private static final Color ACCENT_RED = new Color(220, 50, 50);

    // Heatmap colors (Red team themed)
    private static final Color[] HEATMAP_COLORS = {
            new Color(22, 27, 34), // Level 0 - no activity
            new Color(75, 20, 20), // Level 1 - low
            new Color(140, 30, 30), // Level 2 - medium
            new Color(200, 45, 45), // Level 3 - high
            new Color(255, 60, 60) // Level 4 - very high activity
    };

    public BurpHubTab(IBurpExtenderCallbacks callbacks, DatabaseManager database, ActivityTracker tracker) {
        this.callbacks = callbacks;
        this.database = database;
        this.tracker = tracker;

        // Build UI synchronously to ensure panel is ready
        buildUI();
    }

    private void buildUI() {
        mainPanel = new JPanel(new BorderLayout(0, 0));
        mainPanel.setBackground(BG_DARK);

        // Create tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(BG_DARK);
        tabbedPane.setForeground(TEXT_PRIMARY);
        tabbedPane.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 13));

        // --- Tab 1: Dashboard (existing layout) ---
        JPanel dashboardPanel = new JPanel(new BorderLayout(0, 20));
        dashboardPanel.setBackground(BG_DARK);
        dashboardPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // Header
        JPanel headerPanel = createHeaderPanel();
        dashboardPanel.add(headerPanel, BorderLayout.NORTH);

        // Center content
        JPanel centerPanel = new JPanel(new BorderLayout(0, 20));
        centerPanel.setBackground(BG_DARK);

        // Heatmap section
        JPanel heatmapSection = createHeatmapSection();
        centerPanel.add(heatmapSection, BorderLayout.NORTH);

        // Stats grid
        JPanel statsPanel = createStatsPanel();
        centerPanel.add(statsPanel, BorderLayout.CENTER);

        dashboardPanel.add(centerPanel, BorderLayout.CENTER);

        tabbedPane.addTab("\uD83D\uDCCA Dashboard", dashboardPanel);

        // --- Tab 2: Wrapped ---
        WrapPanel wrapPanel = new WrapPanel(database);
        tabbedPane.addTab("\uD83C\uDFB5 Wrapped", wrapPanel);

        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        // Initial data load
        refreshStats();
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_DARK);

        // Title
        JLabel titleLabel = new JLabel("🔥 BurpHub");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 28));
        titleLabel.setForeground(TEXT_PRIMARY);

        JLabel subtitleLabel = new JLabel("Track your security testing activity");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        subtitleLabel.setForeground(TEXT_SECONDARY);

        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new BoxLayout(titlePanel, BoxLayout.Y_AXIS));
        titlePanel.setBackground(BG_DARK);
        titlePanel.add(titleLabel);
        titlePanel.add(Box.createVerticalStrut(5));
        titlePanel.add(subtitleLabel);

        // Streak display
        JPanel streakPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 20, 0));
        streakPanel.setBackground(BG_DARK);

        streakLabel = createStreakBadge("🔥 0 day streak", ACCENT_ORANGE);
        longestStreakLabel = createStreakBadge("🏆 Best: 0 days", TEXT_SECONDARY);

        streakPanel.add(longestStreakLabel);
        streakPanel.add(streakLabel);

        panel.add(titlePanel, BorderLayout.WEST);
        panel.add(streakPanel, BorderLayout.EAST);

        return panel;
    }

    private JLabel createStreakBadge(String text, Color color) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Segoe UI", Font.BOLD, 16));
        label.setForeground(color);
        label.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(color.darker(), 1),
                BorderFactory.createEmptyBorder(8, 15, 8, 15)));
        return label;
    }

    private JPanel createHeatmapSection() {
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.setBackground(BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(60, 60, 60), 1),
                BorderFactory.createEmptyBorder(15, 15, 15, 15)));

        JLabel title = new JLabel("Activity (Last 365 Days)");
        title.setFont(new Font("Segoe UI", Font.BOLD, 14));
        title.setForeground(TEXT_PRIMARY);
        panel.add(title, BorderLayout.NORTH);

        heatmapPanel = new HeatmapPanel();
        panel.add(heatmapPanel, BorderLayout.CENTER);

        // Legend
        JPanel legendPanel = createHeatmapLegend();
        panel.add(legendPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createHeatmapLegend() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        panel.setBackground(BG_CARD);

        JLabel lessLabel = new JLabel("Less");
        lessLabel.setForeground(TEXT_SECONDARY);
        lessLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        panel.add(lessLabel);

        for (Color color : HEATMAP_COLORS) {
            JPanel box = new JPanel();
            box.setPreferredSize(new Dimension(12, 12));
            box.setBackground(color);
            box.setBorder(BorderFactory.createLineBorder(new Color(60, 60, 60), 1));
            panel.add(box);
        }

        JLabel moreLabel = new JLabel("More");
        moreLabel.setForeground(TEXT_SECONDARY);
        moreLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        panel.add(moreLabel);

        return panel;
    }

    private JPanel createStatsPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 2, 20, 0));
        panel.setBackground(BG_DARK);

        // Left column - Today's stats
        JPanel todayPanel = createTodayStatsPanel();
        panel.add(todayPanel);

        // Right column - All-time stats
        JPanel allTimePanel = createAllTimeStatsPanel();
        panel.add(allTimePanel);

        return panel;
    }

    private JPanel createTodayStatsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 15));
        panel.setBackground(BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(60, 60, 60), 1),
                BorderFactory.createEmptyBorder(15, 15, 15, 15)));

        JLabel title = new JLabel("📊 Today's Activity");
        title.setFont(new Font("Segoe UI", Font.BOLD, 16));
        title.setForeground(TEXT_PRIMARY);
        panel.add(title, BorderLayout.NORTH);

        // Stats grid - 12 rows (total + 11 tools), 2 columns
        JPanel gridPanel = new JPanel(new GridLayout(12, 2, 10, 10));
        gridPanel.setBackground(BG_CARD);

        todayRequestsLabel = createStatValue("0");
        gridPanel.add(createStatLabel("Total Requests"));
        gridPanel.add(todayRequestsLabel);

        proxyLabel = createStatValue("0");
        gridPanel.add(createStatLabel("🔍 Proxy"));
        gridPanel.add(proxyLabel);

        repeaterLabel = createStatValue("0");
        gridPanel.add(createStatLabel("🔄 Repeater"));
        gridPanel.add(repeaterLabel);

        intruderLabel = createStatValue("0");
        gridPanel.add(createStatLabel("⚔️ Intruder"));
        gridPanel.add(intruderLabel);

        scannerLabel = createStatValue("0");
        gridPanel.add(createStatLabel("🔬 Scanner"));
        gridPanel.add(scannerLabel);

        spiderLabel = createStatValue("0");
        gridPanel.add(createStatLabel("🕷️ Spider"));
        gridPanel.add(spiderLabel);

        // New tools (non-trackable - no Burp API)
        decoderLabel = createDimmedStatValue("N/A");
        gridPanel.add(createStatLabel("🔤 Decoder (No API)"));
        gridPanel.add(decoderLabel);

        comparerLabel = createDimmedStatValue("N/A");
        gridPanel.add(createStatLabel("⚖️ Comparer (No API)"));
        gridPanel.add(comparerLabel);

        sequencerLabel = createDimmedStatValue("N/A");
        gridPanel.add(createStatLabel("🎲 Sequencer (No API)"));
        gridPanel.add(sequencerLabel);

        extenderLabel = createStatValue("0");
        gridPanel.add(createStatLabel("🔌 Extender"));
        gridPanel.add(extenderLabel);

        targetLabel = createStatValue("0");
        gridPanel.add(createStatLabel("🎯 Target"));
        gridPanel.add(targetLabel);

        loggerLabel = createStatValue("0");
        gridPanel.add(createStatLabel("📝 Logger"));
        gridPanel.add(loggerLabel);

        panel.add(gridPanel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createAllTimeStatsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 15));
        panel.setBackground(BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(60, 60, 60), 1),
                BorderFactory.createEmptyBorder(15, 15, 15, 15)));

        JLabel title = new JLabel("🏅 All-Time Stats");
        title.setFont(new Font("Segoe UI", Font.BOLD, 16));
        title.setForeground(TEXT_PRIMARY);
        panel.add(title, BorderLayout.NORTH);

        // Stats grid
        JPanel gridPanel = new JPanel(new GridLayout(3, 2, 10, 15));
        gridPanel.setBackground(BG_CARD);

        totalRequestsLabel = createStatValue("0");
        gridPanel.add(createStatLabel("Total Requests"));
        gridPanel.add(totalRequestsLabel);

        totalTimeLabel = createStatValue("0h 0m");
        gridPanel.add(createStatLabel("Total Time"));
        gridPanel.add(totalTimeLabel);

        activeDaysLabel = createStatValue("0");
        gridPanel.add(createStatLabel("Active Days"));
        gridPanel.add(activeDaysLabel);

        panel.add(gridPanel, BorderLayout.CENTER);

        return panel;
    }

    private JLabel createStatLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        label.setForeground(TEXT_SECONDARY);
        return label;
    }

    private JLabel createStatValue(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Segoe UI", Font.BOLD, 18));
        label.setForeground(ACCENT_RED);
        label.setHorizontalAlignment(SwingConstants.RIGHT);
        return label;
    }

    private JLabel createDimmedStatValue(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Segoe UI", Font.PLAIN, 16)); // Lighter weight
        label.setForeground(new Color(100, 100, 100)); // Dimmed gray
        label.setHorizontalAlignment(SwingConstants.RIGHT);
        return label;
    }

    /**
     * Refresh all stats from database
     */
    public void refreshStats() {
        SwingUtilities.invokeLater(() -> {
            try {
                // Update streak
                DatabaseManager.StreakInfo streak = database.getStreakInfo();
                streakLabel.setText("🔥 " + streak.currentStreak + " day streak");
                longestStreakLabel.setText("🏆 Best: " + streak.longestStreak + " days");

                // Update today's stats (original 5 tools)
                proxyLabel.setText(String.valueOf(tracker.getInterceptedToday()));
                repeaterLabel.setText(String.valueOf(tracker.getRepeaterToday()));
                intruderLabel.setText(String.valueOf(tracker.getIntruderToday()));
                scannerLabel.setText(String.valueOf(tracker.getScannerToday()));
                spiderLabel.setText(String.valueOf(tracker.getSpiderToday()));

                // Update new tools - Use real getter methods
                // Trackable tools (have API support)
                extenderLabel.setText(String.valueOf(tracker.getExtenderToday()));
                targetLabel.setText(String.valueOf(tracker.getTargetToday()));
                loggerLabel.setText(String.valueOf(tracker.getLoggerToday()));

                // Non-trackable tools (no Burp API - show N/A)
                decoderLabel.setText("N/A");
                comparerLabel.setText("N/A");
                sequencerLabel.setText("N/A");

                todayRequestsLabel.setText(String.valueOf(tracker.getTotalRequestsToday()));

                // Update all-time stats
                DatabaseManager.TotalStats total = database.getTotalStats();
                totalRequestsLabel.setText(formatNumber(total.getTotalRequests()));
                totalTimeLabel.setText(formatTime(total.totalMinutes));
                activeDaysLabel.setText(String.valueOf(total.activeDays));

                // Update heatmap
                Map<String, Integer> heatmapData = database.getActivityHeatmap(365);
                heatmapPanel.setData(heatmapData);

            } catch (SQLException e) {
                e.printStackTrace();
            }
        });
    }

    private String formatNumber(int num) {
        if (num >= 1000000) {
            return String.format("%.1fM", num / 1000000.0);
        } else if (num >= 1000) {
            return String.format("%.1fK", num / 1000.0);
        }
        return String.valueOf(num);
    }

    private String formatTime(int minutes) {
        int hours = minutes / 60;
        int mins = minutes % 60;
        if (hours > 0) {
            return hours + "h " + mins + "m";
        }
        return mins + "m";
    }

    public JPanel getPanel() {
        return mainPanel;
    }

    /**
     * Inner class for the GitHub-style heatmap visualization
     */
    private class HeatmapPanel extends JPanel {
        private Map<String, Integer> data;
        private static final int CELL_SIZE = 12;
        private static final int CELL_GAP = 3;
        private static final int WEEKS = 53;
        private static final int DAYS = 7;

        public HeatmapPanel() {
            setBackground(BG_CARD);
            setPreferredSize(new Dimension(
                    WEEKS * (CELL_SIZE + CELL_GAP) + 30,
                    DAYS * (CELL_SIZE + CELL_GAP) + 20));
        }

        public void setData(Map<String, Integer> data) {
            this.data = data;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2d = (Graphics2D) g;
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            if (data == null)
                return;

            // Day labels
            String[] days = { "", "Mon", "", "Wed", "", "Fri", "" };
            g2d.setColor(TEXT_SECONDARY);
            g2d.setFont(new Font("Segoe UI", Font.PLAIN, 10));
            for (int i = 0; i < days.length; i++) {
                g2d.drawString(days[i], 0, 20 + i * (CELL_SIZE + CELL_GAP) + CELL_SIZE - 2);
            }

            // Calculate max for normalization
            int maxActivity = data.values().stream().mapToInt(Integer::intValue).max().orElse(1);
            if (maxActivity == 0)
                maxActivity = 1;

            // Draw cells
            LocalDate today = LocalDate.now();
            LocalDate startDate = today.minusDays(364);
            int startDayOfWeek = startDate.getDayOfWeek().getValue() % 7; // 0 = Sunday

            DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE;

            int col = 0;
            int row = startDayOfWeek;

            for (int i = 0; i < 365; i++) {
                LocalDate date = startDate.plusDays(i);
                String dateStr = date.format(formatter);
                int activity = data.getOrDefault(dateStr, 0);

                // Determine color level
                int level;
                if (activity == 0) {
                    level = 0;
                } else if (activity <= maxActivity * 0.25) {
                    level = 1;
                } else if (activity <= maxActivity * 0.5) {
                    level = 2;
                } else if (activity <= maxActivity * 0.75) {
                    level = 3;
                } else {
                    level = 4;
                }

                int x = 30 + col * (CELL_SIZE + CELL_GAP);
                int y = 10 + row * (CELL_SIZE + CELL_GAP);

                g2d.setColor(HEATMAP_COLORS[level]);
                g2d.fillRoundRect(x, y, CELL_SIZE, CELL_SIZE, 3, 3);

                row++;
                if (row >= 7) {
                    row = 0;
                    col++;
                }
            }
        }
    }
}
