package burphub;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.time.LocalDate;
import java.time.Month;
import java.time.format.TextStyle;
import java.util.Locale;

/**
 * WrapPanel - Interactive Spotify Wrapped-style summary for BurpHub
 * Features: animated counters, hover effects, story-mode slides, gradient
 * backgrounds
 */
public class WrapPanel extends JPanel {

    private DatabaseManager database;

    // Current state
    private int currentYear;
    private int currentMonth;
    private boolean isYearlyMode = false;
    private boolean isDailyMode = false;
    private int currentSlide = 0;
    private int totalSlides = 6;

    // Animation state
    private Timer animationTimer;
    private int animatedValue = 0;
    private int targetValue = 0;
    private float fadeAlpha = 0f;
    private Timer fadeTimer;

    // Cached data
    private DatabaseManager.MonthlyWrap monthlyData;
    private DatabaseManager.YearlyWrap yearlyData;
    private DatabaseManager.DailyWrap dailyData;

    // Colors
    private static final Color BG_DARK = new Color(30, 30, 30);
    private static final Color BG_CARD = new Color(45, 45, 45);
    private static final Color BG_CARD_HOVER = new Color(55, 55, 55);
    private static final Color TEXT_PRIMARY = new Color(230, 230, 230);
    private static final Color TEXT_SECONDARY = new Color(160, 160, 160);
    private static final Color ACCENT_RED = new Color(220, 50, 50);
    private static final Color ACCENT_ORANGE = new Color(255, 140, 0);
    private static final Color ACCENT_CRIMSON = new Color(180, 30, 60);

    // Gradient colors for each slide
    private static final Color[][] SLIDE_GRADIENTS = {
            { new Color(40, 10, 10), new Color(80, 20, 20) }, // Total Requests - deep red
            { new Color(10, 20, 40), new Color(20, 40, 80) }, // Top Tool - dark blue
            { new Color(40, 30, 10), new Color(80, 60, 20) }, // Most Active Day - amber
            { new Color(10, 30, 20), new Color(20, 60, 40) }, // Session Time - dark teal
            { new Color(30, 10, 30), new Color(60, 20, 60) }, // Active Days - purple
            { new Color(40, 15, 15), new Color(100, 30, 30) }, // Comparison - bright red
            { new Color(20, 20, 35), new Color(40, 40, 70) }, // Longest Streak (yearly)
            { new Color(15, 25, 35), new Color(30, 50, 70) }, // Bar Chart (yearly)
    };

    // Slide content panels
    private JPanel slideContainer;
    private CardLayout slideLayout;
    private JLabel slideCounter;

    // Nav buttons
    private JButton prevBtn, nextBtn;
    private JButton dailyBtn, monthlyBtn, yearlyBtn;
    private JComboBox<String> monthSelector;
    private JComboBox<Integer> yearSelector;

    public WrapPanel(DatabaseManager database) {
        this.database = database;
        this.currentYear = LocalDate.now().getYear();
        this.currentMonth = LocalDate.now().getMonthValue();

        setLayout(new BorderLayout(0, 0));
        setBackground(BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        buildUI();
        loadData();
    }

    private void buildUI() {
        // Top bar: mode toggle + date selector
        JPanel topBar = createTopBar();
        add(topBar, BorderLayout.NORTH);

        // Center: slide content
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBackground(BG_DARK);

        slideLayout = new CardLayout();
        slideContainer = new JPanel(slideLayout);
        slideContainer.setBackground(BG_DARK);

        centerPanel.add(slideContainer, BorderLayout.CENTER);

        // Navigation arrows
        JPanel navPanel = createNavPanel();
        centerPanel.add(navPanel, BorderLayout.SOUTH);

        add(centerPanel, BorderLayout.CENTER);
    }

    private JPanel createTopBar() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_DARK);
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 15, 0));

        // Left: Mode toggle
        JPanel modePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        modePanel.setBackground(BG_DARK);

        dailyBtn = createToggleButton("Daily", false);
        monthlyBtn = createToggleButton("Monthly", true);
        yearlyBtn = createToggleButton("Yearly", false);

        dailyBtn.addActionListener(e -> {
            isDailyMode = true;
            isYearlyMode = false;
            currentSlide = 0;
            totalSlides = 6;
            updateToggleState();
            loadData();
        });

        monthlyBtn.addActionListener(e -> {
            isDailyMode = false;
            isYearlyMode = false;
            currentSlide = 0;
            totalSlides = 7;
            updateToggleState();
            loadData();
        });

        yearlyBtn.addActionListener(e -> {
            isDailyMode = false;
            isYearlyMode = true;
            currentSlide = 0;
            totalSlides = 9;
            updateToggleState();
            loadData();
        });

        modePanel.add(dailyBtn);
        modePanel.add(monthlyBtn);
        modePanel.add(yearlyBtn);
        panel.add(modePanel, BorderLayout.WEST);

        // Right: Date selector
        JPanel datePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        datePanel.setBackground(BG_DARK);

        String[] months = new String[12];
        for (int i = 0; i < 12; i++) {
            months[i] = Month.of(i + 1).getDisplayName(TextStyle.FULL, Locale.ENGLISH);
        }
        monthSelector = new JComboBox<>(months);
        monthSelector.setSelectedIndex(currentMonth - 1);
        monthSelector.setBackground(BG_CARD);
        monthSelector.setForeground(TEXT_PRIMARY);
        monthSelector.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        monthSelector.addActionListener(e -> {
            currentMonth = monthSelector.getSelectedIndex() + 1;
            currentSlide = 0;
            loadData();
        });

        Integer[] years = new Integer[5];
        int startYear = currentYear - 4;
        for (int i = 0; i < 5; i++) {
            years[i] = startYear + i;
        }
        yearSelector = new JComboBox<>(years);
        yearSelector.setSelectedItem(currentYear);
        yearSelector.setBackground(BG_CARD);
        yearSelector.setForeground(TEXT_PRIMARY);
        yearSelector.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        yearSelector.addActionListener(e -> {
            currentYear = (Integer) yearSelector.getSelectedItem();
            currentSlide = 0;
            loadData();
        });

        datePanel.add(monthSelector);
        datePanel.add(yearSelector);
        panel.add(datePanel, BorderLayout.EAST);

        // Center: Title
        JLabel title = new JLabel("YOUR WRAP", SwingConstants.CENTER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 16));
        title.setForeground(ACCENT_RED);
        panel.add(title, BorderLayout.CENTER);

        return panel;
    }

    private JButton createToggleButton(String text, boolean active) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setPreferredSize(new Dimension(90, 30));
        if (active) {
            btn.setBackground(ACCENT_RED);
            btn.setForeground(Color.WHITE);
        } else {
            btn.setBackground(BG_CARD);
            btn.setForeground(TEXT_SECONDARY);
        }
        return btn;
    }

    private void updateToggleState() {
        // Reset all
        dailyBtn.setBackground(BG_CARD);
        dailyBtn.setForeground(TEXT_SECONDARY);
        monthlyBtn.setBackground(BG_CARD);
        monthlyBtn.setForeground(TEXT_SECONDARY);
        yearlyBtn.setBackground(BG_CARD);
        yearlyBtn.setForeground(TEXT_SECONDARY);

        if (isDailyMode) {
            dailyBtn.setBackground(ACCENT_RED);
            dailyBtn.setForeground(Color.WHITE);
            monthSelector.setEnabled(true); // Allow selecting day within month?
            // For now daily mode just shows "Today" for simplicity
        } else if (isYearlyMode) {
            yearlyBtn.setBackground(ACCENT_RED);
            yearlyBtn.setForeground(Color.WHITE);
            monthSelector.setEnabled(false);
        } else {
            monthlyBtn.setBackground(ACCENT_RED);
            monthlyBtn.setForeground(Color.WHITE);
            monthSelector.setEnabled(true);
        }
    }

    private JPanel createNavPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_DARK);
        panel.setBorder(BorderFactory.createEmptyBorder(15, 0, 0, 0));

        prevBtn = createNavButton("\u25C0  Prev");
        nextBtn = createNavButton("Next  \u25B6");

        prevBtn.addActionListener(e -> navigateSlide(-1));
        nextBtn.addActionListener(e -> navigateSlide(1));

        slideCounter = new JLabel("1 / 6", SwingConstants.CENTER);
        slideCounter.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        slideCounter.setForeground(TEXT_SECONDARY);

        panel.add(prevBtn, BorderLayout.WEST);
        panel.add(slideCounter, BorderLayout.CENTER);
        panel.add(nextBtn, BorderLayout.EAST);

        return panel;
    }

    private JButton createNavButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        btn.setFocusPainted(false);
        btn.setBackground(BG_CARD);
        btn.setForeground(TEXT_PRIMARY);
        btn.setBorderPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setPreferredSize(new Dimension(110, 35));

        btn.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(ACCENT_RED);
            }

            public void mouseExited(MouseEvent e) {
                btn.setBackground(BG_CARD);
            }
        });

        return btn;
    }

    private void navigateSlide(int direction) {
        int newSlide = currentSlide + direction;
        if (newSlide < 0 || newSlide >= totalSlides)
            return;
        currentSlide = newSlide;
        slideCounter.setText((currentSlide + 1) + " / " + totalSlides);
        slideLayout.show(slideContainer, "slide" + currentSlide);

        // Start fade-in animation
        fadeAlpha = 0f;
        if (fadeTimer != null)
            fadeTimer.stop();
        fadeTimer = new Timer(20, e -> {
            fadeAlpha = Math.min(1f, fadeAlpha + 0.08f);
            slideContainer.repaint();
            if (fadeAlpha >= 1f)
                ((Timer) e.getSource()).stop();
        });
        fadeTimer.start();

        // Start counter animation for the current slide
        startCounterAnimation();

        prevBtn.setEnabled(currentSlide > 0);
        nextBtn.setEnabled(currentSlide < totalSlides - 1);
    }

    private void startCounterAnimation() {
        if (animationTimer != null)
            animationTimer.stop();
        animatedValue = 0;

        // Determine target value for current slide
        if (isDailyMode && dailyData != null) {
            switch (currentSlide) {
                case 0 -> targetValue = dailyData.totalRequests;
                case 1 -> targetValue = dailyData.topToolCount;
                case 2 -> targetValue = dailyData.sessionMinutes;
                case 3 -> targetValue = dailyData.status2xx;
                case 4 -> targetValue = dailyData.sessionsCount;
                default -> targetValue = 0;
            }
        } else if (!isYearlyMode && monthlyData != null) {
            switch (currentSlide) {
                case 0 -> targetValue = monthlyData.totalRequests;
                case 1 -> targetValue = monthlyData.topToolCount;
                case 2 -> targetValue = monthlyData.mostActiveDayCount;
                case 3 -> targetValue = monthlyData.totalMinutes;
                case 4 -> targetValue = monthlyData.activeDays;
                case 5 -> targetValue = Math.abs(monthlyData.getChangePercent());
                default -> targetValue = 0;
            }
        } else if (isYearlyMode && yearlyData != null) {
            switch (currentSlide) {
                case 0 -> targetValue = yearlyData.totalRequests;
                case 1 -> targetValue = yearlyData.topToolCount;
                case 2 -> targetValue = yearlyData.mostActiveDayCount;
                case 3 -> targetValue = yearlyData.totalMinutes;
                case 4 -> targetValue = yearlyData.activeDays;
                case 5 -> targetValue = Math.abs(yearlyData.mostActiveMonthCount);
                case 6 -> targetValue = yearlyData.longestStreak;
                default -> targetValue = 0;
            }
        }

        if (targetValue == 0)
            return;

        int step = Math.max(1, targetValue / 30);
        animationTimer = new Timer(25, e -> {
            animatedValue = Math.min(targetValue, animatedValue + step);
            slideContainer.repaint();
            if (animatedValue >= targetValue)
                ((Timer) e.getSource()).stop();
        });
        animationTimer.start();
    }

    private void loadData() {
        try {
            if (isDailyMode) {
                dailyData = database
                        .getDailyWrap(LocalDate.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE));
                totalSlides = 6;
            } else if (!isYearlyMode) {
                monthlyData = database.getMonthlyWrap(currentYear, currentMonth);
                totalSlides = 7;
            } else {
                yearlyData = database.getYearlyWrap(currentYear);
                totalSlides = 9;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        buildSlides();
        currentSlide = 0;
        slideCounter.setText("1 / " + totalSlides);
        slideLayout.show(slideContainer, "slide0");
        prevBtn.setEnabled(false);
        nextBtn.setEnabled(totalSlides > 1);

        fadeAlpha = 0f;
        if (fadeTimer != null)
            fadeTimer.stop();
        fadeTimer = new Timer(20, e -> {
            fadeAlpha = Math.min(1f, fadeAlpha + 0.08f);
            slideContainer.repaint();
            if (fadeAlpha >= 1f)
                ((Timer) e.getSource()).stop();
        });
        fadeTimer.start();
        startCounterAnimation();
    }

    private void buildSlides() {
        slideContainer.removeAll();

        if (isDailyMode && dailyData != null) {
            slideContainer.add(createStatSlide(
                    "\uD83D\uDCC8", "Today's Total",
                    String.valueOf(dailyData.totalRequests),
                    "requests processed",
                    0), "slide0");

            slideContainer.add(createStatSlide(
                    "\uD83D\uDEE0\uFE0F", "Top Tool",
                    dailyData.topTool,
                    formatNumber(dailyData.topToolCount) + " uses today",
                    1), "slide1");

            slideContainer.add(createStatSlide(
                    "\u23F1\uFE0F", "Session Time",
                    formatTime(dailyData.sessionMinutes),
                    "spent testing today",
                    2), "slide2");

            slideContainer.add(createStatSlide(
                    "\u2705", "Status 2xx",
                    String.valueOf(dailyData.status2xx),
                    "successful responses today",
                    3), "slide3");

            slideContainer.add(createStatSlide(
                    "\uD83D\uDCAE", "Sessions",
                    String.valueOf(dailyData.sessionsCount),
                    "distinct sessions today",
                    4), "slide4");

            slideContainer.add(createSummarySlide(
                    "[+] Today's Recap",
                    new String[] {
                            dailyData.totalRequests + " Total Requests",
                            dailyData.topTool + " (#1 Tool)",
                            formatTime(dailyData.sessionMinutes) + " Session Time",
                            dailyData.status2xx + " Successes (2xx)",
                            dailyData.sessionsCount + " Sessions"
                    }, 5), "slide5");

        } else if (!isYearlyMode && monthlyData != null) {
            String monthName = Month.of(currentMonth).getDisplayName(TextStyle.FULL, Locale.ENGLISH);

            slideContainer.add(createStatSlide(
                    "\uD83C\uDFAF", "Total Requests",
                    String.valueOf(monthlyData.totalRequests),
                    monthName + " " + currentYear,
                    0), "slide0");

            slideContainer.add(createStatSlide(
                    "\uD83D\uDEE0\uFE0F", "Your #1 Tool",
                    monthlyData.topTool,
                    formatNumber(monthlyData.topToolCount) + " uses",
                    1), "slide1");

            slideContainer.add(createStatSlide(
                    "\uD83D\uDD25", "Most Active Day",
                    monthlyData.mostActiveDay,
                    formatNumber(monthlyData.mostActiveDayCount) + " requests",
                    2), "slide2");

            slideContainer.add(createStatSlide(
                    "\u23F1\uFE0F", "Time Invested",
                    formatTime(monthlyData.totalMinutes),
                    "of security testing",
                    3), "slide3");

            slideContainer.add(createStatSlide(
                    "\uD83D\uDCC5", "Active Days",
                    monthlyData.activeDays + " / " + monthlyData.daysInMonth,
                    "days you showed up",
                    4), "slide4");

            int change = monthlyData.getChangePercent();
            String changeStr = (change >= 0 ? "+" : "") + change + "%";
            slideContainer.add(createStatSlide(
                    change >= 0 ? "\uD83D\uDCC8" : "\uD83D\uDCC9",
                    "vs Last Month",
                    changeStr,
                    change >= 0 ? "Keep pushing!" : "Time to grind!",
                    5), "slide5");

        } else if (isYearlyMode && yearlyData != null) {
            slideContainer.add(createStatSlide(
                    "\uD83C\uDFAF", "Total Requests",
                    String.valueOf(yearlyData.totalRequests),
                    "in " + currentYear,
                    0), "slide0");

            slideContainer.add(createStatSlide(
                    "\uD83D\uDEE0\uFE0F", "Your #1 Tool",
                    yearlyData.topTool,
                    formatNumber(yearlyData.topToolCount) + " uses",
                    1), "slide1");

            slideContainer.add(createStatSlide(
                    "\uD83D\uDD25", "Busiest Day",
                    yearlyData.mostActiveDay,
                    formatNumber(yearlyData.mostActiveDayCount) + " requests",
                    2), "slide2");

            slideContainer.add(createStatSlide(
                    "\u23F1\uFE0F", "Time Invested",
                    formatTime(yearlyData.totalMinutes),
                    "of security testing",
                    3), "slide3");

            slideContainer.add(createStatSlide(
                    "\uD83D\uDCC5", "Active Days",
                    String.valueOf(yearlyData.activeDays),
                    "days you showed up in " + currentYear,
                    4), "slide4");

            slideContainer.add(createStatSlide(
                    "\uD83D\uDCC6", "Busiest Month",
                    yearlyData.mostActiveMonth,
                    formatNumber(yearlyData.mostActiveMonthCount) + " requests",
                    5), "slide5");

            slideContainer.add(createStatSlide(
                    "\uD83C\uDFC6", "Longest Streak",
                    yearlyData.longestStreak + " days",
                    "consecutive testing days",
                    6), "slide6");

            slideContainer.add(createBarChartSlide(), "slide7");

            slideContainer.add(createSummarySlide(
                    "* " + currentYear + " in Review",
                    new String[] {
                            formatNumber(yearlyData.totalRequests) + " Total Requests",
                            yearlyData.topTool + " (#1 Tool)",
                            formatTime(yearlyData.totalMinutes) + " Total Time",
                            yearlyData.activeDays + " Active Days",
                            yearlyData.longestStreak + " Day Streak"
                    }, 8), "slide8");
        }

        slideContainer.revalidate();
        slideContainer.repaint();
    }

    /**
     * Creates a single stat "story" slide with gradient background, emoji, and
     * large number
     */
    private JPanel createStatSlide(String emoji, String title, String value, String subtitle, int slideIndex) {
        JPanel slide = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                // Gradient background
                int idx = Math.min(slideIndex, SLIDE_GRADIENTS.length - 1);
                GradientPaint gp = new GradientPaint(0, 0, SLIDE_GRADIENTS[idx][0],
                        getWidth(), getHeight(), SLIDE_GRADIENTS[idx][1]);
                g2d.setPaint(gp);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 20, 20);

                // Apply fade
                Composite original = g2d.getComposite();
                g2d.setComposite(
                        AlphaComposite.getInstance(AlphaComposite.SRC_OVER, Math.max(0f, Math.min(1f, fadeAlpha))));

                // Emoji
                g2d.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 48));
                FontMetrics efm = g2d.getFontMetrics();
                int ey = getHeight() / 2 - 80;
                g2d.setColor(Color.WHITE);
                g2d.drawString(emoji, (getWidth() - efm.stringWidth(emoji)) / 2, ey);

                // Title
                g2d.setFont(new Font("Segoe UI", Font.PLAIN, 16));
                g2d.setColor(TEXT_SECONDARY);
                FontMetrics tfm = g2d.getFontMetrics();
                g2d.drawString(title, (getWidth() - tfm.stringWidth(title)) / 2, ey + 40);

                // Animated value
                String displayValue;
                // Only animate numeric values
                boolean isNumeric = false;
                try {
                    Integer.parseInt(value);
                    isNumeric = true;
                } catch (Exception ex) {
                    /* not numeric */ }

                if (isNumeric && currentSlide == slideIndex) {
                    displayValue = formatNumber(animatedValue);
                } else {
                    displayValue = value;
                }

                g2d.setFont(new Font("Segoe UI", Font.BOLD, 52));
                g2d.setColor(ACCENT_RED);
                FontMetrics vfm = g2d.getFontMetrics();
                g2d.drawString(displayValue, (getWidth() - vfm.stringWidth(displayValue)) / 2, ey + 105);

                // Subtitle
                g2d.setFont(new Font("Segoe UI", Font.ITALIC, 14));
                g2d.setColor(TEXT_SECONDARY);
                FontMetrics sfm = g2d.getFontMetrics();
                g2d.drawString(subtitle, (getWidth() - sfm.stringWidth(subtitle)) / 2, ey + 140);

                g2d.setComposite(original);
            }
        };

        slide.setPreferredSize(new Dimension(600, 350));
        slide.setBackground(BG_DARK);

        // Hover effect
        slide.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                slide.setBorder(BorderFactory.createLineBorder(ACCENT_RED, 2, true));
            }

            @Override
            public void mouseExited(MouseEvent e) {
                slide.setBorder(null);
            }
        });

        return slide;
    }

    /**
     * Creates a bar chart slide showing month-by-month activity (yearly only)
     */
    private JPanel createBarChartSlide() {
        JPanel slide = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                // Gradient background
                GradientPaint gp = new GradientPaint(0, 0, SLIDE_GRADIENTS[7][0],
                        getWidth(), getHeight(), SLIDE_GRADIENTS[7][1]);
                g2d.setPaint(gp);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 20, 20);

                if (yearlyData == null)
                    return;

                // Apply fade
                Composite original = g2d.getComposite();
                g2d.setComposite(
                        AlphaComposite.getInstance(AlphaComposite.SRC_OVER, Math.max(0f, Math.min(1f, fadeAlpha))));

                // Title
                g2d.setFont(new Font("Segoe UI", Font.BOLD, 18));
                g2d.setColor(ACCENT_RED);
                String chartTitle = "\uD83D\uDCCA Month-by-Month Activity — " + currentYear;
                FontMetrics tfm = g2d.getFontMetrics();
                g2d.drawString(chartTitle, (getWidth() - tfm.stringWidth(chartTitle)) / 2, 35);

                // Draw bars
                int maxVal = 1;
                for (int v : yearlyData.monthlyTotals) {
                    maxVal = Math.max(maxVal, v);
                }

                int barAreaTop = 60;
                int barAreaBottom = getHeight() - 40;
                int barAreaHeight = barAreaBottom - barAreaTop;
                int totalBarsWidth = getWidth() - 80;
                int barWidth = totalBarsWidth / 12 - 6;
                int startX = 40;

                String[] monthLabels = { "J", "F", "M", "A", "M", "J", "J", "A", "S", "O", "N", "D" };

                for (int i = 0; i < 12; i++) {
                    int val = yearlyData.monthlyTotals[i];
                    int barHeight = (int) ((double) val / maxVal * barAreaHeight);
                    if (val > 0 && barHeight < 5)
                        barHeight = 5;

                    int x = startX + i * (barWidth + 6);
                    int y = barAreaBottom - barHeight;

                    // Bar gradient
                    if (val > 0) {
                        GradientPaint barGp = new GradientPaint(x, y, ACCENT_RED,
                                x, barAreaBottom, ACCENT_CRIMSON);
                        g2d.setPaint(barGp);
                        g2d.fillRoundRect(x, y, barWidth, barHeight, 4, 4);
                    } else {
                        g2d.setColor(new Color(50, 50, 50));
                        g2d.fillRoundRect(x, barAreaBottom - 3, barWidth, 3, 2, 2);
                    }

                    // Value on top
                    if (val > 0) {
                        g2d.setFont(new Font("Segoe UI", Font.BOLD, 10));
                        g2d.setColor(ACCENT_ORANGE);
                        String valStr = val >= 1000 ? (val / 1000) + "k" : String.valueOf(val);
                        FontMetrics fm = g2d.getFontMetrics();
                        g2d.drawString(valStr, x + (barWidth - fm.stringWidth(valStr)) / 2, y - 5);
                    }

                    // Month label
                    g2d.setFont(new Font("Segoe UI", Font.PLAIN, 11));
                    g2d.setColor(TEXT_SECONDARY);
                    FontMetrics lm = g2d.getFontMetrics();
                    g2d.drawString(monthLabels[i], x + (barWidth - lm.stringWidth(monthLabels[i])) / 2,
                            barAreaBottom + 18);
                }

                g2d.setComposite(original);
            }
        };

        slide.setPreferredSize(new Dimension(600, 350));
        slide.setBackground(BG_DARK);
        return slide;
    }

    // ==================== Utility ====================

    private String formatNumber(int n) {
        if (n >= 1_000_000)
            return String.format("%.1fM", n / 1_000_000.0);
        if (n >= 1_000)
            return String.format("%,d", n);
        return String.valueOf(n);
    }

    private String formatTime(int minutes) {
        if (minutes < 60)
            return minutes + "m";
        int hours = minutes / 60;
        int mins = minutes % 60;
        if (hours >= 24) {
            int days = hours / 24;
            hours = hours % 24;
            return days + "d " + hours + "h";
        }
        return hours + "h " + mins + "m";
    }

    /**
     * Creates a summary slide with multiple key metrics
     */
    private JPanel createSummarySlide(String title, String[] metrics, int slideIndex) {
        JPanel slide = new JPanel(new BorderLayout(0, 15)) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                // Gradient background (last one)
                GradientPaint gp = new GradientPaint(0, 0, new Color(40, 40, 40),
                        getWidth(), getHeight(), new Color(20, 20, 20));
                g2d.setPaint(gp);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 20, 20);

                // Apply fade
                Composite original = g2d.getComposite();
                g2d.setComposite(
                        AlphaComposite.getInstance(AlphaComposite.SRC_OVER, Math.max(0f, Math.min(1f, fadeAlpha))));

                g2d.setFont(new Font("Segoe UI", Font.BOLD, 28));
                g2d.setColor(Color.WHITE);
                FontMetrics fm = g2d.getFontMetrics();
                g2d.drawString(title, (getWidth() - fm.stringWidth(title)) / 2, 60);

                g2d.setComposite(original);
            }
        };

        JPanel metricsPanel = new JPanel();
        metricsPanel.setLayout(new BoxLayout(metricsPanel, BoxLayout.Y_AXIS));
        metricsPanel.setOpaque(false);
        metricsPanel.setBorder(BorderFactory.createEmptyBorder(80, 40, 40, 40));

        for (String metric : metrics) {
            JLabel label = new JLabel("• " + metric);
            label.setFont(new Font("Segoe UI", Font.PLAIN, 18));
            label.setForeground(TEXT_PRIMARY);
            label.setAlignmentX(Component.CENTER_ALIGNMENT);
            metricsPanel.add(label);
            metricsPanel.add(Box.createVerticalStrut(10));
        }

        slide.add(metricsPanel, BorderLayout.CENTER);
        slide.setPreferredSize(new Dimension(600, 350));
        slide.setBackground(BG_DARK);
        return slide;
    }
}
