package com.project.securevault;

import com.formdev.flatlaf.FlatDarkLaf;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/**
 * INTEGRATION FILE (MEMBER 4)
 * This file connects the UI, Hashing, Crypto, and Logging.
 * UPDATED: Implements Brute Force Mitigation (Throttling + Account Lockout).
 */

public class SecureFileApp extends JFrame {
    private CardLayout cardLayout;
    private JPanel mainPanel;

    // Services
    private AuthService authService = new AuthService();
    private CryptoService cryptoService = new CryptoService();
    private DatabaseManager dbManager = new DatabaseManager();

    // Security State (Brute Force Mitigation)
    private Map<String, Integer> failedAttempts = new HashMap<>();
    private Map<String, Long> lockoutExpiry = new HashMap<>();
    private static final int MAX_ATTEMPTS = 10;
    private static final long LOCKOUT_DURATION = 10 * 60 * 1000; // 10 minutes

    // Session State
    private String currentUser;
    private String currentPassword;
    private String currentSalt;

    // UI Fields
    private JTextField loginUsernameField, regUsernameField;
    private JPasswordField loginPasswordField, regPasswordField, regConfirmPasswordField;
    private JLabel statusLabel;
    private File selectedFile;

    // Table Components
    private DefaultTableModel tableModel;
    private JTable activityTable;

    public SecureFileApp() {
        dbManager.setup();
        setTitle("Aegis Vault - Secure File Manager");
        setSize(600, 650);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        try {
            ImageIcon icon = new ImageIcon("src/resources/icon.png");
            setIconImage(icon.getImage());
        } catch (Exception e) {
            System.err.println("Icon not found, using default Java icon.");
        }


        cardLayout = new CardLayout();
        mainPanel = new JPanel(cardLayout);

        mainPanel.add(createLoginPanel(), "LOGIN");
        mainPanel.add(createRegisterPanel(), "REGISTER");
        mainPanel.add(createDashboardPanel(), "DASHBOARD");

        add(mainPanel);
        cardLayout.show(mainPanel, "LOGIN");
    }

    private void clearSession() {
        currentUser = null;
        currentPassword = null;
        currentSalt = null;
        selectedFile = null;

        if (statusLabel != null) {
            statusLabel.setText("Status: No file selected");
        }

        if (loginUsernameField != null) loginUsernameField.setText("");
        if (loginPasswordField != null) loginPasswordField.setText("");
        if (regUsernameField != null) regUsernameField.setText("");
        if (regPasswordField != null) regPasswordField.setText("");
        if (regConfirmPasswordField != null) regConfirmPasswordField.setText("");
    }

    private void handleLogin() {
        String user = loginUsernameField.getText().trim();
        String pass = new String(loginPasswordField.getPassword());

        if (user.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a username.");
            return;
        }

        // 1. SECURITY CHECK: Is the user currently locked out?
        long currentTime = System.currentTimeMillis();
        if (lockoutExpiry.containsKey(user) && currentTime < lockoutExpiry.get(user)) {
            long remainingMillis = lockoutExpiry.get(user) - currentTime;
            long remainingMinutes = (remainingMillis / 1000) / 60;
            if (remainingMinutes == 0) remainingMinutes = 1; // Round up to 1

            JOptionPane.showMessageDialog(this,
                    "Too many failed attempts. Account is locked. Please try again in " + remainingMinutes + " minute(s).");
            return;
        }

        try {
            String[] creds = dbManager.getUserCredentials(user);
            if (creds != null && authService.verify(pass, creds[0], creds[1])) {
                // SUCCESS: Reset security tracking for this user
                failedAttempts.remove(user);
                lockoutExpiry.remove(user);

                this.currentUser = user;
                this.currentPassword = pass;
                this.currentSalt = creds[1];

                AuditLogger.log(user, "LOGIN_SUCCESS");

                // Load activity history on successful login
                refreshActivityTable();
                cardLayout.show(mainPanel, "DASHBOARD");
            } else {
                // FAILURE: Increment attempts and handle security penalties
                AuditLogger.log(user, "LOGIN_FAILED");

                int attempts = failedAttempts.getOrDefault(user, 0) + 1;
                failedAttempts.put(user, attempts);

                if (attempts >= MAX_ATTEMPTS) {
                    // Trigger 10-minute lockout
                    lockoutExpiry.put(user, currentTime + LOCKOUT_DURATION);
                    JOptionPane.showMessageDialog(this, "Maximum attempts reached. Account locked for 10 minutes.");
                } else {
                    // Login Throttling: Enforce a 2-second delay to slow down automated scripts
                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }

                    int remaining = MAX_ATTEMPTS - attempts;
                    JOptionPane.showMessageDialog(this, "Invalid credentials. " + remaining + " attempts remaining.");
                }

                loginPasswordField.setText("");
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error during login process.");
        }
    }

    private void handleRegistration() {
        String user = regUsernameField.getText().trim();
        String pass = new String(regPasswordField.getPassword());
        String confirm = new String(regConfirmPasswordField.getPassword());

        if (user.isEmpty() || pass.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Fields cannot be empty.");
            return;
        }
        if (!pass.equals(confirm)) {
            JOptionPane.showMessageDialog(this, "Passwords do not match.");
            return;
        }

        try {
            String salt = authService.generateSalt();
            String hash = authService.hashPassword(pass, salt);
            if (dbManager.registerUser(user, hash, salt)) {
                AuditLogger.log(user, "REGISTER_SUCCESS");
                JOptionPane.showMessageDialog(this, "Account created! Please login.");
                cardLayout.show(mainPanel, "LOGIN");
            } else {
                JOptionPane.showMessageDialog(this, "Username already exists.");
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Registration Error: " + e.getMessage());
        }
    }

    private void handleLogout() {
        AuditLogger.log(currentUser, "LOGOUT");
        clearSession();
        cardLayout.show(mainPanel, "LOGIN");
    }

    private void handleEncryption() {
        if (selectedFile == null) return;
        try {
            cryptoService.encrypt(selectedFile, currentPassword, currentSalt);
            if (selectedFile.delete()) {
                statusLabel.setText("Status: Encrypted & Original Deleted!");
                AuditLogger.log(currentUser, "FILE_ENCRYPTED_AND_DELETED: " + selectedFile.getName());
            } else {
                statusLabel.setText("Status: Encrypted (Could not delete original)");
            }
            selectedFile = null;
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Encryption failed: " + e.getMessage());
        }
    }

    private void handleDecryption() {
        if (selectedFile == null) return;
        try {
            cryptoService.decrypt(selectedFile, currentPassword, currentSalt);
            statusLabel.setText("Status: File Decrypted Successfully!");
            AuditLogger.log(currentUser, "FILE_DECRYPTED: " + selectedFile.getName());
            selectedFile = null;
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Decryption failed: Wrong password or file tampered.");
        }
    }

    //  UI Layout Methods

    private JPanel createLoginPanel() {
        // 1. Create a container panel with a modern background color
        JPanel container = new JPanel(new GridBagLayout());
        container.setBorder(new EmptyBorder(40, 40, 40, 40)); // Adds "breathable" space

        // 2. Create the login card (a sub-panel to give a "card" look)
        JPanel card = new JPanel(new GridBagLayout());
        card.putClientProperty("FlatLaf.style", "arc: 20"); // Rounds the corners of the panel
        card.setBorder(new EmptyBorder(20, 20, 20, 20));

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(10, 10, 10, 10);
        g.fill = GridBagConstraints.HORIZONTAL;

        // Title Label
        JLabel title = new JLabel("Welcome Back");
        title.setFont(new Font("SansSerif", Font.BOLD, 22));
        g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
        g.anchor = GridBagConstraints.CENTER;
        card.add(title, g);

        // Username Field with Placeholder
        loginUsernameField = new JTextField(15);
        loginUsernameField.putClientProperty("JTextField.placeholderText", "Enter your username");
        loginUsernameField.putClientProperty("JTextField.showClearButton", true);
        g.gridy = 1; g.gridwidth = 2;
        card.add(new JLabel("Username"), g);
        g.gridy = 2;
        card.add(loginUsernameField, g);

        // Password Field with Placeholder
        loginPasswordField = new JPasswordField(15);
        loginPasswordField.putClientProperty("JTextField.placeholderText", "Enter your password");
        loginPasswordField.putClientProperty("NoSelectedTextColor", true); // Modern selection look
        g.gridy = 3;
        card.add(new JLabel("Password"), g);
        g.gridy = 4;
        card.add(loginPasswordField, g);

        // Login Button with custom style
        JButton btn = new JButton("Login");
        btn.putClientProperty("JButton.buttonType", "roundRect"); // Rounded edges
        btn.setBackground(new Color(52, 152, 219)); // Modern Blue
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.addActionListener(e -> handleLogin()); // Connects to existing logic

        g.gridy = 5; g.insets = new Insets(20, 10, 5, 10);
        card.add(btn, g);

        // Register Button (Styled as a link or secondary button)
        JButton reg = new JButton("Don't have an account? Register");
        reg.setBorderPainted(false);
        reg.setContentAreaFilled(false);
        reg.setCursor(new Cursor(Cursor.HAND_CURSOR));
        reg.setForeground(new Color(150, 150, 150));
        reg.addActionListener(e -> cardLayout.show(mainPanel, "REGISTER"));

        g.gridy = 6; g.insets = new Insets(0, 10, 10, 10);
        card.add(reg, g);

        container.add(card);
        return container;
    }

    private JPanel createRegisterPanel() {
        JPanel container = new JPanel(new GridBagLayout());
        container.setBorder(new EmptyBorder(40, 40, 40, 40));

        JPanel card = new JPanel(new GridBagLayout());
        card.putClientProperty("FlatLaf.style", "arc: 20");
        card.setBorder(new EmptyBorder(20, 20, 20, 20));

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(8, 10, 8, 10);
        g.fill = GridBagConstraints.HORIZONTAL;

        // Title
        JLabel title = new JLabel("Create Account");
        title.setFont(new Font("SansSerif", Font.BOLD, 22));
        g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
        g.anchor = GridBagConstraints.CENTER;
        card.add(title, g);

        // Fields with placeholders
        regUsernameField = new JTextField(15);
        regUsernameField.putClientProperty("JTextField.placeholderText", "Choose a username");

        regPasswordField = new JPasswordField(15);
        regPasswordField.putClientProperty("JTextField.placeholderText", "Create password");

        regConfirmPasswordField = new JPasswordField(15);
        regConfirmPasswordField.putClientProperty("JTextField.placeholderText", "Confirm password");

        g.gridwidth = 2;
        g.gridy = 1; card.add(new JLabel("Username"), g);
        g.gridy = 2; card.add(regUsernameField, g);
        g.gridy = 3; card.add(new JLabel("Password"), g);
        g.gridy = 4; card.add(regPasswordField, g);
        g.gridy = 5; card.add(new JLabel("Confirm Password"), g);
        g.gridy = 6; card.add(regConfirmPasswordField, g);

        // Register Button
        JButton btn = new JButton("Register");
        btn.putClientProperty("JButton.buttonType", "roundRect");
        btn.setBackground(new Color(46, 204, 113)); // Modern Green
        btn.setForeground(Color.WHITE);
        btn.addActionListener(e -> handleRegistration());
        g.gridy = 7; g.insets = new Insets(20, 10, 5, 10);
        card.add(btn, g);

        // Back Button
        JButton back = new JButton("Already have an account? Login");
        back.setBorderPainted(false);
        back.setContentAreaFilled(false);
        back.setCursor(new Cursor(Cursor.HAND_CURSOR));
        back.addActionListener(e -> cardLayout.show(mainPanel, "LOGIN"));
        g.gridy = 8; g.insets = new Insets(0, 10, 10, 10);
        card.add(back, g);

        container.add(card);
        return container;
    }

    private JPanel createDashboardPanel() {
        JPanel container = new JPanel(new BorderLayout(20, 20));
        container.setBorder(new EmptyBorder(30, 30, 30, 30));

        //
        JPanel header = new JPanel(new BorderLayout());
        JLabel welcomeLabel = new JLabel("Aegis Vault Dashboard");
        welcomeLabel.setFont(new Font("SansSerif", Font.BOLD, 24));
        header.add(welcomeLabel, BorderLayout.WEST);

        JPanel navActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));

        JButton aboutBtn = new JButton("About");
        aboutBtn.putClientProperty("JButton.buttonType", "roundRect");
        aboutBtn.addActionListener(e -> showAboutDialog()); // Triggers the method above

        JButton logout = new JButton("Logout");
        logout.putClientProperty("JButton.buttonType", "roundRect");
        logout.addActionListener(e -> handleLogout());

        navActions.add(aboutBtn);
        navActions.add(logout);
        header.add(navActions, BorderLayout.EAST);

        JPanel card = new JPanel(new GridBagLayout());
        card.putClientProperty("FlatLaf.style", "arc: 20");
        card.setBorder(new EmptyBorder(20, 20, 20, 20));

        statusLabel = new JLabel("Status: No file selected", SwingConstants.CENTER);
        statusLabel.setFont(new Font("SansSerif", Font.ITALIC, 14));
        statusLabel.setForeground(new Color(150, 150, 150));

        JButton sel = new JButton("Select File");
        JButton enc = new JButton("Encrypt File");
        JButton dec = new JButton("Decrypt File");

        // Styling Buttons
        sel.putClientProperty("JButton.buttonType", "roundRect");
        enc.setBackground(new Color(231, 76, 60)); // Red for Encrypt (Action)
        enc.setForeground(Color.WHITE);
        dec.setBackground(new Color(52, 152, 219)); // Blue for Decrypt
        dec.setForeground(Color.WHITE);

        sel.addActionListener(e -> {
            JFileChooser j = new JFileChooser();
            if(j.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                selectedFile = j.getSelectedFile();
                statusLabel.setText("Selected: " + selectedFile.getName());
                statusLabel.setForeground(new Color(52, 152, 219));
            }
        });

        // Updated action listeners to refresh table
        enc.addActionListener(e -> { handleEncryption(); refreshActivityTable(); });
        dec.addActionListener(e -> { handleDecryption(); refreshActivityTable(); });

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(10, 10, 10, 10);
        g.fill = GridBagConstraints.HORIZONTAL;
        g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
        card.add(statusLabel, g);
        g.gridy = 1; card.add(sel, g);
        g.gridy = 2; g.gridwidth = 1; card.add(enc, g);
        g.gridx = 1; card.add(dec, g);

        // Bottom Section: Recent Activity Table
        String[] columns = {"Timestamp", "Action"};
        tableModel = new DefaultTableModel(columns, 0);
        activityTable = new JTable(tableModel);
        activityTable.setEnabled(false); // Make read-only
        JScrollPane scrollPane = new JScrollPane(activityTable);
        scrollPane.setPreferredSize(new Dimension(400, 150));
        scrollPane.setBorder(BorderFactory.createTitledBorder("Recent Activity"));

        JPanel mainCenter = new JPanel(new BorderLayout(0, 20));
        mainCenter.add(card, BorderLayout.NORTH);
        mainCenter.add(scrollPane, BorderLayout.CENTER);

        container.add(header, BorderLayout.NORTH);
        container.add(mainCenter, BorderLayout.CENTER);

        return container;
    }

    private void refreshActivityTable() {
        tableModel.setRowCount(0); // Clear existing rows
        File logFile = new File("audit_log.txt");
        if (!logFile.exists()) return;

        try (Scanner scanner = new Scanner(logFile)) {
            List<String> lines = new ArrayList<>();
            while (scanner.hasNextLine()) {
                lines.add(scanner.nextLine());
            }
            // Show only the last 5 actions
            int start = Math.max(0, lines.size() - 5);
            for (int i = lines.size() - 1; i >= start; i--) {
                String[] parts = lines.get(i).split(" \\| ");
                if (parts.length >= 3) {
                    // Display Timestamp and Action (skipping Username for privacy)
                    tableModel.addRow(new Object[]{parts[0].substring(0, 19), parts[2].replace("Action: ", "")});
                }
            }
        } catch (Exception e) {
            // Ignore log file errors
        }
    }

    private void showAboutDialog() {
        String message = "<html><body style='width: 250px;'>" +
                "<h2>Aegis Vault v1.0</h2>" +
                "<p>A secure file management system designed for maximum privacy.</p><br>" +
                "<b>Security Protocols:</b>" +
                "<ul>" +
                "<li><b>Encryption:</b> AES-256 (CBC Mode)</li>" +
                "<li><b>Key Derivation:</b> PBKDF2 with HMAC-SHA256</li>" +
                "<li><b>Password Hashing:</b> SHA-256 with 16-byte Salt</li>" +
                "</ul></body></html>";

        JOptionPane.showMessageDialog(this, message, "About Aegis Vault", JOptionPane.INFORMATION_MESSAGE);
    }

    //main method
    public static void main(String[] args) {
        try {
            // This line tells the app to use the modern FlatLaf theme
            com.formdev.flatlaf.FlatDarkLaf.setup();

            // These optional lines make components like text fields and buttons rounded
            javax.swing.UIManager.put("Button.arc", 15);
            javax.swing.UIManager.put("Component.arc", 15);
            javax.swing.UIManager.put("TextComponent.arc", 15);

        } catch (Exception ex) {
            System.err.println("Failed to initialize FlatLaf: " + ex.getMessage());
        }

        // Launch the application as usual
        javax.swing.SwingUtilities.invokeLater(() -> new SecureFileApp().setVisible(true));
    }
}