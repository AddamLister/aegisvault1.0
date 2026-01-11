package com.project.securevault;

/* --- IMPORTS ---
 * Includes libraries for the FlatLaf theme, Java Swing UI components,
 * file handling, and utility collections like Map and List.
 */
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

public class SecureFileApp extends JFrame {
    private CardLayout cardLayout;
    private JPanel mainPanel;

    /* --- CORE SERVICES ---
     * Instances of service classes that handle authentication logic,
     * cryptographic operations (AES), and database interactions.
     */
    private AuthService authService = new AuthService();
    private CryptoService cryptoService = new CryptoService();
    private DatabaseManager dbManager = new DatabaseManager();

    /* --- SECURITY STATE ---
     * Manages brute-force protection by tracking failed login attempts
     * and calculating lockout durations for specific usernames.
     */
    private Map<String, Integer> failedAttempts = new HashMap<>();
    private Map<String, Long> lockoutExpiry = new HashMap<>();
    private static final int MAX_ATTEMPTS = 10;
    private static final long LOCKOUT_DURATION = 10 * 60 * 1000; // 10 minutes

    /* --- SESSION & UI FIELDS ---
     * Stores data for the currently logged-in user and references
     * to UI components like text fields and tables.
     */
    private String currentUser;
    private String currentPassword;
    private String currentSalt;

    private JTextField loginUsernameField, regUsernameField;
    private JPasswordField loginPasswordField, regPasswordField, regConfirmPasswordField;
    private JButton registerButton;
    private JLabel statusLabel;
    private File selectedFile;

    private DefaultTableModel tableModel;
    private JTable activityTable;

    /* --- CONSTRUCTOR ---
     * Sets up the main window (JFrame), initializes the database,
     * and assembles the CardLayout containing Login, Register, and Dashboard.
     */
    public SecureFileApp() {
        dbManager.setup();
        setTitle("Aegis Vault - Secure File Manager");
        setSize(600, 700);
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

    /* --- AUTHENTICATION LOGIC ---
     * Methods to handle login verification, user registration,
     * session clearing, and logout procedures.
     */
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
        String rawUser = loginUsernameField.getText().trim();
        String pass = new String(loginPasswordField.getPassword());

        if (rawUser.isEmpty() || pass.isEmpty()) return;

        String userKey = rawUser.toLowerCase();

        long currentTime = System.currentTimeMillis();
        if (lockoutExpiry.containsKey(userKey) && currentTime < lockoutExpiry.get(userKey)) {
            long remainingMillis = lockoutExpiry.get(userKey) - currentTime;
            long remainingMinutes = Math.max(1, (remainingMillis / 1000) / 60);
            JOptionPane.showMessageDialog(this, "Account locked. Try again in " + remainingMinutes + " minute(s).");
            return;
        }

        try {
            String[] creds = dbManager.getUserCredentials(rawUser);

            if (creds == null) {
                JOptionPane.showMessageDialog(this, "User not found.");
                return;
            }

            boolean isMatch = authService.verify(pass, creds[0], creds[1]);

            if (isMatch) {
                failedAttempts.remove(userKey);
                lockoutExpiry.remove(userKey);

                this.currentUser = rawUser;
                this.currentPassword = pass;
                this.currentSalt = creds[1];

                AuditLogger.log(rawUser, "LOGIN_SUCCESS");
                refreshActivityTable();
                cardLayout.show(mainPanel, "DASHBOARD");
            } else {
                int attempts = failedAttempts.getOrDefault(userKey, 0) + 1;
                failedAttempts.put(userKey, attempts);
                AuditLogger.log(rawUser, "LOGIN_FAILED");

                if (attempts >= MAX_ATTEMPTS) {
                    lockoutExpiry.put(userKey, currentTime + LOCKOUT_DURATION);
                    JOptionPane.showMessageDialog(this, "Maximum attempts reached. Account locked.");
                } else {
                    int remaining = MAX_ATTEMPTS - attempts;
                    JOptionPane.showMessageDialog(this, "Invalid Password! " + remaining + " attempts left.");
                }
                loginPasswordField.setText("");
            }
        } catch (Exception e) {
            e.printStackTrace();
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

        // --- SECURITY CHECKS ---
        if (pass.length() <= 12) {
            JOptionPane.showMessageDialog(this, "Password must be more than 12 characters long.");
            return;
        }

        String complexityRegex = "^(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>]).*$";
        if (!pass.matches(complexityRegex)) {
            JOptionPane.showMessageDialog(this, "Password must contain at least one number and one special character.");
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

    /* --- FILE OPERATIONS ---
     * Interacts with CryptoService to perform encryption and decryption.
     */
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

    /* --- UI LAYOUT METHODS ---
     * Methods using GridBagLayout and BorderLayout to build the app's interface.
     */
    private JPanel createLoginPanel() {
        JPanel container = new JPanel(new GridBagLayout());
        container.setBorder(new EmptyBorder(40, 40, 40, 40));

        JPanel card = new JPanel(new GridBagLayout());
        card.putClientProperty("FlatLaf.style", "arc: 20");
        card.setBorder(new EmptyBorder(20, 20, 20, 20));

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(10, 10, 10, 10);
        g.fill = GridBagConstraints.HORIZONTAL;

        JLabel title = new JLabel("Welcome Back");
        title.setFont(new Font("SansSerif", Font.BOLD, 22));
        g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
        g.anchor = GridBagConstraints.CENTER;
        card.add(title, g);

        loginUsernameField = new JTextField(15);
        loginUsernameField.putClientProperty("JTextField.placeholderText", "Username");
        g.gridy = 1; card.add(new JLabel("Username"), g);
        g.gridy = 2; card.add(loginUsernameField, g);

        loginPasswordField = new JPasswordField(15);
        loginPasswordField.putClientProperty("JTextField.placeholderText", "Password");
        g.gridy = 3; card.add(new JLabel("Password"), g);
        g.gridy = 4; card.add(loginPasswordField, g);

        // --- PASSWORD VISIBILITY TOGGLE ---
        JCheckBox showPass = new JCheckBox("Show Password");
        showPass.addActionListener(e -> {
            if (showPass.isSelected()) {
                loginPasswordField.setEchoChar((char) 0);
            } else {
                loginPasswordField.setEchoChar('•');
            }
        });
        g.gridy = 5; card.add(showPass, g);

        JButton btn = new JButton("Login");
        btn.setBackground(new Color(52, 152, 219));
        btn.setForeground(Color.WHITE);
        btn.addActionListener(e -> handleLogin());
        g.gridy = 6; card.add(btn, g);

        registerButton = new JButton("Register");
        registerButton.addActionListener(e -> cardLayout.show(mainPanel, "REGISTER"));
        g.gridy = 7; card.add(registerButton, g);

        container.add(card);
        return container;
    }

    /* --- REGISTRATION PANEL WITH DYNAMIC REQUIREMENTS --- */
    private JPanel createRegisterPanel() {
        JPanel container = new JPanel(new GridBagLayout());
        container.setBorder(new EmptyBorder(40, 40, 40, 40));

        JPanel card = new JPanel(new GridBagLayout());
        card.putClientProperty("FlatLaf.style", "arc: 20");
        card.setBorder(new EmptyBorder(20, 20, 20, 20));

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(8, 10, 8, 10);
        g.fill = GridBagConstraints.HORIZONTAL;

        JLabel title = new JLabel("Create Account");
        title.setFont(new Font("SansSerif", Font.BOLD, 22));
        g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
        card.add(title, g);

        // --- REQUIREMENT TEXT BOX ---
        // This text stays visible so the user knows exactly what to type.
        JLabel reqText = new JLabel("<html><body style='width: 250px; color: #E74C3C;'>" +
                "<b>Password Requirements:</b><br>" +
                "• More than 12 characters<br>" +
                "• At least one number (0-9)<br>" +
                "• At least one special character (!@#$%^&*)</body></html>");
        g.gridy = 1; card.add(reqText, g);

        regUsernameField = new JTextField(15);
        regPasswordField = new JPasswordField(15);
        regConfirmPasswordField = new JPasswordField(15);

        // --- REAL-TIME CHECKER ---
        // This listener changes the requirement text color to green when satisfied.
        regPasswordField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) { check(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { check(); }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { check(); }

            private void check() {
                String p = new String(regPasswordField.getPassword());
                String regex = "^(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>]).*$";
                if (p.length() > 12 && p.matches(regex)) {
                    reqText.setText("<html><body style='width: 250px; color: #2ECC71;'>" +
                            "<b>Password Requirements:</b> (Requirement Met!)<br>" +
                            "• More than 12 characters<br>" +
                            "• At least one number (0-9)<br>" +
                            "• At least one special character (!@#$%^&*)</body></html>");
                } else {
                    reqText.setText("<html><body style='width: 250px; color: #E74C3C;'>" +
                            "<b>Password Requirements:</b><br>" +
                            "• More than 12 characters<br>" +
                            "• At least one number (0-9)<br>" +
                            "• At least one special character (!@#$%^&*)</body></html>");
                }
            }
        });

        g.gridy = 2; card.add(new JLabel("Username"), g);
        g.gridy = 3; card.add(regUsernameField, g);
        g.gridy = 4; card.add(new JLabel("Password"), g);
        g.gridy = 5; card.add(regPasswordField, g);
        g.gridy = 6; card.add(new JLabel("Confirm Password"), g);
        g.gridy = 7; card.add(regConfirmPasswordField, g);

        // Visibility Toggle
        JCheckBox showPass = new JCheckBox("Show Passwords");
        showPass.addActionListener(e -> {
            char echo = showPass.isSelected() ? (char) 0 : '•';
            regPasswordField.setEchoChar(echo);
            regConfirmPasswordField.setEchoChar(echo);
        });
        g.gridy = 8; card.add(showPass, g);

        JButton btn = new JButton("Register");
        btn.setBackground(new Color(46, 204, 113));
        btn.setForeground(Color.WHITE);
        btn.addActionListener(e -> handleRegistration());
        g.gridy = 9; card.add(btn, g);

        JButton back = new JButton("Back to Login");
        back.addActionListener(e -> cardLayout.show(mainPanel, "LOGIN"));
        g.gridy = 10; card.add(back, g);

        container.add(card);
        return container;
    }

    /* --- DASHBOARD PANEL ---
     * Constructs the main user interface for logged-in users,
     * including the header with the About and Logout buttons.
     */
    private JPanel createDashboardPanel() {
        JPanel container = new JPanel(new BorderLayout(20, 20));
        container.setBorder(new EmptyBorder(30, 30, 30, 30));

        // Header Section
        JPanel header = new JPanel(new BorderLayout());
        JLabel welcomeLabel = new JLabel("Aegis Vault Dashboard");
        welcomeLabel.setFont(new Font("SansSerif", Font.BOLD, 24));
        header.add(welcomeLabel, BorderLayout.WEST);

        // Header Buttons (About & Logout)
        JPanel navActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));

        JButton aboutBtn = new JButton("About");
        aboutBtn.putClientProperty("JButton.buttonType", "roundRect");
        aboutBtn.addActionListener(e -> showAboutDialog()); // Triggers the About Dialog

        JButton logout = new JButton("Logout");
        logout.putClientProperty("JButton.buttonType", "roundRect");
        logout.addActionListener(e -> handleLogout());

        navActions.add(aboutBtn);
        navActions.add(logout);
        header.add(navActions, BorderLayout.EAST);

        // Main Center Area (File Controls)
        JPanel mainCenter = new JPanel(new BorderLayout(0, 20));
        JPanel card = new JPanel(new GridBagLayout());
        card.putClientProperty("FlatLaf.style", "arc: 20");
        card.setBorder(new EmptyBorder(20, 20, 20, 20));

        statusLabel = new JLabel("Status: No file selected", SwingConstants.CENTER);
        statusLabel.setFont(new Font("SansSerif", Font.ITALIC, 14));
        statusLabel.setForeground(new Color(150, 150, 150));

        JButton sel = new JButton("Select File");
        JButton enc = new JButton("Encrypt File");
        JButton dec = new JButton("Decrypt File");

        sel.putClientProperty("JButton.buttonType", "roundRect");

        // Red for Encryption
        enc.putClientProperty("JButton.buttonType", "roundRect");
        enc.setBackground(new Color(231, 76, 60));
        enc.setForeground(Color.WHITE);

        // Blue for Decryption
        dec.putClientProperty("JButton.buttonType", "roundRect");
        dec.setBackground(new Color(52, 152, 219));
        dec.setForeground(Color.WHITE);

        sel.addActionListener(e -> {
            JFileChooser j = new JFileChooser();
            if(j.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                selectedFile = j.getSelectedFile();
                statusLabel.setText("Selected: " + selectedFile.getName());
                statusLabel.setForeground(new Color(52, 152, 219));
            }
        });

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

        // Activity Table
        String[] columns = {"Timestamp", "Action"};
        tableModel = new DefaultTableModel(columns, 0);
        activityTable = new JTable(tableModel);
        activityTable.setEnabled(false);
        JScrollPane scrollPane = new JScrollPane(activityTable);
        scrollPane.setPreferredSize(new Dimension(400, 150));
        scrollPane.setBorder(BorderFactory.createTitledBorder("Recent Activity"));

        mainCenter.add(card, BorderLayout.NORTH);
        mainCenter.add(scrollPane, BorderLayout.CENTER);

        container.add(header, BorderLayout.NORTH);
        container.add(mainCenter, BorderLayout.CENTER);

        return container;
    }

    /* --- UTILITY METHODS --- */
    private void refreshActivityTable() {
        tableModel.setRowCount(0);
        File logFile = new File("audit_log.txt");
        if (!logFile.exists()) return;
        try (Scanner scanner = new Scanner(logFile)) {
            List<String> lines = new ArrayList<>();
            while (scanner.hasNextLine()) lines.add(scanner.nextLine());
            int start = Math.max(0, lines.size() - 5);
            for (int i = lines.size() - 1; i >= start; i--) {
                String[] parts = lines.get(i).split(" \\| ");
                if (parts.length >= 3) {
                    tableModel.addRow(new Object[]{parts[0].substring(0, 19), parts[2].replace("Action: ", "")});
                }
            }
        } catch (Exception e) {}
    }

    /* --- ABOUT DIALOG ---
     * Displays a styled information dialog showing system version
     * and the underlying security protocols.
     */
    private void showAboutDialog() {
        String message = "<html><body style='width: 300px; padding: 10px;'>" +
                "<h2 style='color: #3498db;'>Aegis Vault v1.0</h2>" +
                "<p>A secure file management system designed for maximum privacy.</p><br>" +
                "<b>Security Protocols:</b>" +
                "<ul style='margin-left: 20px;'>" +
                "<li><b>Encryption:</b> AES-256 (CBC Mode)</li>" +
                "<li><b>Key Derivation:</b> PBKDF2 with HMAC-SHA256</li>" +
                "<li><b>Password Hashing:</b> SHA-256 with 16-byte Salt</li>" +
                "</ul></body></html>";

        JOptionPane.showMessageDialog(this, message, "About Aegis Vault", JOptionPane.INFORMATION_MESSAGE);
    }

    /* --- MAIN ENTRY POINT --- */
    public static void main(String[] args) {
        try {
            com.formdev.flatlaf.FlatDarkLaf.setup();
        } catch (Exception ex) {}
        javax.swing.SwingUtilities.invokeLater(() -> new SecureFileApp().setVisible(true));
    }
}