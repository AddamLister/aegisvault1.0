package com.project.securevault;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontPosture;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Main JavaFX UI for Aegis Vault — a secure file encryption/decryption
 * dashboard with login, registration, drag-and-drop file selection, and
 * a real-time audit activity log.
 * <p>
 * Uses an undecorated {@link Stage} with a custom title bar that supports
 * mouse dragging, and applies {@code style.css} for a dark-themed UI.
 * All cryptographic operations run asynchronously via {@link Task} to
 * keep the UI responsive.
 * </p>
 */
public class SecureFileApp extends Application {

    private static final Logger LOGGER = Logger.getLogger(SecureFileApp.class.getName());

    /* ------------------------------------------------------------------ */
    /*  SERVICES                                                           */
    /* ------------------------------------------------------------------ */

    private final AuthService authService = new AuthService();
    private final CryptoService cryptoService = new CryptoService();
    private final DatabaseManager dbManager = new DatabaseManager();

    /* ------------------------------------------------------------------ */
    /*  BRUTE-FORCE PROTECTION                                             */
    /* ------------------------------------------------------------------ */

    private final Map<String, Integer> failedAttempts = new HashMap<>();
    private final Map<String, Long> lockoutExpiry = new HashMap<>();
    private static final int MAX_ATTEMPTS = 10;
    private static final long LOCKOUT_DURATION = 10L * 60 * 1000; // 10 minutes

    /* ------------------------------------------------------------------ */
    /*  SESSION STATE                                                      */
    /* ------------------------------------------------------------------ */

    private String currentUser;
    private String currentPassword;
    private String currentSalt;

    /* ------------------------------------------------------------------ */
    /*  UI COMPONENTS                                                      */
    /* ------------------------------------------------------------------ */

    private BorderPane mainRoot;
    private Stage primaryStage;

    // Auth fields
    private TextField loginUsernameField;
    private PasswordField loginPasswordField;
    private TextField loginPasswordVisibleField;

    private TextField regUsernameField;
    private PasswordField regPasswordField;
    private TextField regPasswordVisibleField;
    private PasswordField regConfirmPasswordField;
    private TextField regConfirmPasswordVisibleField;

    // Dashboard controls
    private Label statusLabel;
    private File selectedFile;
    private Button selBtn, encBtn, decBtn;
    private ProgressBar progressBar;

    // Title bar dragging offsets
    private double xOffset;
    private double yOffset;

    // Activity log table
    private TableView<ActivityLog> activityTable;
    private final ObservableList<ActivityLog> activityData = FXCollections.observableArrayList();

    // View panels
    private VBox loginPanel, registerPanel, dashboardPanel;

    /* ================================================================== */
    /*  APPLICATION LIFECYCLE                                              */
    /* ================================================================== */

    @Override
    public void start(Stage primaryStage) {
        dbManager.setup();
        this.primaryStage = primaryStage;
        primaryStage.setTitle("Aegis Vault - Secure File Manager");

        try {
            primaryStage.getIcons().add(new Image(
                    getClass().getResource("/resources/icon.png").toExternalForm()));
        } catch (Exception e) {
            LOGGER.fine("Icon not found, using default Java icon.");
        }

        primaryStage.initStyle(StageStyle.UNDECORATED);
        mainRoot = new BorderPane();
        mainRoot.setTop(createTitleBar());

        loginPanel = createLoginPanel();
        registerPanel = createRegisterPanel();
        dashboardPanel = createDashboardPanel();

        showView(loginPanel);

        Scene scene = new Scene(mainRoot, 600, 700);
        try {
            String css = getClass().getResource("/resources/style.css").toExternalForm();
            scene.getStylesheets().add(css);
        } catch (Exception e) {
            LOGGER.warning("Could not load style.css");
        }

        primaryStage.setScene(scene);

        // Ensure clean session teardown on window close
        primaryStage.setOnCloseRequest(event -> {
            clearSession();
            Platform.exit();
        });

        primaryStage.show();
    }

    /* ================================================================== */
    /*  TITLE BAR                                                          */
    /* ================================================================== */

    private HBox createTitleBar() {
        HBox titleBar = new HBox();
        titleBar.setAlignment(Pos.CENTER_RIGHT);
        titleBar.setPadding(new Insets(5, 10, 5, 10));
        titleBar.setStyle("-fx-background-color: #1e1e1e;");

        ImageView iconView;
        try {
            iconView = new ImageView(new Image(
                    getClass().getResource("/resources/icon.png").toExternalForm()));
            iconView.setFitHeight(18);
            iconView.setFitWidth(18);
        } catch (Exception e) {
            iconView = new ImageView();
        }

        Label title = new Label("Aegis Vault");
        title.setStyle("-fx-text-fill: #a9b7c6; -fx-font-weight: bold;");

        HBox titleBox = new HBox(8);
        titleBox.setAlignment(Pos.CENTER_LEFT);
        titleBox.getChildren().addAll(iconView, title);
        HBox.setHgrow(titleBox, Priority.ALWAYS);

        Button minimizeBtn = new Button("-");
        minimizeBtn.setStyle("-fx-background-color: transparent; -fx-text-fill: #a9b7c6; -fx-font-weight: bold;");
        minimizeBtn.setOnMouseEntered(e ->
                minimizeBtn.setStyle("-fx-background-color: #3498db; -fx-text-fill: white; -fx-font-weight: bold;"));
        minimizeBtn.setOnMouseExited(e ->
                minimizeBtn.setStyle("-fx-background-color: transparent; -fx-text-fill: #a9b7c6; -fx-font-weight: bold;"));
        minimizeBtn.setOnAction(e -> primaryStage.setIconified(true));

        Button closeBtn = new Button("X");
        closeBtn.setStyle("-fx-background-color: transparent; -fx-text-fill: #a9b7c6; -fx-font-weight: bold;");
        closeBtn.setOnMouseEntered(e ->
                closeBtn.setStyle("-fx-background-color: #e74c3c; -fx-text-fill: white; -fx-font-weight: bold;"));
        closeBtn.setOnMouseExited(e ->
                closeBtn.setStyle("-fx-background-color: transparent; -fx-text-fill: #a9b7c6; -fx-font-weight: bold;"));
        closeBtn.setOnAction(e -> Platform.exit());

        titleBar.getChildren().addAll(titleBox, minimizeBtn, closeBtn);

        // Dragging support for undecorated stage
        titleBar.setOnMousePressed(event -> {
            xOffset = event.getSceneX();
            yOffset = event.getSceneY();
        });
        titleBar.setOnMouseDragged(event -> {
            primaryStage.setX(event.getScreenX() - xOffset);
            primaryStage.setY(event.getScreenY() - yOffset);
        });

        return titleBar;
    }

    /* ================================================================== */
    /*  VIEW MANAGEMENT                                                    */
    /* ================================================================== */

    private void showView(Region view) {
        mainRoot.setCenter(view);
    }

    /* ================================================================== */
    /*  SESSION MANAGEMENT                                                 */
    /* ================================================================== */

    private void clearSession() {
        currentUser = null;
        currentPassword = null;
        currentSalt = null;
        selectedFile = null;

        if (statusLabel != null) {
            statusLabel.setText("Status: No file selected");
            statusLabel.setTextFill(Color.web("#969696"));
        }

        if (loginUsernameField != null) loginUsernameField.clear();
        if (loginPasswordField != null) loginPasswordField.clear();
        if (loginPasswordVisibleField != null) loginPasswordVisibleField.clear();

        if (regUsernameField != null) regUsernameField.clear();
        if (regPasswordField != null) regPasswordField.clear();
        if (regConfirmPasswordField != null) regConfirmPasswordField.clear();
        if (regPasswordVisibleField != null) regPasswordVisibleField.clear();
        if (regConfirmPasswordVisibleField != null) regConfirmPasswordVisibleField.clear();
    }

    /* ================================================================== */
    /*  ALERTS                                                             */
    /* ================================================================== */

    private void showAlert(Alert.AlertType type, String title, String content) {
        Alert alert = new Alert(type);
        alert.initStyle(StageStyle.UNDECORATED);
        alert.setGraphic(null); // Clear default graphic to avoid duplication

        DialogPane dialogPane = alert.getDialogPane();

        // Custom Title Bar for Alert Dialog
        HBox alertTitleBar = new HBox();
        alertTitleBar.setAlignment(Pos.CENTER_RIGHT);
        alertTitleBar.setPadding(new Insets(5, 10, 5, 10));
        alertTitleBar.setStyle("-fx-background-color: #1e1e1e;");

        // Subtle indicator circle corresponding to alert severity
        javafx.scene.shape.Circle indicator = new javafx.scene.shape.Circle(5);
        switch (type) {
            case ERROR -> indicator.setFill(Color.web("#e74c3c"));
            case WARNING -> indicator.setFill(Color.web("#f1c40f"));
            case INFORMATION -> indicator.setFill(Color.web("#3498db"));
            default -> indicator.setFill(Color.web("#2ecc71"));
        }

        Label titleLabel = new Label(title);
        titleLabel.setStyle("-fx-text-fill: #a9b7c6; -fx-font-weight: bold;");

        HBox titleBox = new HBox(8);
        titleBox.setAlignment(Pos.CENTER_LEFT);
        titleBox.getChildren().addAll(indicator, titleLabel);
        HBox.setHgrow(titleBox, Priority.ALWAYS);

        // Clickable close button
        Button closeBtn = new Button("X");
        closeBtn.setStyle("-fx-background-color: transparent; -fx-text-fill: #a9b7c6; -fx-font-weight: bold; -fx-cursor: hand;");
        closeBtn.setOnMouseEntered(e ->
                closeBtn.setStyle("-fx-background-color: #e74c3c; -fx-text-fill: white; -fx-font-weight: bold;"));
        closeBtn.setOnMouseExited(e ->
                closeBtn.setStyle("-fx-background-color: transparent; -fx-text-fill: #a9b7c6; -fx-font-weight: bold;"));
        closeBtn.setOnAction(e -> alert.close());

        alertTitleBar.getChildren().addAll(titleBox, closeBtn);

        // Dragging support for undecorated alert dialog
        final double[] dragOffset = new double[2];
        alertTitleBar.setOnMousePressed(event -> {
            dragOffset[0] = event.getSceneX();
            dragOffset[1] = event.getSceneY();
        });
        alertTitleBar.setOnMouseDragged(event -> {
            alert.setX(event.getScreenX() - dragOffset[0]);
            alert.setY(event.getScreenY() - dragOffset[1]);
        });

        dialogPane.setHeader(alertTitleBar);
        dialogPane.setContentText(content);

        try {
            String css = getClass().getResource("/resources/style.css").toExternalForm();
            dialogPane.getStylesheets().add(css);
            dialogPane.getStyleClass().add("root");
            dialogPane.setStyle("-fx-border-color: #1e1e1e; -fx-border-width: 2;");
        } catch (Exception ignored) { }

        alert.showAndWait();
    }

    /* ================================================================== */
    /*  LOGIN HANDLER                                                      */
    /* ================================================================== */

    private void handleLogin() {
        String rawUser = loginUsernameField.getText().trim();
        String pass = loginPasswordField.isVisible()
                ? loginPasswordField.getText()
                : loginPasswordVisibleField.getText();

        if (rawUser.isEmpty() || pass.isEmpty()) return;

        String userKey = rawUser.toLowerCase();
        long currentTime = System.currentTimeMillis();

        if (lockoutExpiry.containsKey(userKey) && currentTime < lockoutExpiry.get(userKey)) {
            long remainingMinutes = Math.max(1,
                    (lockoutExpiry.get(userKey) - currentTime) / 60_000);
            showAlert(Alert.AlertType.WARNING, "Account Locked",
                    "Account locked. Try again in " + remainingMinutes + " minute(s).");
            return;
        }

        try {
            String[] creds = dbManager.getUserCredentials(rawUser);

            if (creds == null) {
                showAlert(Alert.AlertType.ERROR, "Login Failed", "User not found.");
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
                showView(dashboardPanel);
            } else {
                int attempts = failedAttempts.getOrDefault(userKey, 0) + 1;
                failedAttempts.put(userKey, attempts);
                AuditLogger.log(rawUser, "LOGIN_FAILED");

                if (attempts >= MAX_ATTEMPTS) {
                    lockoutExpiry.put(userKey, currentTime + LOCKOUT_DURATION);
                    showAlert(Alert.AlertType.ERROR, "Account Locked",
                            "Maximum attempts reached. Account locked.");
                } else {
                    int remaining = MAX_ATTEMPTS - attempts;
                    showAlert(Alert.AlertType.WARNING, "Login Failed",
                            "Invalid Password! " + remaining + " attempts left.");
                }
                loginPasswordField.clear();
                loginPasswordVisibleField.clear();
            }
        } catch (NoSuchAlgorithmException e) {
            LOGGER.log(Level.WARNING, "Login error", e);
        }
    }

    /* ================================================================== */
    /*  REGISTRATION HANDLER                                               */
    /* ================================================================== */

    private void handleRegistration() {
        String user = regUsernameField.getText().trim();
        String pass = regPasswordField.isVisible()
                ? regPasswordField.getText()
                : regPasswordVisibleField.getText();
        String confirm = regConfirmPasswordField.isVisible()
                ? regConfirmPasswordField.getText()
                : regConfirmPasswordVisibleField.getText();

        if (user.isEmpty() || pass.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "Validation Error",
                    "Fields cannot be empty.");
            return;
        }

        if (pass.length() <= 12) {
            showAlert(Alert.AlertType.WARNING, "Validation Error",
                    "Password must be more than 12 characters long.");
            return;
        }

        String complexityRegex = "^(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>]).*$";
        if (!pass.matches(complexityRegex)) {
            showAlert(Alert.AlertType.WARNING, "Validation Error",
                    "Password must contain at least one number and one special character.");
            return;
        }

        if (!pass.equals(confirm)) {
            showAlert(Alert.AlertType.WARNING, "Validation Error",
                    "Passwords do not match.");
            return;
        }

        try {
            String salt = authService.generateSalt();
            String hash = authService.hashPassword(pass, salt);
            if (dbManager.registerUser(user, hash, salt)) {
                AuditLogger.log(user, "REGISTER_SUCCESS");
                showAlert(Alert.AlertType.INFORMATION, "Success",
                        "Account created! Please login.");
                showView(loginPanel);
            } else {
                showAlert(Alert.AlertType.ERROR, "Registration Error",
                        "Username already exists.");
            }
        } catch (NoSuchAlgorithmException e) {
            showAlert(Alert.AlertType.ERROR, "Registration Error", e.getMessage());
        }
    }

    /* ================================================================== */
    /*  LOGOUT HANDLER                                                     */
    /* ================================================================== */

    private void handleLogout() {
        AuditLogger.log(currentUser, "LOGOUT");
        clearSession();
        showView(loginPanel);
    }

    /* ================================================================== */
    /*  ENCRYPTION / DECRYPTION TASK WORKERS                               */
    /* ================================================================== */

    /**
     * Disables action buttons and shows the progress bar during
     * cryptographic operations.
     */
    private void lockUI() {
        selBtn.setDisable(true);
        encBtn.setDisable(true);
        decBtn.setDisable(true);
        progressBar.setVisible(true);
    }

    /**
     * Re-enables action buttons and hides the progress bar after
     * cryptographic operations complete.
     */
    private void unlockUI() {
        progressBar.setVisible(false);
        selBtn.setDisable(false);
        encBtn.setDisable(false);
        decBtn.setDisable(false);
    }

    private void handleEncryption() {
        if (selectedFile == null) return;

        lockUI();
        statusLabel.setText("Status: Encrypting...");
        statusLabel.setTextFill(Color.web("#a9b7c6"));

        Task<Void> task = new Task<>() {
            @Override
            protected Void call() throws Exception {
                cryptoService.encrypt(selectedFile, currentPassword, currentSalt);
                return null;
            }
        };

        task.setOnSucceeded(e -> {
            unlockUI();
            try {
                if (cryptoService.secureDelete(selectedFile)) {
                    statusLabel.setText("Status: Encrypted & Original Wiped!");
                    AuditLogger.log(currentUser,
                            "FILE_ENCRYPTED_AND_WIPED: " + selectedFile.getName());
                } else {
                    statusLabel.setText("Status: Encrypted (Could not delete original)");
                }
                selectedFile = null;
            } catch (Exception ex) {
                showAlert(Alert.AlertType.ERROR, "Encryption Failed", ex.getMessage());
            }
            refreshActivityTable();
        });

        task.setOnFailed(e -> {
            unlockUI();
            showAlert(Alert.AlertType.ERROR, "Encryption Failed",
                    task.getException().getMessage());
            refreshActivityTable();
        });

        new Thread(task).start();
    }

    private void handleDecryption() {
        if (selectedFile == null) return;

        lockUI();
        statusLabel.setText("Status: Decrypting...");
        statusLabel.setTextFill(Color.web("#a9b7c6"));

        Task<Void> task = new Task<>() {
            @Override
            protected Void call() throws Exception {
                cryptoService.decrypt(selectedFile, currentPassword, currentSalt);
                return null;
            }
        };

        task.setOnSucceeded(e -> {
            unlockUI();
            statusLabel.setText("Status: File Decrypted Successfully!");
            statusLabel.setTextFill(Color.web("#2ecc71"));
            AuditLogger.log(currentUser, "FILE_DECRYPTED: " + selectedFile.getName());
            selectedFile = null;
            refreshActivityTable();
        });

        task.setOnFailed(e -> {
            unlockUI();
            Throwable cause = task.getException();
            if (cause != null && (cause instanceof SecurityException
                    || (cause.getCause() != null
                    && cause.getCause() instanceof SecurityException))) {
                String msg = cause instanceof SecurityException
                        ? cause.getMessage()
                        : cause.getCause().getMessage();
                showAlert(Alert.AlertType.ERROR, "INTEGRITY COMPROMISED", msg);
                statusLabel.setText(
                        "Security Alert: Threat intercepted. Process execution terminated.");
                statusLabel.setTextFill(Color.web("#e74c3c"));
                AuditLogger.log(currentUser,
                        "TAMPER_ATTEMPT_DETECTED: " + selectedFile.getName());
            } else {
                String errMsg = cause != null ? cause.getMessage() : "Unknown error";
                showAlert(Alert.AlertType.ERROR, "Operational Error",
                        "Decryption failed: " + errMsg);
            }
            refreshActivityTable();
        });

        new Thread(task).start();
    }

    /* ================================================================== */
    /*  PASSWORD VISIBILITY BINDING                                        */
    /* ================================================================== */

    private void bindPasswordFields(PasswordField pf, TextField tf) {
        tf.textProperty().bindBidirectional(pf.textProperty());
    }

    /* ================================================================== */
    /*  LOGIN PANEL                                                        */
    /* ================================================================== */

    private VBox createLoginPanel() {
        VBox container = new VBox();
        container.setAlignment(Pos.CENTER);
        container.setPadding(new Insets(40));

        VBox card = new VBox(15);
        card.getStyleClass().addAll("card", "login-card");
        card.setAlignment(Pos.CENTER);
        card.setMaxWidth(400);

        Label title = new Label("Welcome Back");
        title.setFont(Font.font("SansSerif", FontWeight.BOLD, 22));

        VBox userBox = new VBox(5);
        Label userLbl = new Label("Username");
        loginUsernameField = new TextField();
        loginUsernameField.setPromptText("Username");
        userBox.getChildren().addAll(userLbl, loginUsernameField);

        VBox passBox = new VBox(5);
        Label passLbl = new Label("Password");

        StackPane passStack = new StackPane();
        loginPasswordField = new PasswordField();
        loginPasswordField.setPromptText("Password");
        loginPasswordVisibleField = new TextField();
        loginPasswordVisibleField.setPromptText("Password");
        loginPasswordVisibleField.setVisible(false);
        bindPasswordFields(loginPasswordField, loginPasswordVisibleField);
        passStack.getChildren().addAll(loginPasswordField, loginPasswordVisibleField);

        passBox.getChildren().addAll(passLbl, passStack);

        CheckBox showPass = new CheckBox("Show Password");
        showPass.setOnAction(e -> {
            loginPasswordField.setVisible(!showPass.isSelected());
            loginPasswordVisibleField.setVisible(showPass.isSelected());
        });

        Button loginBtn = new Button("Login");
        loginBtn.getStyleClass().add("button-primary");
        loginBtn.setMaxWidth(Double.MAX_VALUE);
        loginBtn.setOnAction(e -> handleLogin());
        loginBtn.setDefaultButton(true);

        Button regBtn = new Button("Register");
        regBtn.getStyleClass().add("button");
        regBtn.setMaxWidth(Double.MAX_VALUE);
        regBtn.setOnAction(e -> showView(registerPanel));

        card.getChildren().addAll(title, userBox, passBox, showPass, loginBtn, regBtn);
        container.getChildren().add(card);

        return container;
    }

    /* ================================================================== */
    /*  REGISTER PANEL                                                     */
    /* ================================================================== */

    private VBox createRegisterPanel() {
        VBox container = new VBox();
        container.setAlignment(Pos.CENTER);
        container.setPadding(new Insets(40));

        VBox card = new VBox(10);
        card.getStyleClass().addAll("card", "register-card");
        card.setAlignment(Pos.CENTER_LEFT);
        card.setMaxWidth(400);

        Label title = new Label("Create Account");
        title.setFont(Font.font("SansSerif", FontWeight.BOLD, 22));
        title.setAlignment(Pos.CENTER);
        title.setMaxWidth(Double.MAX_VALUE);

        Text reqText = new Text("""
                Password Requirements:
                \u2022 More than 12 characters
                \u2022 At least one number (0-9)
                \u2022 At least one special character (!@#$%^&*)""");
        reqText.setFill(Color.web("#e74c3c"));

        VBox userBox = new VBox(5);
        regUsernameField = new TextField();
        userBox.getChildren().addAll(new Label("Username"), regUsernameField);

        VBox passBox = new VBox(5);
        regPasswordField = new PasswordField();
        regPasswordVisibleField = new TextField();
        regPasswordVisibleField.setVisible(false);
        bindPasswordFields(regPasswordField, regPasswordVisibleField);
        StackPane passStack = new StackPane(regPasswordField, regPasswordVisibleField);
        passBox.getChildren().addAll(new Label("Password"), passStack);

        VBox confirmBox = new VBox(5);
        regConfirmPasswordField = new PasswordField();
        regConfirmPasswordVisibleField = new TextField();
        regConfirmPasswordVisibleField.setVisible(false);
        bindPasswordFields(regConfirmPasswordField, regConfirmPasswordVisibleField);
        StackPane confirmStack = new StackPane(
                regConfirmPasswordField, regConfirmPasswordVisibleField);
        confirmBox.getChildren().addAll(new Label("Confirm Password"), confirmStack);

        regPasswordField.textProperty().addListener((obs, oldV, newV) -> {
            String regex = "^(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>]).*$";
            if (newV.length() > 12 && newV.matches(regex)) {
                reqText.setText("""
                        Password Requirements: (Requirement Met!)
                        \u2022 More than 12 characters
                        \u2022 At least one number (0-9)
                        \u2022 At least one special character (!@#$%^&*)""");
                reqText.setFill(Color.web("#2ecc71"));
            } else {
                reqText.setText("""
                        Password Requirements:
                        \u2022 More than 12 characters
                        \u2022 At least one number (0-9)
                        \u2022 At least one special character (!@#$%^&*)""");
                reqText.setFill(Color.web("#e74c3c"));
            }
        });

        CheckBox showPass = new CheckBox("Show Passwords");
        showPass.setOnAction(e -> {
            boolean show = showPass.isSelected();
            regPasswordField.setVisible(!show);
            regPasswordVisibleField.setVisible(show);
            regConfirmPasswordField.setVisible(!show);
            regConfirmPasswordVisibleField.setVisible(show);
        });

        Button btn = new Button("Register");
        btn.getStyleClass().add("button-success");
        btn.setMaxWidth(Double.MAX_VALUE);
        btn.setOnAction(e -> handleRegistration());

        Button back = new Button("Back to Login");
        back.getStyleClass().add("button");
        back.setMaxWidth(Double.MAX_VALUE);
        back.setOnAction(e -> showView(loginPanel));

        card.getChildren().addAll(
                title, reqText, userBox, passBox, confirmBox, showPass, btn, back);
        container.getChildren().add(card);

        return container;
    }

    /* ================================================================== */
    /*  DASHBOARD PANEL                                                    */
    /* ================================================================== */

    @SuppressWarnings("unchecked")
    private VBox createDashboardPanel() {
        VBox container = new VBox(20);
        container.setPadding(new Insets(30));

        // --- Header ---
        HBox header = new HBox();
        header.setAlignment(Pos.CENTER_LEFT);

        Label welcomeLabel = new Label("Aegis Vault Dashboard");
        welcomeLabel.setFont(Font.font("SansSerif", FontWeight.BOLD, 24));

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button aboutBtn = new Button("About");
        aboutBtn.getStyleClass().add("button");
        aboutBtn.setOnAction(e -> showAboutDialog());

        Button logoutBtn = new Button("Logout");
        logoutBtn.getStyleClass().add("button");
        logoutBtn.setOnAction(e -> handleLogout());

        HBox actions = new HBox(10, aboutBtn, logoutBtn);
        header.getChildren().addAll(welcomeLabel, spacer, actions);

        // --- Operations Card ---
        VBox card = new VBox(15);
        card.getStyleClass().add("card");
        card.setAlignment(Pos.CENTER);

        statusLabel = new Label("Status: No file selected");
        statusLabel.setFont(Font.font("SansSerif", FontPosture.ITALIC, 14));
        statusLabel.setTextFill(Color.web("#969696"));

        progressBar = new ProgressBar();
        progressBar.setMaxWidth(Double.MAX_VALUE);
        progressBar.setVisible(false);

        selBtn = new Button("Select File or Drag and Drop Here");
        selBtn.getStyleClass().add("drop-zone");
        selBtn.setMaxWidth(Double.MAX_VALUE);
        selBtn.setPrefHeight(60);

        HBox actionBtns = new HBox(10);
        actionBtns.setAlignment(Pos.CENTER);

        encBtn = new Button("Encrypt File");
        encBtn.getStyleClass().add("button-danger");
        encBtn.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(encBtn, Priority.ALWAYS);

        decBtn = new Button("Decrypt File");
        decBtn.getStyleClass().add("button-primary");
        decBtn.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(decBtn, Priority.ALWAYS);

        actionBtns.getChildren().addAll(encBtn, decBtn);

        selBtn.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Select File");
            File file = fileChooser.showOpenDialog(primaryStage);
            if (file != null) {
                selectedFile = file;
                statusLabel.setText("Selected: " + selectedFile.getName());
                statusLabel.setTextFill(Color.web("#3498db"));
            }
        });

        encBtn.setOnAction(e -> handleEncryption());
        decBtn.setOnAction(e -> handleDecryption());

        // Drag-and-drop support
        card.setOnDragOver(event -> {
            if (event.getDragboard().hasFiles()) {
                event.acceptTransferModes(TransferMode.COPY);
            }
            event.consume();
        });

        card.setOnDragDropped(event -> {
            var db = event.getDragboard();
            boolean success = false;
            if (db.hasFiles() && !db.getFiles().isEmpty()) {
                success = true;
                selectedFile = db.getFiles().get(0);
                statusLabel.setText("Selected: " + selectedFile.getName());
                statusLabel.setTextFill(Color.web("#3498db"));
            }
            event.setDropCompleted(success);
            event.consume();
        });

        card.getChildren().addAll(statusLabel, progressBar, selBtn, actionBtns);

        // --- Activity Table ---
        VBox tableBox = new VBox(5);
        Label tableTitle = new Label("Recent Activity");
        tableTitle.setStyle("-fx-font-weight: bold;");

        activityTable = new TableView<>();
        activityTable.setItems(activityData);

        TableColumn<ActivityLog, String> timeCol = new TableColumn<>("Timestamp");
        timeCol.setCellValueFactory(
                cellData -> new SimpleStringProperty(cellData.getValue().timestamp()));
        timeCol.setPrefWidth(180);

        TableColumn<ActivityLog, String> actionCol = new TableColumn<>("Action");
        actionCol.setCellValueFactory(
                cellData -> new SimpleStringProperty(cellData.getValue().action()));
        actionCol.setPrefWidth(350);

        activityTable.getColumns().addAll(timeCol, actionCol);
        VBox.setVgrow(activityTable, Priority.ALWAYS);

        tableBox.getChildren().addAll(tableTitle, activityTable);
        VBox.setVgrow(tableBox, Priority.ALWAYS);

        container.getChildren().addAll(header, card, tableBox);
        return container;
    }

    /* ================================================================== */
    /*  ACTIVITY LOG                                                       */
    /* ================================================================== */

    private void refreshActivityTable() {
        Platform.runLater(() -> {
            activityData.clear();
            File logFile = new File("audit_log.txt");
            if (!logFile.exists()) return;

            try {
                List<String> lines = Files.readAllLines(logFile.toPath(), StandardCharsets.UTF_8);
                int start = Math.max(0, lines.size() - 5);
                for (int i = lines.size() - 1; i >= start; i--) {
                    String[] parts = lines.get(i).split(" \\| ");
                    if (parts.length >= 3) {
                        String timestamp = parts[0].length() >= 19
                                ? parts[0].substring(0, 19) : parts[0];
                        String action = parts[2].replace("Action: ", "");
                        activityData.add(new ActivityLog(timestamp, action));
                    }
                }
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to read audit log", e);
            }
        });
    }

    /* ================================================================== */
    /*  ABOUT DIALOG                                                       */
    /* ================================================================== */

    private void showAboutDialog() {
        showAlert(Alert.AlertType.INFORMATION, "About Aegis Vault",
                """
                        Aegis Vault v1.0 (Pro Version)
                        
                        A secure file management system guaranteeing Confidentiality, Integrity, and Authenticity.
                        
                        Security Protocols:
                        - Confidentiality: AES-256 (CBC Mode)
                        - Integrity & Authenticity: Encrypt-then-MAC using HMAC-SHA256
                        - Key Derivation: PBKDF2 (512-bit split keys)
                        - Secure Shredding: 3-pass DoD-inspired overwrite""");
    }

    /* ================================================================== */
    /*  DATA MODEL                                                         */
    /* ================================================================== */

    /**
     * Immutable record representing a single row in the activity table.
     */
    public record ActivityLog(String timestamp, String action) { }
}