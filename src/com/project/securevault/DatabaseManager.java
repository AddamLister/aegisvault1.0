package com.project.securevault;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages the SQLite database for Aegis Vault, including schema
 * initialisation and user credential CRUD operations.
 * <p>
 * Uses JDBC 4.0+ automatic driver discovery — no manual
 * {@code Class.forName()} call is required.
 * </p>
 */
public class DatabaseManager {

    private static final Logger LOGGER = Logger.getLogger(DatabaseManager.class.getName());

    /* --- DATABASE CONFIGURATION --- */
    private static final String URL = "jdbc:sqlite:secureapp.db";

    /* --- DATABASE SETUP --- */

    /**
     * Creates the {@code users} table if it does not already exist.
     * All credential columns enforce {@code NOT NULL}.
     */
    public void setup() {
        String sql = "CREATE TABLE IF NOT EXISTS users ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                + "username TEXT UNIQUE NOT NULL, "
                + "password_hash TEXT NOT NULL, "
                + "salt TEXT NOT NULL"
                + ");";
        try (Connection conn = DriverManager.getConnection(URL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "DB Setup Error", e);
        }
    }

    /* --- USER REGISTRATION --- */

    /**
     * Inserts a new user record.
     *
     * @param username the unique username
     * @param hash     the Base64-encoded password hash
     * @param salt     the Base64-encoded salt
     * @return {@code true} if the insert succeeded, {@code false} if the
     *         username already exists or another SQL error occurred
     */
    public boolean registerUser(String username, String hash, String salt) {
        String sql = "INSERT INTO users(username, password_hash, salt) VALUES(?,?,?)";
        try (Connection conn = DriverManager.getConnection(URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, hash);
            pstmt.setString(3, salt);
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Registration failed for user '" + username + "'", e);
            return false;
        }
    }

    /* --- CREDENTIAL RETRIEVAL --- */

    /**
     * Retrieves the stored hash and salt for the given username.
     *
     * @param username the username to look up
     * @return a two-element array {@code [password_hash, salt]}, or
     *         {@code null} if the user does not exist
     */
    public String[] getUserCredentials(String username) {
        String sql = "SELECT password_hash, salt FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new String[]{
                            rs.getString("password_hash"),
                            rs.getString("salt")
                    };
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Credential lookup failed for user '" + username + "'", e);
        }
        return null;
    }
}