package com.project.securevault;

import java.sql.*;

public class DatabaseManager {
    // Ensure the SQLite JDBC driver is in your library path
    private static final String URL = "jdbc:sqlite:secureapp.db";

    public void setup() {
        // Table now includes 'salt'
        String sql = "CREATE TABLE IF NOT EXISTS users ("
                + "id INTEGER PRIMARY KEY,"
                + "username TEXT UNIQUE,"
                + "password_hash TEXT,"
                + "salt TEXT);";

        try (Connection conn = DriverManager.getConnection(URL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            System.err.println("DB Setup Error: " + e.getMessage());
        }
    }

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
            return false; // Username likely taken
        }
    }

    // Returns [Hash, Salt] or null if not found
    public String[] getUserCredentials(String username) {
        String sql = "SELECT password_hash, salt FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return new String[]{rs.getString("password_hash"), rs.getString("salt")};
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
}
