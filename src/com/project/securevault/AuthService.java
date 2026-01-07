package com.project.securevault;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class AuthService {

    // Generates a random 16-byte salt
    public String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // Hashes password + salt using SHA-256
    public String hashPassword(String password, String salt) throws Exception {
        String combined = password + salt;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(combined.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hash);
    }

    // Verifies if input matches stored data
    public boolean verify(String inputPass, String storedHash, String storedSalt) throws Exception {
        String newHash = hashPassword(inputPass, storedSalt);
        return newHash.equals(storedHash);
    }
}
