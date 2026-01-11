package com.project.securevault;

import java.security.MessageDigest;
import java.util.Base64;

public class AuthService {

    /* --- SALT GENERATION --- */
    public String generateSalt() {
        return Base64.getEncoder().encodeToString(new java.security.SecureRandom().generateSeed(16));
    }

    /* --- PASSWORD HASHING --- */
    public String hashPassword(String password, String salt) throws Exception {
        if (password == null || salt == null) return "EMPTY";
        String combined = password + salt;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(combined.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hash);
    }

    /* --- AUTHENTICATION VERIFICATION --- */
    public boolean verify(String inputPass, String storedHash, String storedSalt) throws Exception {
        if (inputPass == null || storedHash == null || storedSalt == null) return false;
        String newHash = hashPassword(inputPass, storedSalt);
        return newHash.equals(storedHash);
    }
}