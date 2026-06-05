package com.project.securevault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Authentication service providing SHA-256-based password hashing with
 * per-user random salts.
 * <p>
 * <b>Security properties:</b>
 * <ul>
 *   <li>16-byte cryptographically random salt via {@link SecureRandom}</li>
 *   <li>SHA-256 digest of {@code (password + salt)}</li>
 *   <li>Constant-time hash comparison via
 *       {@link MessageDigest#isEqual(byte[], byte[])} to eliminate
 *       timing side-channels</li>
 * </ul>
 * </p>
 */
public class AuthService {

    private static final int SALT_LENGTH_BYTES = 16;

    /* --- SALT GENERATION --- */

    /**
     * Generates a cryptographically random 16-byte salt, returned as a
     * Base64-encoded string suitable for database storage.
     *
     * @return Base64-encoded salt
     */
    public String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /* --- PASSWORD HASHING --- */

    /**
     * Produces a Base64-encoded SHA-256 hash of {@code password + salt}.
     *
     * @param password the plaintext password (must not be null)
     * @param salt     the Base64-encoded salt     (must not be null)
     * @return Base64-encoded hash
     * @throws IllegalArgumentException    if either argument is null
     * @throws NoSuchAlgorithmException if SHA-256 is unavailable (should never happen)
     */
    public String hashPassword(String password, String salt) throws NoSuchAlgorithmException {
        if (password == null || salt == null) {
            throw new IllegalArgumentException("Password and salt must not be null.");
        }
        byte[] combined = (password + salt).getBytes(StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(combined);
        return Base64.getEncoder().encodeToString(hash);
    }

    /* --- AUTHENTICATION VERIFICATION --- */

    /**
     * Verifies that {@code inputPass} matches the stored hash when combined
     * with {@code storedSalt}.
     * <p>
     * Uses {@link MessageDigest#isEqual(byte[], byte[])} for constant-time
     * comparison, preventing timing-based side-channel attacks.
     * </p>
     *
     * @param inputPass  the password supplied by the user
     * @param storedHash the Base64 hash retrieved from the database
     * @param storedSalt the Base64 salt retrieved from the database
     * @return {@code true} if and only if the credentials match
     * @throws NoSuchAlgorithmException if hashing fails
     */
    public boolean verify(String inputPass, String storedHash, String storedSalt) throws NoSuchAlgorithmException {
        if (inputPass == null || storedHash == null || storedSalt == null) {
            return false;
        }
        String newHash = hashPassword(inputPass, storedSalt);
        return MessageDigest.isEqual(
                newHash.getBytes(StandardCharsets.UTF_8),
                storedHash.getBytes(StandardCharsets.UTF_8)
        );
    }
}