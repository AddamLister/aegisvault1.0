package com.project.securevault;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides Encrypt-then-MAC file encryption with AES-256-CBC and
 * HMAC-SHA256, plus multi-pass secure file shredding.
 *
 * <h2>Cryptographic Protocol</h2>
 * <pre>
 * Key Derivation:
 *   PBKDF2-HMAC-SHA256  (65 536 iterations, 512-bit output)
 *     → first  256 bits  →  AES encryption key
 *     → second 256 bits  →  HMAC authentication key
 *
 * Encrypted File Layout:
 *   ┌──────────────┬─────────────────┬──────────────────┐
 *   │ 16-byte IV   │   Ciphertext    │  32-byte HMAC    │
 *   └──────────────┴─────────────────┴──────────────────┘
 *
 * Encryption:
 *   1. Generate 16-byte random IV
 *   2. AES-256-CBC encrypt plaintext
 *   3. HMAC-SHA256 over (IV ‖ Ciphertext)
 *   4. Write IV ‖ Ciphertext ‖ HMAC
 *
 * Decryption:
 *   1. Extract HMAC, verify with constant-time comparison
 *   2. If valid, extract IV and decrypt
 * </pre>
 *
 * <h2>Secure Shredding</h2>
 * Three-pass overwrite inspired by DoD 5220.22-M:
 * <ol>
 *   <li>Pass 1 — all zero bytes</li>
 *   <li>Pass 2 — all {@code 0xFF} bytes</li>
 *   <li>Pass 3 — cryptographically random bytes</li>
 * </ol>
 */
public class CryptoService {

    private static final Logger LOGGER = Logger.getLogger(CryptoService.class.getName());

    /* --- ENCRYPTION CONFIGURATION --- */
    private static final String CIPHER_ALGO = "AES/CBC/PKCS5Padding";
    private static final String DERIVATION_ALGO = "PBKDF2WithHmacSHA256";
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final int ITERATIONS = 65_536;
    private static final int KEY_LENGTH = 512;   // bits — split into two 256-bit keys
    private static final int IV_SIZE = 16;        // bytes
    private static final int MAC_SIZE = 32;       // bytes — SHA-256 output
    private static final int SHRED_PASSES = 3;
    private static final int SHRED_CHUNK = 1024 * 1024; // 1 MiB buffer

    /* ------------------------------------------------------------------ */
    /*  KEY DERIVATION                                                     */
    /* ------------------------------------------------------------------ */

    /**
     * Derives a 256-bit AES key and a 256-bit HMAC key from the given
     * password and salt using PBKDF2-HMAC-SHA256.
     *
     * @return {@code [aesKey, hmacKey]}
     */
    private SecretKey[] deriveKeys(String password, String salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(DERIVATION_ALGO);
        KeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt.getBytes(StandardCharsets.UTF_8),
                ITERATIONS,
                KEY_LENGTH
        );
        byte[] fullKey = factory.generateSecret(spec).getEncoded();

        try {
            // Split: first 32 bytes → AES, second 32 bytes → HMAC
            byte[] aesKeyBytes = Arrays.copyOfRange(fullKey, 0, 32);
            byte[] hmacKeyBytes = Arrays.copyOfRange(fullKey, 32, 64);

            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, HMAC_ALGO);

            // Zero intermediary key material
            Arrays.fill(aesKeyBytes, (byte) 0);
            Arrays.fill(hmacKeyBytes, (byte) 0);

            return new SecretKey[]{aesKey, hmacKey};
        } finally {
            Arrays.fill(fullKey, (byte) 0);
        }
    }

    /* ------------------------------------------------------------------ */
    /*  ENCRYPT-THEN-MAC                                                   */
    /* ------------------------------------------------------------------ */

    /**
     * Encrypts the given file using AES-256-CBC, then appends an
     * HMAC-SHA256 tag over (IV ‖ ciphertext).  The encrypted payload is
     * written to {@code <originalName>.enc}.
     *
     * @param file     the plaintext file to encrypt
     * @param password the user's password (used for key derivation)
     * @param salt     the user's Base64-encoded salt
     */
    public void encrypt(File file, String password, String salt) throws Exception {
        SecretKey[] keys = deriveKeys(password, salt);
        SecretKey aesKey = keys[0];
        SecretKey hmacKey = keys[1];

        try {
            // 1. Generate cryptographically random IV
            byte[] iv = new byte[IV_SIZE];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // 2. Encrypt file contents
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            byte[] plaintext = Files.readAllBytes(file.toPath());
            byte[] ciphertext = cipher.doFinal(plaintext);

            // 3. Combine IV ‖ Ciphertext
            byte[] ivAndCiphertext = new byte[IV_SIZE + ciphertext.length];
            System.arraycopy(iv, 0, ivAndCiphertext, 0, IV_SIZE);
            System.arraycopy(ciphertext, 0, ivAndCiphertext, IV_SIZE, ciphertext.length);

            // 4. Compute HMAC over (IV ‖ Ciphertext)
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(hmacKey);
            byte[] macBytes = mac.doFinal(ivAndCiphertext);

            // 5. Final payload: IV ‖ Ciphertext ‖ HMAC
            byte[] payload = new byte[ivAndCiphertext.length + MAC_SIZE];
            System.arraycopy(ivAndCiphertext, 0, payload, 0, ivAndCiphertext.length);
            System.arraycopy(macBytes, 0, payload, ivAndCiphertext.length, MAC_SIZE);

            Files.write(new File(file.getAbsolutePath() + ".enc").toPath(), payload);
        } finally {
            // Defence-in-depth: zero plaintext and key references
            destroyKey(aesKey);
            destroyKey(hmacKey);
        }
    }

    /* ------------------------------------------------------------------ */
    /*  VERIFY-THEN-DECRYPT                                                */
    /* ------------------------------------------------------------------ */

    /**
     * Verifies the HMAC tag (constant-time), then decrypts the file.
     * The recovered plaintext is written alongside the {@code .enc} file
     * with the extension stripped.
     *
     * @param file     the {@code .enc} file to decrypt
     * @param password the user's password
     * @param salt     the user's Base64-encoded salt
     * @throws SecurityException if the HMAC verification fails (tampered
     *                           or wrong password)
     */
    public void decrypt(File file, String password, String salt) throws Exception {
        SecretKey[] keys = deriveKeys(password, salt);
        SecretKey aesKey = keys[0];
        SecretKey hmacKey = keys[1];

        try {
            byte[] fileContent = Files.readAllBytes(file.toPath());

            // Minimum length: IV + at least 1 block of ciphertext + MAC
            if (fileContent.length < IV_SIZE + MAC_SIZE) {
                throw new SecurityException("File is too short or corrupted.");
            }

            // 1. Separate (IV ‖ Ciphertext) from the trailing MAC
            int ivAndCipherSize = fileContent.length - MAC_SIZE;
            byte[] ivAndCiphertext = Arrays.copyOfRange(fileContent, 0, ivAndCipherSize);
            byte[] storedMac = Arrays.copyOfRange(fileContent, ivAndCipherSize, fileContent.length);

            // 2. VERIFY AUTHENTICITY & INTEGRITY (constant-time)
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(hmacKey);
            byte[] calculatedMac = mac.doFinal(ivAndCiphertext);

            if (!MessageDigest.isEqual(storedMac, calculatedMac)) {
                throw new SecurityException(
                        "CRITICAL: File integrity/authenticity verification failed. "
                                + "The file was tampered with or the wrong password was used.");
            }

            // 3. Extract IV and ciphertext
            byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, IV_SIZE);
            byte[] cipherText = Arrays.copyOfRange(ivAndCiphertext, IV_SIZE, ivAndCipherSize);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // 4. Decrypt
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            byte[] decryptedContent = cipher.doFinal(cipherText);

            String outPath = file.getAbsolutePath().replace(".enc", "");
            Files.write(new File(outPath).toPath(), decryptedContent);
        } finally {
            destroyKey(aesKey);
            destroyKey(hmacKey);
        }
    }

    /* ------------------------------------------------------------------ */
    /*  SECURE SHREDDING (3-PASS)                                          */
    /* ------------------------------------------------------------------ */

    /**
     * Securely deletes a file by overwriting its contents with three passes
     * (zeros, ones, random), then deleting it from disk.
     *
     * @param file the file to shred
     * @return {@code true} if the file was successfully overwritten and
     *         deleted; {@code false} otherwise
     */
    public boolean secureDelete(File file) {
        if (!file.exists() || !file.isFile()) {
            return false;
        }
        try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
            long length = file.length();
            int chunkSize = (int) Math.min(length, SHRED_CHUNK);
            byte[] buffer = new byte[chunkSize];
            SecureRandom random = new SecureRandom();

            for (int pass = 0; pass < SHRED_PASSES; pass++) {
                raf.seek(0);
                long remaining = length;

                while (remaining > 0) {
                    int toWrite = (int) Math.min(remaining, buffer.length);

                    switch (pass) {
                        case 0 -> Arrays.fill(buffer, 0, toWrite, (byte) 0x00);  // zeros
                        case 1 -> Arrays.fill(buffer, 0, toWrite, (byte) 0xFF);  // ones
                        default -> random.nextBytes(buffer);                       // random
                    }

                    raf.write(buffer, 0, toWrite);
                    remaining -= toWrite;
                }

                raf.getFD().sync(); // force flush to physical storage
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Secure shred failed for '" + file.getName() + "'", e);
            return false;
        }
        return file.delete();
    }

    /* ------------------------------------------------------------------ */
    /*  INTERNAL HELPERS                                                    */
    /* ------------------------------------------------------------------ */

    /**
     * Best-effort key destruction.  Attempts {@link javax.crypto.SecretKey}
     * {@code destroy()}, falling back to zeroing the encoded bytes.
     */
    private void destroyKey(SecretKey key) {
        try {
            key.destroy();
        } catch (javax.security.auth.DestroyFailedException ignored) {
            // Not all providers support destroy(); zero the encoded form instead
            byte[] encoded = key.getEncoded();
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }
}