package com.project.securevault;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.io.File;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

public class CryptoService {
    // Advanced encryption standard with Chain Block Chaining and Padding
    private static final String ALGO = "AES/CBC/PKCS5Padding";
    // Key Derivation Function to turn a password into a 256-bit key
    private static final String DERIVATION_ALGO = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;
    private static final int IV_SIZE = 16;

    // Helper: Derives the AES key from the user's password and salt
    private SecretKey deriveKey(String password, String salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(DERIVATION_ALGO);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), ITERATIONS, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    public void encrypt(File file, String password, String salt) throws Exception {
        SecretKey key = deriveKey(password, salt);

        // Generate a random IV (Initialization Vector)
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] fileContent = Files.readAllBytes(file.toPath());
        byte[] encryptedContent = c.doFinal(fileContent);

        // Save IV + Encrypted Data together so we can decrypt later
        byte[] combined = new byte[iv.length + encryptedContent.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedContent, 0, combined, iv.length, encryptedContent.length);

        Files.write(new File(file.getAbsolutePath() + ".enc").toPath(), combined);
    }

    public void decrypt(File file, String password, String salt) throws Exception {
        SecretKey key = deriveKey(password, salt);

        byte[] fileContent = Files.readAllBytes(file.toPath());

        // Extract the IV from the start of the file
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(fileContent, 0, iv, 0, iv.length);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Extract the actual encrypted data
        int encryptedSize = fileContent.length - IV_SIZE;
        byte[] encryptedData = new byte[encryptedSize];
        System.arraycopy(fileContent, IV_SIZE, encryptedData, 0, encryptedSize);

        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] decryptedContent = c.doFinal(encryptedData);

        // Save decrypted file (remove .enc)
        String outPath = file.getAbsolutePath().replace(".enc", "");
        Files.write(new File(outPath).toPath(), decryptedContent);
    }
}
