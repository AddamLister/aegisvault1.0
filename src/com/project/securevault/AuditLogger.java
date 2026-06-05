package com.project.securevault;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Thread-safe, append-only audit logger that writes timestamped security
 * events to {@code audit_log.txt}.
 * <p>
 * Each log entry follows the format:
 * <pre>  YYYY-MM-DDTHH:MM:SS | User: &lt;username&gt; | Action: &lt;action&gt;</pre>
 * </p>
 */
public class AuditLogger {

    private static final Logger LOGGER = Logger.getLogger(AuditLogger.class.getName());
    private static final String LOG_FILE = "audit_log.txt";
    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

    /**
     * Appends a single audit entry.  Synchronised to prevent interleaved
     * writes when encryption / decryption tasks log from background threads.
     *
     * @param username the authenticated user performing the action
     * @param action   a short, upper-case tag describing the event
     */
    public static synchronized void log(String username, String action) {
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(
                        new FileOutputStream(LOG_FILE, true),
                        StandardCharsets.UTF_8))) {
            String timestamp = LocalDateTime.now().format(FORMATTER);
            writer.write(timestamp + " | User: " + username + " | Action: " + action);
            writer.newLine();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "AuditLogger write failed", e);
        }
    }
}