package com.project.securevault;

import java.io.FileWriter;
import java.time.LocalDateTime;

public class AuditLogger {

    /* --- AUDIT LOGGING --- */
    public static void log(String username, String action) {
        try (FileWriter fw = new FileWriter("audit_log.txt", true)) {
            fw.write(LocalDateTime.now() + " | User: " + username + " | Action: " + action + "\n");
        } catch (Exception e) { e.printStackTrace(); }
    }
}