package com.project.securevault;

import java.io.FileWriter;
import java.time.LocalDateTime;

public class AuditLogger {
    public static void log(String username, String action) {
        // Appends to audit_log.txt
        try (FileWriter fw = new FileWriter("audit_log.txt", true)) {
            fw.write(LocalDateTime.now() + " | User: " + username + " | Action: " + action + "\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
