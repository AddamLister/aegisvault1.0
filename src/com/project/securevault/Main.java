package com.project.securevault;

import javafx.application.Application;

/**
 * Application entry point for Aegis Vault.
 * <p>
 * This class exists as a non-{@link Application} launcher so that the JavaFX
 * module system can locate and initialize {@link SecureFileApp} correctly,
 * even when running from a classpath-based (non-modular) project layout.
 * </p>
 */
public class Main {

    public static void main(String[] args) {
        Application.launch(SecureFileApp.class, args);
    }
}
