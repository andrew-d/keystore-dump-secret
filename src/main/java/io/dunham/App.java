package io.dunham;

import java.io.Console;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.JCommander;


public class App {
    @Parameter
    private List<String> keyStoreFiles;

    @Parameter(names={"--entry-name"})
    private String entryName = "secret1";

    public void run() {
        if (keyStoreFiles == null || keyStoreFiles.isEmpty()) {
            System.out.println("No keystore given");
            return;
        }

        final char[] password = promptPassword("Enter keystore password: ");

        try {
            final KeyStore ks = KeyStore.getInstance("JCEKS");

            try(final FileInputStream is = new FileInputStream(keyStoreFiles.get(0))) {
                ks.load(is, password);
            }

            System.out.println("Loaded keystore");

            final char[] entryPassword = promptPassword("Enter entry password: ");
            final KeyStore.ProtectionParameter protParam =
                new KeyStore.PasswordProtection(entryPassword);

            final KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry)ks.getEntry(entryName, protParam);
            System.out.println("Loaded entry");

            // System.out.println("Secret key:" + skEntry.toString());

            final SecretKey sk = skEntry.getSecretKey();

            System.out.println("Algorithm: " + sk.getAlgorithm());
            System.out.println("Format: " + sk.getFormat());

            final byte[] encoded = sk.getEncoded();
            System.out.println("Encoded: " + bytesToHex(encoded));
        } catch (final Exception e) {
            System.err.println("Caught exception");
            e.printStackTrace(System.err);
        }
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private char[] promptPassword(String prompt) {
        Console c = null;

        c = System.console();
        if (c == null) {
            return null;
        }

        return c.readPassword(prompt);
    }

    public static void main(String[] args) {
        App a = new App();
        new JCommander(a, args);
        a.run();
    }
}
