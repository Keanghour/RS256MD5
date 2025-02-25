package RSAXMD5;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.*;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSAWithMD5Decrypt {

    // Decrypt data with RSA private key
    public static String rsaDecrypt(String encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes); // Return decrypted data as string
    }

    // Generate MD5 hash of the decrypted data
    public static String generateMD5Hash(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashBytes = md.digest(data.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString(); // Return MD5 hash of the decrypted data
    }

    // Load the RSA private key from PEM file
    public static PrivateKey loadPrivateKey(String filepath) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(filepath));
        StringBuilder keyString = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            if (!line.startsWith("-----")) {
                keyString.append(line);
            }
        }
        reader.close();
        byte[] keyBytes = Base64.getDecoder().decode(keyString.toString());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // Verify MD5 hash with encrypted data
    public static boolean verifyMD5Hash(String encryptedData, String providedMD5Hash) throws Exception {
        String calculatedMD5Hash = generateMD5Hash(encryptedData);
        return calculatedMD5Hash.equals(providedMD5Hash);
    }

    public static void main(String[] args) throws Exception {
        String encryptedData = "f/TrN0i/+J6OuaKFyMSBQno2KY9SBuelfTNdCad1fnb9Xz8QbrAS41O1biyF1iNTW6iMdXULP84u6ArbZ32IqnHv+C8obBMCa7C6XhygbcN+UPGEHLzGohLo7P4qQ5LMhzl/DlgLFAI232dv1cz+fya2HbcCD9RYZJjiSllofsMsTUDcQCj+2G3ubPXYMMSPnCLFKMnP5ngIjY/pIwWOql8TqY+Hnjl80mhTsRVHJiUMTJz10q5jhtbxSjM9otZaSWwfYzY4POIiPk6f7uX20L4DAC9OSJgz1iKqc3a6QXLFLW4Mrixu3rtaxUJKgPkDz2N51oRiacnQyJD3HAuo6A=="; // Replace this with actual encrypted data
        String providedMD5Hash = "7b22ab920d2fe4b6a1bbd30b45f9e0f9"; // Replace this with the MD5 hash provided (for comparison)

        // Load RSA private key from PEM file
        PrivateKey privateKey = loadPrivateKey("privateKey.pem");

        // Verify the MD5 hash of the encrypted data first
        if (verifyMD5Hash(encryptedData, providedMD5Hash)) {
            // If hash is valid, proceed to decrypt the encrypted data
            String decryptedData = rsaDecrypt(encryptedData, privateKey);
            System.out.println("Decrypted Data: " + decryptedData);
        } else {
            System.out.println("MD5 hash verification failed! The data might have been tampered with.");
        }
    }
}
