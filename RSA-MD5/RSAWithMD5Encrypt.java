package RSAXMD5;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSAWithMD5Encrypt {

    // Encrypt data with RSA public key
    public static String rsaEncrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes); // Base64 encoding the encrypted data
    }

    // Generate MD5 hash of the encrypted data
    public static String generateMD5Hash(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashBytes = md.digest(data.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString(); // Return MD5 hash
    }

    // Load the RSA public key from PEM file
    public static PublicKey loadPublicKey(String filepath) throws Exception {
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
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static void main(String[] args) throws Exception {
        String originalData = "HelloWorld"; // Data to encrypt and hash

        // Load RSA public key from PEM file
        PublicKey publicKey = loadPublicKey("publicKey.pem");

        // Encrypt data using RSA
        String encryptedData = rsaEncrypt(originalData, publicKey);
        System.out.println("Encrypted Data: " + encryptedData);

        // Hash the encrypted data with MD5
        String encryptedDataMD5 = generateMD5Hash(encryptedData);
        System.out.println("MD5 Hash of Encrypted Data: " + encryptedDataMD5);

        // Save encrypted data and hash for later verification during decryption
        // (for example, saving to a file or passing them to the decryption process)
    }
}
