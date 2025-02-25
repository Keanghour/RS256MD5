import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSAWithSHA256Encrypt {

    // Encrypt data with RSA public key
    public static String rsaEncrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // Using OAEP with SHA-256
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes); // Base64 encoding the encrypted data
    }

    // Generate SHA-256 hash of the encrypted data
    public static String generateSHA256Hash(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(data.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString(); // Return SHA-256 hash
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

        // Hash the encrypted data with SHA-256
        String encryptedDataSHA256 = generateSHA256Hash(encryptedData);
        System.out.println("SHA-256 Hash of Encrypted Data: " + encryptedDataSHA256);

        // Save encrypted data and hash for later verification during decryption
    }
}
