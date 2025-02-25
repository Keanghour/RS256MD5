import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.*;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSAWithSHA256Decrypt {

    // Decrypt data with RSA private key
    public static String rsaDecrypt(String encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // Using OAEP with SHA-256
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes); // Return decrypted data as string
    }

    // Generate SHA-256 hash of the decrypted data
    public static String generateSHA256Hash(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(data.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString(); // Return SHA-256 hash of the decrypted data
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

    // Verify SHA-256 hash with encrypted data
    public static boolean verifySHA256Hash(String encryptedData, String providedSHA256Hash) throws Exception {
        String calculatedSHA256Hash = generateSHA256Hash(encryptedData);
        return calculatedSHA256Hash.equals(providedSHA256Hash);
    }

    public static void main(String[] args) throws Exception {
        String encryptedData = "gqO4WCqulx5RleTedDiAdcXWhfSad2EnfDlCcN4QtHn5glT3GC23T9kBedniqoit3L2I76iV4aSH65TKMmDXvEpJ+tUP5YCR0I1gR+iRP038CSZdK931czxcnkNTw//Co1wkOo0K9xHO6JngQEvkmGkTK8XtAQAlSqYWZqK9XauwtMHcuFNa9Bur6bNL2HPIViy+UiDfOUpzG0wVwPC+PpYMNwpUAUJCerKcGmBvL9W1o86m0SFfPrv3doF/xswBNGJdXYlj/pga5bW9TAZujqYFo9Okaglh2o9R7pu6zDj3KwhJRlSfuArYDmBEVSsYPERkR8xBLGa54hNcDXShwQ=="; // Replace this with actual encrypted data
        String providedSHA256Hash = "257d62f46f9e339e25be8f0bd8de53d10c75f2a0a8349f94e0cb8af6479691fd"; // Replace this with the SHA-256 hash provided (for comparison)

        // Load RSA private key from PEM file
        PrivateKey privateKey = loadPrivateKey("privateKey.pem");

        // Verify the SHA-256 hash of the encrypted data first
        if (verifySHA256Hash(encryptedData, providedSHA256Hash)) {
            // If hash is valid, proceed to decrypt the encrypted data
            String decryptedData = rsaDecrypt(encryptedData, privateKey);
            System.out.println("Decrypted Data: " + decryptedData);
        } else {
            System.out.println("SHA-256 hash verification failed! The data might have been tampered with.");
        }
    }
}
