package RSA;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class KeyPairGeneratorUtil {

    public static void main(String[] args) {
        try {
            // Step 1: Initialize the KeyPairGenerator for RSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            // Step 2: Initialize with a 2048-bit key size (common for secure RSA keys)
            keyPairGenerator.initialize(2048);

            // Step 3: Generate the RSA Key Pair (public and private keys)
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Step 4: Get the public and private keys from the key pair
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Step 5: Convert keys to byte arrays
            byte[] publicKeyBytes = publicKey.getEncoded();
            byte[] privateKeyBytes = privateKey.getEncoded();

            // Step 6: Encode the byte arrays in Base64
            String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);
            String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKeyBytes);

            // Step 7: Format the PEM format for Public Key
            String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                    formatBase64(publicKeyBase64) +
                    "\n-----END PUBLIC KEY-----";

            // Format the PEM format for Private Key
            String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                    formatBase64(privateKeyBase64) +
                    "\n-----END PRIVATE KEY-----";

            // Step 8: Save the PEM formatted keys to files
            try (
                    FileOutputStream publicKeyOut = new FileOutputStream("publicKey.pem");
                    FileOutputStream privateKeyOut = new FileOutputStream("privateKey.pem")) {
                publicKeyOut.write(publicKeyPem.getBytes());
                privateKeyOut.write(privateKeyPem.getBytes());
            }

            // Step 9: Confirm key pair generation and saving
            System.out.println("RSA Key Pair generated and saved in PEM format.");

        } catch (Exception e) {
            // Print any exceptions that occur during key pair generation and saving
            e.printStackTrace();
        }
    }

    // Helper method to format Base64 string into lines of 64 characters (PEM format
    // requirement)
    private static String formatBase64(String base64String) {
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < base64String.length(); i += 64) {
            int endIndex = Math.min(i + 64, base64String.length());
            formatted.append(base64String, i, endIndex).append("\n");
        }
        return formatted.toString();
    }
}
