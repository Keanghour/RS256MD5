package RSA;

import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Encryptor {

    public static void main(String[] args) {
        try {
            // Load public key from PEM file
            String publicKeyPEM = loadPEM("publicKey.pem");

            // Remove the first and last lines (PEM header/footer)
            publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "").trim();

            // Decode Base64-encoded public key
            byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);

            // Reconstruct PublicKey from decoded bytes
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

            // Transaction message
            String transactionMessage = "Transfer $100 to Account #12345";

            // Encrypt the message
            String encryptedMessage = RSACryptoAlgorithm.encrypt(transactionMessage, publicKey);

            System.out.println("Encrypted Message: " + encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Utility to load PEM files (public/private key)
    private static String loadPEM(String pemFile) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(pemFile)));
        StringBuilder pemContent = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            pemContent.append(line);
        }
        reader.close();
        return pemContent.toString();
    }
}
