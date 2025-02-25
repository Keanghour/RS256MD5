package RSA;

import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Decryptor {

    public static void main(String[] args) {
        try {
            // Load private key from PEM file
            String privateKeyPEM = loadPEM("privateKey.pem");

            // Remove the first and last lines (PEM header/footer)
            privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "").trim();

            // Decode Base64-encoded private key
            byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);

            // Reconstruct PrivateKey from decoded bytes
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

            // Encrypted message (from Encryptor)
            String encryptedMessage = "b4cTiylXHltq3usYxy9Lks11XWRP5Mlqe74MmA3GexU4RTqgjUmlh5m0VOcEs7hyulwYUa1lZRju0Ckviuw2th1FIJf3hxpOzJTiBRw2DFk0p/+ACIslRlEoazwixBzneXWyU/omhblYNc2Nd0beqYf7Df86PkI/olRZkcDzrFxOe+Ib7tasPxzDVONsg5luWWJBPEThZDuiWrhIOgnO0ZGbkfquk4Gtif9AAh4ZZdHPmQMn+aWy0LaHDL9H5eHC8FkTZ3g8j2YBS03eoxy6+OrSMc2RYgnJn4sEXa/9q+ut92zdeQR4CVe7hnMuzYKvzYayTzKXfejzgC3yWCWAWw=="; // Example placeholder, replace with actual
                                                                     // encrypted message

            // Decrypt the message
            String decryptedMessage = RSACryptoAlgorithm.decrypt(encryptedMessage, privateKey);

            System.out.println("Decrypted Message: " + decryptedMessage);
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
