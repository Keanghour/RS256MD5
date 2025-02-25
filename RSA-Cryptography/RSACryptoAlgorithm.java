package RSA;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;
import java.util.Base64;

public class RSACryptoAlgorithm {

    // Encrypt a message using RSA public key
    public static String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes); // Return the encrypted message in Base64
    }

    // Decrypt a message using RSA private key
    public static String decrypt(String encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)); // Decode Base64, then
                                                                                              // decrypt
        return new String(decryptedBytes);
    }

    // Sign a message using RSA private key
    public static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA"); // Using SHA-256 for signing
        signature.initSign(privateKey);
        signature.update(message.getBytes()); // Update the signature with the message
        byte[] signedMessage = signature.sign();
        return Base64.getEncoder().encodeToString(signedMessage); // Return the signed message in Base64
    }

    // Verify the signature of a message using RSA public key
    public static boolean verifySignature(String message, String signatureStr, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA"); // Using SHA-256 for verification
        signature.initVerify(publicKey);
        signature.update(message.getBytes()); // Update with the original message
        byte[] signatureBytes = Base64.getDecoder().decode(signatureStr); // Decode Base64 to get the signature
        return signature.verify(signatureBytes); // Verify the signature
    }
}
