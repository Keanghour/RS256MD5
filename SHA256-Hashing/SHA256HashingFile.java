import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256HashingFile {
    // Method to generate SHA-256 hash
    public static String generateSHA256Hash(String data) {
        try {
            // Get the MessageDigest instance for SHA-256
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // Perform the hashing
            byte[] hashBytes = md.digest(data.getBytes());

            // Convert byte array to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }

            return hexString.toString(); // Return SHA-256 hash
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null; // Return null if error occurs
        }
    }

    public static void main(String[] args) {
        String data = "HelloWorld"; // Sample data to be hashed

        String hashedData = generateSHA256Hash(data); // Get the SHA-256 hash of the data
        System.out.println("SHA-256 Hash: " + hashedData); // Print the SHA-256 hash
    }
}
