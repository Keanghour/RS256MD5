package MD5;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashingFile {
    // Method to generate MD5 hash
    public static String generateMD5Hash(String data) {
        try {
            // Get the MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("MD5");

            // Perform the hashing
            byte[] hashBytes = md.digest(data.getBytes());

            // Convert byte array to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }

            return hexString.toString(); // Return MD5 hash
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null; // Return null if error occurs
        }
    }

    public static void main(String[] args) {
        String data = "HelloWorld"; // Sample data to be hashed

        String hashedData = generateMD5Hash(data); // Get the MD5 hash of the data
        System.out.println("MD5 Hash: " + hashedData); // Print the MD5 hash
    }
}
