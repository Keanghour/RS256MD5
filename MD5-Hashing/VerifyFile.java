package MD5;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class VerifyFile {
    // Method to generate MD5 hash
    public static String generateMD5Hash(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(data.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString(); // Return MD5 hash
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to verify if the data matches the given MD5 hash
    public static boolean verifyHash(String originalData, String hashToVerify) {
        String generatedHash = generateMD5Hash(originalData);
        return generatedHash.equals(hashToVerify); // Return true if hashes match, otherwise false
    }

    public static void main(String[] args) {
        String data = "HelloWorld"; // Sample data to be verified
        String givenHash = "68e109f0f40ca72a15e05cc22786f8e6"; // Precomputed MD5 hash to check

        boolean isMatch = verifyHash(data, givenHash); // Verify if the hash matches

        // Instead of printing a message, just return the boolean
        System.out.println(isMatch); // This will print 'true' or 'false' based on the match
    }
}
