import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256VerifyFile {
    // Method to generate SHA-256 hash
    public static String generateSHA256Hash(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(data.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString(); // Return SHA-256 hash
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to verify if the data matches the given SHA-256 hash
    public static boolean verifyHash(String originalData, String hashToVerify) {
        String generatedHash = generateSHA256Hash(originalData);
        return generatedHash.equals(hashToVerify); // Return true if hashes match, otherwise false
    }

    public static void main(String[] args) {
        String data = "HelloWorld"; // Sample data to be verified
        String givenHash = "872e4e50ce9990d8b041330c47c9ddd11bec6b503ae9386a99da8584e9bb12c4"; // Precomputed SHA-256
                                                                                               // hash to check

        boolean isMatch = verifyHash(data, givenHash); // Verify if the hash matches

        // Instead of printing a message, just return the boolean
        System.out.println(isMatch); // This will print 'true' or 'false' based on the match
    }
}
