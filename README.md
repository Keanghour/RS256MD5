# RS256MD5
This project integrates RSA encryption with both MD5 and SHA-256 hashing for enhanced data security. RSA handles encryption/decryption, while MD5 and SHA-256 generate and verify hashes of the data. This dual-hashing ensures strong data integrity and protection against tampering during transmission.

---

# RSA with MD5/SHA-256 Encryption and Decryption

## Overview

This project demonstrates the usage of RSA encryption and decryption alongside MD5 and SHA-256 hashing algorithms. It ensures data integrity through hashing and encryption with RSA keys. The project includes:

- RSA Encryption and Decryption with both MD5 and SHA-256 hash verification.
- Ability to encrypt data using RSA public keys and decrypt using RSA private keys.
- Provides the ability to verify data integrity with MD5/SHA-256 hashes.

## Components

1. **RSAWithMD5Encrypt.java**
   - Encrypts data using RSA public key and generates MD5 hash of the encrypted data.

2. **RSAWithMD5Decrypt.java**
   - Decrypts data using RSA private key and verifies the MD5 hash of the decrypted data.

3. **RSAWithSHA256Encrypt.java**
   - Encrypts data using RSA public key and generates SHA-256 hash of the encrypted data.

4. **RSAWithSHA256Decrypt.java**
   - Decrypts data using RSA private key and verifies the SHA-256 hash of the decrypted data.

## Key Features

- **RSA Encryption/Decryption:** Protects data using public and private keys.
- **MD5/SHA-256 Hashing:** Ensures the integrity of encrypted data by generating and verifying hashes.
- **Key Management:** Loads RSA public/private keys from PEM files.

## How to Use

### Prerequisites
1. Java 8 or higher.
2. RSA Public and Private keys in PEM format.

### Steps
1. Place the RSA public/private key files (e.g., `publicKey.pem` and `privateKey.pem`) in the project directory.
2. Run the desired class (`RSAWithMD5Encrypt`, `RSAWithMD5Decrypt`, `RSAWithSHA256Encrypt`, or `RSAWithSHA256Decrypt`) to see encryption, decryption, and hash verification in action.

Example usage:
```bash
# To encrypt and generate MD5 hash
java RSAWithMD5Encrypt

# To decrypt and verify MD5 hash
java RSAWithMD5Decrypt
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Feel free to modify it according to your project’s specifics, like the key file paths or any additional requirements.
