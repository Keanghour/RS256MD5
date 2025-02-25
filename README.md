---

# RS256MD5

This project integrates RSA encryption with both MD5 and SHA-256 hashing for enhanced data security. RSA handles encryption and decryption, while MD5 and SHA-256 generate and verify hashes of the data. This dual-hashing ensures strong data integrity and protection against tampering during transmission.

---

# RSA with MD5/SHA-256 Encryption and Decryption

## Overview

This project demonstrates the usage of **RSA encryption** and decryption alongside **MD5** and **SHA-256** hashing algorithms to ensure the integrity of the encrypted data. The combination of encryption with RSA keys and hash verification using MD5/SHA-256 guarantees strong security measures and ensures that the data hasn't been tampered with during transmission.

### Key Features:
- **RSA Encryption/Decryption**: Encrypt and decrypt data using RSA public and private keys.
- **MD5/SHA-256 Hashing**: Generate MD5/SHA-256 hashes for encrypted data and verify their integrity.
- **Key Management**: Supports loading RSA public/private keys from PEM files for encryption/decryption.

## Components

### 1. **RSAWithMD5Encrypt.java**
   - Encrypts data using the RSA public key and generates an MD5 hash of the encrypted data.

### 2. **RSAWithMD5Decrypt.java**
   - Decrypts data using the RSA private key and verifies the MD5 hash of the decrypted data to ensure integrity.

### 3. **RSAWithSHA256Encrypt.java**
   - Encrypts data using the RSA public key and generates a SHA-256 hash of the encrypted data.

### 4. **RSAWithSHA256Decrypt.java**
   - Decrypts data using the RSA private key and verifies the SHA-256 hash of the decrypted data.

## How to Use

### Prerequisites
1. Java 8 or higher.
2. RSA **Public** and **Private** keys in PEM format.

### Setup:
1. Place the RSA public/private key files (e.g., `publicKey.pem` and `privateKey.pem`) in the project directory.
2. Use the following commands to run the desired Java class for encryption, decryption, and hash verification.

### Example Usage:

```bash
# To encrypt data and generate MD5 hash
java RSAWithMD5Encrypt

# To decrypt data and verify MD5 hash
java RSAWithMD5Decrypt

# To encrypt data and generate SHA-256 hash
java RSAWithSHA256Encrypt

# To decrypt data and verify SHA-256 hash
java RSAWithSHA256Decrypt
```

## Contact

Feel free to reach out if you have any questions or need further assistance:

- **Email**: [phokeanghour12@gmail.com](mailto:phokeanghour12@gmail.com)
- **Telegram**: [@phokeanghour](https://t.me/phokeanghour)

[![Telegram](https://www.vectorlogo.zone/logos/telegram/telegram-ar21.svg)](https://t.me/phokeanghour)
[![LinkedIn](https://www.vectorlogo.zone/logos/linkedin/linkedin-ar21.svg)](https://www.linkedin.com/in/pho-keanghour-27133b21b/)

---

**Credit**: This project was created by **Pho Keanghour**.

---

Let me know if this works or if you'd like any more adjustments!
