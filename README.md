# Secure-Message-Prototype-
Please run both Alice and Bobs Code at the same time and enter in any inputs required quick for the code to run smoothly

---

## 🚀 How It Works

1. **Message Input**  
   Alice and Bob each input a plaintext message that will be encrypted and authenticated.

2. **Key Generation (RSA)**  
   Each party generates a **3072-bit RSA key pair** and saves them as `.pem` files.

3. **Digital Signing**  
   - Each message is signed using RSA-PKCS#1 v1.5.  
   - Diffie–Hellman values (`g^a mod p`, `g^b mod p`) are also signed for authenticity.

4. **Verification**  
   Each party verifies the other's message and DH value signatures using the public key.

5. **Diffie–Hellman Key Exchange**  
   The shared secret is computed:

6. **Key Derivation Function (KDF)**  
The shared secret is iteratively hashed to produce the final **session key**.

7. **PRNG**  
A simple pseudo-random number generator based on SHA256 is used for nonce derivation.

8. **Symmetric Encryption (AES-GCM)**  
The message is encrypted using AES-GCM with the derived session key and nonce.

9. **HMAC Authentication**  
An HMAC-SHA256 tag is computed for the ciphertext, ensuring integrity.

10. **Decryption & Verification**  
 The recipient verifies the HMAC and decrypts the ciphertext to recover the plaintext message.

---

## 🧩 Requirements

Install dependencies using pip:

```bash
pip install pycryptodome
