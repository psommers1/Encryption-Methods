# Encryption Methods Demonstration

Simple demonstration of symmetric and asymmetric encryption methods in Python.

**Author:** Paul Sommers  
**Course:** SDEV245

## What This Does

This Python script demonstrates two fundamental encryption approaches:
- Symmetric encryption using Fernet (AES-128 in CBC mode)
- Asymmetric encryption using RSA (2048-bit keys)

The code encrypts and decrypts a short message using both methods, showing the keys, inputs, and outputs for each approach.

## Key Concepts

### Symmetric Encryption (Fernet/AES)

Symmetric encryption uses the **same key** for both encryption and decryption. In this demo, we use the Fernet library, which implements AES (Advanced Encryption Standard) in CBC mode with HMAC for authentication.

**How it works:**
1. Generate a single symmetric key
2. Use that key to encrypt the message
3. Use the same key to decrypt the message

**Strengths:**
- **Speed:** Very fast encryption and decryption operations
- **Efficiency:** Low computational overhead, ideal for large files or data streams
- **Small keys:** 256-bit keys provide strong security with minimal storage
- **Resource-friendly:** Works well on devices with limited processing power

**Weaknesses:**
- **Key distribution problem:** How do you securely share the key with someone?
- **Single point of failure:** If the key is compromised, all encrypted data is at risk
- **Scalability issues:** Need a unique key for each pair of communicating parties (N*(N-1)/2 keys for N users)
- **No authentication:** Without additional mechanisms, you can't verify who encrypted the message

### Asymmetric Encryption (RSA)

Asymmetric encryption uses **two different keys**: a public key for encryption and a private key for decryption. This demo uses RSA, one of the most widely-used asymmetric algorithms.

**How it works:**
1. Generate a key pair (private key and public key)
2. Share the public key openly (anyone can have it)
3. Others encrypt messages using your public key
4. Only you can decrypt using your private key

**Strengths:**
- **Solves key distribution:** Public keys can be shared openly without compromising security
- **Authentication:** Private keys enable digital signatures to verify sender identity
- **No shared secrets:** Private key never needs to be transmitted
- **Better key management:** Each user only needs one key pair regardless of number of contacts

**Weaknesses:**
- **Slow:** 100-1000x slower than symmetric encryption
- **Size limitations:** Can only encrypt small amounts of data (limited by key size)
- **Large keys required:** 2048-bit keys for security comparable to 128-bit symmetric keys
- **Computational cost:** More processing power required, draining for mobile devices

## Real-World Usage: Hybrid Encryption

Most modern systems combine both methods to get the best of both worlds:

1. **RSA (asymmetric)** - Used to securely exchange a session key
2. **AES (symmetric)** - Used to encrypt the actual data with the session key
3. This is how **HTTPS, TLS, PGP, and SSH** work

**Example (simplified HTTPS):**
- Your browser gets the website's public RSA key
- Browser generates a random AES key
- Browser encrypts the AES key with the website's RSA public key
- Website decrypts to get the AES key using its RSA private key
- All further communication is encrypted with fast AES using that session key

## How to Run

**Step 1: Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 2: Run the script**
```bash
python encryption_demo.py
```

The script will display:
- Keys used for both methods
- Original message (input)
- Encrypted message (output)
- Decrypted message (verification)
- Strengths and weaknesses of each method

## Files

- `encryption_demo.py` - Main script demonstrating both encryption methods
- `requirements.txt` - Python dependencies (cryptography library)
- `README.md` - This file

## Sample Output

The script produces detailed output showing:

**Symmetric Encryption:**
- Generated symmetric key (Base64-encoded)
- Original message
- Encrypted ciphertext
- Decrypted plaintext
- Performance characteristics

**Asymmetric Encryption:**
- Public key (PEM format)
- Private key (PEM format)
- Original message
- Encrypted ciphertext
- Decrypted plaintext
- Performance characteristics

## Links

- **GitHub:** https://github.com/psommers1/Encryption-Methods

## Learning Objectives

This assignment demonstrates understanding of:
- The fundamental difference between symmetric and asymmetric encryption
- Practical implementation of both methods in Python
- When to use each type of encryption
- The strengths and weaknesses of each approach
- Why hybrid systems are the industry standard