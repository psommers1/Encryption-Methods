"""
Encryption/Decryption Demonstration
Author: Paul Sommers
Course: SDEV245

This script demonstrates both symmetric and asymmetric encryption methods
using Python's cryptography library. It shows the strengths and weaknesses
of each approach by encrypting and decrypting a short message.
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64


def print_section(title):
    """Helper function to print section headers for better readability"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def symmetric_encryption_demo():
    """
    Demonstrates symmetric encryption using Fernet (AES-128 in CBC mode).
    
    Symmetric encryption uses the SAME key for both encryption and decryption.
    This is fast and efficient but requires secure key distribution.
    """
    print_section("SYMMETRIC ENCRYPTION (Fernet/AES)")
    
    # Original message to encrypt
    message = "Hello, this is a secret message!"
    print(f"\nOriginal Message: {message}")
    
    # Generate a symmetric key
    # This key must be kept secret and shared securely with anyone who needs to decrypt
    symmetric_key = Fernet.generate_key()
    print(f"\nSymmetric Key (Base64-encoded):")
    print(f"   {symmetric_key.decode()}")
    print(f"   Length: {len(symmetric_key)} bytes")
    
    # Create a Fernet cipher instance with the key
    cipher = Fernet(symmetric_key)
    
    # Encrypt the message
    encrypted_message = cipher.encrypt(message.encode())
    print(f"\nEncrypted Message (Base64-encoded):")
    print(f"   {encrypted_message.decode()}")
    print(f"   Length: {len(encrypted_message)} bytes")
    
    # Decrypt the message using the same key
    decrypted_message = cipher.decrypt(encrypted_message)
    print(f"\nDecrypted Message:")
    print(f"   {decrypted_message.decode()}")
    
    # Verify the decryption worked correctly
    assert decrypted_message.decode() == message, "Decryption failed!"
    print("\nSymmetric encryption/decryption successful!")
    
    print("\nSTRENGTHS:")
    print("   - Very fast encryption/decryption (good for large files)")
    print("   - Less computationally intensive")
    print("   - Smaller key size compared to asymmetric")
    
    print("\nWEAKNESSES:")
    print("   - Key distribution problem (how to securely share the key?)")
    print("   - Same key for encryption and decryption (if compromised, all data is at risk)")
    print("   - Requires secure channel to exchange keys")


def asymmetric_encryption_demo():
    """
    Demonstrates asymmetric encryption using RSA.
    
    Asymmetric encryption uses a PUBLIC key for encryption and a PRIVATE key for decryption.
    This solves the key distribution problem but is slower and has size limitations.
    """
    print_section("ASYMMETRIC ENCRYPTION (RSA)")
    
    # Original message to encrypt
    message = "Hello, this is a secret message!"
    print(f"\nOriginal Message: {message}")
    
    # Generate RSA key pair (private and public keys)
    # Key size of 2048 bits is commonly used for security
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard value for RSA
        key_size=2048           # 2048-bit key for good security
    )
    public_key = private_key.public_key()
    
    # Serialize the public key to PEM format for display
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    print(f"\nPublic Key (PEM format - first 200 chars):")
    print(f"   {public_pem.decode()[:200]}...")
    print(f"   Total length: {len(public_pem)} bytes")
    
    # Serialize the private key to PEM format for display
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    print(f"\nPrivate Key (PEM format - first 200 chars):")
    print(f"   {private_pem.decode()[:200]}...")
    print(f"   Total length: {len(private_pem)} bytes")
    
    # Encrypt the message using the PUBLIC key
    # Anyone with the public key can encrypt, but only the private key holder can decrypt
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"\nEncrypted Message (Base64-encoded):")
    encrypted_b64 = base64.b64encode(encrypted_message).decode()
    print(f"   {encrypted_b64}")
    print(f"   Length: {len(encrypted_message)} bytes")
    
    # Decrypt the message using the PRIVATE key
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"\nDecrypted Message:")
    print(f"   {decrypted_message.decode()}")
    
    # Verify the decryption worked correctly
    assert decrypted_message.decode() == message, "Decryption failed!"
    print("\nAsymmetric encryption/decryption successful!")
    
    print("\nSTRENGTHS:")
    print("   - Solves key distribution problem (public key can be shared openly)")
    print("   - Private key never needs to be transmitted")
    print("   - Different keys for encryption/decryption (better security)")
    print("   - Enables digital signatures and authentication")
    
    print("\nWEAKNESSES:")
    print("   - Much slower than symmetric encryption")
    print("   - Can only encrypt small amounts of data (limited by key size)")
    print("   - Larger key sizes required for equivalent security")
    print("   - More computationally intensive")


def main():
    """
    Main function that runs both encryption demonstrations.
    This allows comparison of symmetric vs asymmetric encryption methods.
    """
    print("\n" + "="*70)
    print("  ENCRYPTION/DECRYPTION DEMONSTRATION")
    print("  Comparing Symmetric and Asymmetric Methods")
    print("="*70)
    
    # Run symmetric encryption demo
    symmetric_encryption_demo()
    
    print("\n\n")
    
    # Run asymmetric encryption demo
    asymmetric_encryption_demo()
    
    # Summary comparison
    print_section("COMPARISON SUMMARY")
    print("\nHYBRID APPROACH (Best Practice):")
    print("   Most real-world systems use BOTH methods:")
    print("   1. Use asymmetric encryption (RSA) to exchange a symmetric key")
    print("   2. Use symmetric encryption (AES) to encrypt the actual data")
    print("   3. This combines the strengths of both methods")
    print("\n   Examples: HTTPS/TLS, PGP/GPG, SSH\n")


if __name__ == "__main__":
    main()