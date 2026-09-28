#!/usr/bin/env python3
"""
Data Encryption and Decryption Tool
Simple command-line tool for AES and RSA encryption
"""

import os
import time
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class AESCipher:
    """AES encryption and decryption implementation"""
    
    def __init__(self, password: str = None, key: bytes = None):
        if key:
            self.key = key
            self.password = None
        elif password:
            self.password = password
            self.key = None
        else:
            raise ValueError("Either password or key must be provided")
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key
    
    def encrypt(self, data: bytes) -> tuple:
        iv = os.urandom(16)
        salt = os.urandom(16)
        
        # Derive key with the salt that will be stored
        if self.password:
            self.key = self._derive_key(self.password, salt)
        
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        pad_length = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_length] * pad_length)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted_data, iv, salt
    
    def decrypt(self, encrypted_data: bytes, iv: bytes, salt: bytes) -> bytes:
        # Derive key with the salt from the encrypted file
        if self.password:
            self.key = self._derive_key(self.password, salt)
        
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        pad_length = padded_data[-1]
        data = padded_data[:-pad_length]
        
        return data


class RSACipher:
    """RSA encryption and decryption implementation"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self) -> tuple:
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def encrypt(self, data: bytes) -> bytes:
        if not self.public_key:
            raise ValueError("Public key not loaded")
        
        max_chunk_size = (self.key_size // 8) - 42
        
        if len(data) > max_chunk_size:
            raise ValueError(f"Data too large for RSA encryption. Max size: {max_chunk_size} bytes")
        
        encrypted_data = self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted_data
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        decrypted_data = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted_data


def encrypt_message(message: str, password: str):
    """Encrypt a message using AES"""
    print(f"Original message: {message}")
    print(f"Password: {password}")
    
    cipher = AESCipher(password=password)
    data = message.encode('utf-8')
    
    start_time = time.time()
    encrypted_data, iv, salt = cipher.encrypt(data)
    encrypt_time = time.time() - start_time
    
    # Create new cipher instance for decryption to test the salt-based key derivation
    cipher_decrypt = AESCipher(password=password)
    start_time = time.time()
    decrypted_data = cipher_decrypt.decrypt(encrypted_data, iv, salt)
    decrypt_time = time.time() - start_time
    
    print(f"\n=== AES Encryption Result ===")
    print(f"Algorithm: AES-256-CBC")
    print(f"Original length: {len(data)} bytes")
    print(f"Encrypted length: {len(encrypted_data)} bytes")
    print(f"Encrypt time: {encrypt_time:.6f} seconds")
    print(f"Decrypt time: {decrypt_time:.6f} seconds")
    print(f"Success: {decrypted_data == data}")
    print(f"\nEncrypted data (base64): {base64.b64encode(encrypted_data).decode('utf-8')}")
    print(f"IV (base64): {base64.b64encode(iv).decode('utf-8')}")
    print(f"Salt (base64): {base64.b64encode(salt).decode('utf-8')}")
    print(f"Decrypted message: {decrypted_data.decode('utf-8')}")


def encrypt_message_rsa(message: str, key_size: int = 2048):
    """Encrypt a message using RSA"""
    print(f"Original message: {message}")
    print(f"RSA key size: {key_size} bits")
    
    cipher = RSACipher(key_size=key_size)
    
    start_time = time.time()
    private_pem, public_pem = cipher.generate_keys()
    key_gen_time = time.time() - start_time
    
    data = message.encode('utf-8')
    
    start_time = time.time()
    encrypted_data = cipher.encrypt(data)
    encrypt_time = time.time() - start_time
    
    start_time = time.time()
    decrypted_data = cipher.decrypt(encrypted_data)
    decrypt_time = time.time() - start_time
    
    print(f"\n=== RSA Encryption Result ===")
    print(f"Algorithm: RSA-{key_size}-OAEP")
    print(f"Original length: {len(data)} bytes")
    print(f"Encrypted length: {len(encrypted_data)} bytes")
    print(f"Key generation time: {key_gen_time:.6f} seconds")
    print(f"Encrypt time: {encrypt_time:.6f} seconds")
    print(f"Decrypt time: {decrypt_time:.6f} seconds")
    print(f"Success: {decrypted_data == data}")
    print(f"\nEncrypted data (base64): {base64.b64encode(encrypted_data).decode('utf-8')}")
    print(f"Decrypted message: {decrypted_data.decode('utf-8')}")


def encrypt_file(file_path: str, password: str):
    """Encrypt a file using AES"""
    # Convert to absolute path if relative
    if not os.path.isabs(file_path):
        file_path = os.path.join(os.getcwd(), file_path)
    
    print(f"Looking for file: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found")
        print(f"Current directory: {os.getcwd()}")
        print(f"Available files in current directory:")
        try:
            files = os.listdir('.')
            for f in files:
                if os.path.isfile(f) and not f.startswith('.'):
                    print(f"  - {f}")
        except:
            pass
        return
    
    cipher = AESCipher(password=password)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    print(f"Original file size: {len(data)} bytes")
    
    start_time = time.time()
    encrypted_data, iv, salt = cipher.encrypt(data)
    encrypt_time = time.time() - start_time
    
    output_path = file_path + '.encrypted'
    
    metadata = {
        'iv': base64.b64encode(iv).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8'),
        'original_filename': os.path.basename(file_path)
    }
    
    with open(output_path, 'wb') as f:
        f.write(json.dumps(metadata).encode('utf-8') + b'\n')
        f.write(encrypted_data)
    
    print(f"\n=== File Encryption Result ===")
    print(f"Algorithm: AES-256-CBC")
    print(f"Encrypted file size: {len(encrypted_data)} bytes")
    print(f"Encrypt time: {encrypt_time:.6f} seconds")
    print(f"Output file: {output_path}")


def decrypt_file(file_path: str, password: str):
    """Decrypt a file using AES"""
    # Convert to absolute path if relative
    if not os.path.isabs(file_path):
        file_path = os.path.join(os.getcwd(), file_path)
    
    print(f"Looking for file: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found")
        print(f"Current directory: {os.getcwd()}")
        print(f"Available files in current directory:")
        try:
            files = os.listdir('.')
            for f in files:
                if os.path.isfile(f) and not f.startswith('.'):
                    print(f"  - {f}")
        except:
            pass
        return
    
    with open(file_path, 'rb') as f:
        metadata_line = f.readline().decode('utf-8').strip()
        metadata = json.loads(metadata_line)
        encrypted_data = f.read()
    
    print(f"Encrypted file size: {len(encrypted_data)} bytes")
    
    iv = base64.b64decode(metadata['iv'])
    salt = base64.b64decode(metadata['salt'])
    
    cipher = AESCipher(password=password)
    
    start_time = time.time()
    decrypted_data = cipher.decrypt(encrypted_data, iv, salt)
    decrypt_time = time.time() - start_time
    
    output_path = file_path.replace('.encrypted', '_decrypted')
    
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"\n=== File Decryption Result ===")
    print(f"Algorithm: AES-256-CBC")
    print(f"Decrypted file size: {len(decrypted_data)} bytes")
    print(f"Decrypt time: {decrypt_time:.6f} seconds")
    print(f"Output file: {output_path}")


def compare_algorithms(message: str, password: str, rsa_key_size: int = 2048):
    """Compare AES and RSA performance"""
    print(f"Comparing algorithms with message: {message}")
    print(f"Message length: {len(message.encode('utf-8'))} bytes")
    
    # AES Test
    aes_cipher = AESCipher(password=password)
    message_bytes = message.encode('utf-8')
    
    start_time = time.time()
    aes_encrypted, aes_iv, aes_salt = aes_cipher.encrypt(message_bytes)
    aes_encrypt_time = time.time() - start_time
    
    # Create new cipher instance for decryption to test salt-based key derivation
    aes_cipher_decrypt = AESCipher(password=password)
    start_time = time.time()
    aes_decrypted = aes_cipher_decrypt.decrypt(aes_encrypted, aes_iv, aes_salt)
    aes_decrypt_time = time.time() - start_time
    
    print(f"\n=== AES Performance ===")
    print(f"Algorithm: AES-256-CBC")
    print(f"Encrypt time: {aes_encrypt_time:.6f} seconds")
    print(f"Decrypt time: {aes_decrypt_time:.6f} seconds")
    print(f"Size ratio: {len(aes_encrypted) / len(message_bytes):.2f}x")
    print(f"Security: Symmetric, 256-bit key")
    print(f"Use case: Bulk data encryption, fast")
    
    # RSA Test (only for small messages)
    if len(message_bytes) < ((rsa_key_size // 8) - 42):
        rsa_cipher = RSACipher(key_size=rsa_key_size)
        
        start_time = time.time()
        rsa_private_pem, rsa_public_pem = rsa_cipher.generate_keys()
        rsa_key_gen_time = time.time() - start_time
        
        start_time = time.time()
        rsa_encrypted = rsa_cipher.encrypt(message_bytes)
        rsa_encrypt_time = time.time() - start_time
        
        start_time = time.time()
        rsa_decrypted = rsa_cipher.decrypt(rsa_encrypted)
        rsa_decrypt_time = time.time() - start_time
        
        print(f"\n=== RSA Performance ===")
        print(f"Algorithm: RSA-{rsa_key_size}-OAEP")
        print(f"Key generation time: {rsa_key_gen_time:.6f} seconds")
        print(f"Encrypt time: {rsa_encrypt_time:.6f} seconds")
        print(f"Decrypt time: {rsa_decrypt_time:.6f} seconds")
        print(f"Size ratio: {len(rsa_encrypted) / len(message_bytes):.2f}x")
        print(f"Security: Asymmetric, {rsa_key_size}-bit key")
        print(f"Use case: Key exchange, digital signatures")
    else:
        print(f"\n=== RSA Skipped ===")
        print(f"Message too large for RSA-{rsa_key_size} encryption")


def show_security_analysis():
    """Display security analysis and recommendations"""
    print("=== Security Analysis ===")
    
    print("\n--- AES Security ---")
    print("Security Level: High (256-bit key)")
    print("Best For: Encrypting files, databases, bulk data")
    print("\nStrengths:")
    print("  + Very fast encryption/decryption")
    print("  + Suitable for large data")
    print("  + 256-bit key is computationally secure")
    print("  + Standard for symmetric encryption")
    print("\nWeaknesses:")
    print("  - Key distribution challenge")
    print("  - Single point of failure if key is compromised")
    print("  - Key must be shared securely")
    
    print("\n--- RSA Security ---")
    print("Security Level: High (depends on key size: 2048+ bits)")
    print("Best For: Key exchange, digital signatures, small data")
    print("\nStrengths:")
    print("  + Solves key distribution problem")
    print("  + Enables digital signatures")
    print("  + Public key can be freely shared")
    print("  + Key exchange protocols")
    print("\nWeaknesses:")
    print("  - Slow compared to AES")
    print("  - Limited data size per encryption")
    print("  - Larger key sizes needed for security")
    print("  - Computationally intensive")
    
    print("\n--- Recommendations ---")
    print("  - Use AES for encrypting large files or data streams")
    print("  - Use RSA for encrypting AES keys (hybrid approach)")
    print("  - Use RSA for digital signatures and authentication")
    print("  - Combine both: RSA to exchange AES keys, AES for data")


def main():
    """Main menu for the crypto tool"""
    print("=" * 60)
    print("    Data Encryption and Decryption Tool")
    print("=" * 60)
    print(f"Current directory: {os.getcwd()}")
    
    # List available files in current directory
    files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.startswith('.') and not f.endswith('.pyc')]
    if files:
        print(f"Available files: {', '.join(files[:5])}")
        if len(files) > 5:
            print(f"  ... and {len(files) - 5} more files")
    print()
    
    while True:
        print("\nChoose an option:")
        print("1. Encrypt message (AES)")
        print("2. Encrypt message (RSA)")
        print("3. Encrypt file")
        print("4. Decrypt file")
        print("5. Compare algorithms")
        print("6. Security analysis")
        print("7. Exit")
        
        choice = input("\nEnter your choice (1-7): ").strip()
        
        if choice == '1':
            message = input("Enter message to encrypt: ")
            password = input("Enter password: ")
            encrypt_message(message, password)
        
        elif choice == '2':
            message = input("Enter message to encrypt: ")
            key_size = int(input("Enter RSA key size (1024/2048/3072/4096): ") or "2048")
            encrypt_message_rsa(message, key_size)
        
        elif choice == '3':
            file_path = input("Enter file path to encrypt: ")
            password = input("Enter password: ")
            encrypt_file(file_path, password)
        
        elif choice == '4':
            file_path = input("Enter encrypted file path: ")
            password = input("Enter password: ")
            decrypt_file(file_path, password)
        
        elif choice == '5':
            message = input("Enter test message: ")
            password = input("Enter password for AES: ")
            key_size = int(input("Enter RSA key size (1024/2048/3072/4096): ") or "2048")
            compare_algorithms(message, password, key_size)
        
        elif choice == '6':
            show_security_analysis()
        
        elif choice == '7':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")


if __name__ == '__main__':
    # Change to the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    main()
