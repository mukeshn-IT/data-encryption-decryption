# Data Encryption and Decryption Tool

A simple command-line tool for encrypting and decrypting data using AES and RSA algorithms.

## Features

- **AES-256-CBC Encryption**: Fast symmetric encryption for messages and files
- **RSA Encryption**: Asymmetric encryption with multiple key sizes
- **File Encryption/Decryption**: Protect sensitive documents
- **Algorithm Comparison**: Compare performance between AES and RSA
- **Security Analysis**: Learn about security trade-offs and best practices

## Installation

1. Install Python 3.7 or higher
2. Install dependencies:
   ```bash
   py -m pip install -r requirements.txt
   ```

## Usage

Run the tool:
```bash
py crypto_tool.py
```

### Menu Options

1. **Encrypt message (AES)** - Encrypt text using AES-256-CBC
2. **Encrypt message (RSA)** - Encrypt text using RSA
3. **Encrypt file** - Encrypt a file using AES
4. **Decrypt file** - Decrypt an encrypted file
5. **Compare algorithms** - Compare AES vs RSA performance
6. **Security analysis** - View security information and recommendations
7. **Exit** - Exit the program

### Example Usage

#### Encrypt a Message
```
Enter your choice (1-7): 1
Enter message to encrypt: Hello World
Enter password: mypassword
```

#### Encrypt a File
```
Enter your choice (1-7): 3
Enter file path to encrypt: test.txt
Enter password: mypassword
```

#### Compare Algorithms
```
Enter your choice (1-7): 5
Enter test message: Test message
Enter password for AES: mypassword
Enter RSA key size (1024/2048/3072/4096): 2048
```

## Algorithm Details

### AES (Advanced Encryption Standard)
- **Type**: Symmetric encryption
- **Key Size**: 256 bits
- **Mode**: CBC (Cipher Block Chaining)
- **Best For**: Large files, bulk data encryption

### RSA (Rivest-Shamir-Adleman)
- **Type**: Asymmetric encryption
- **Key Sizes**: 1024, 2048, 3072, 4096 bits
- **Best For**: Key exchange, digital signatures

## Security Notes

- Use strong passwords for encryption
- Keep your passwords secure
- AES is faster for large data
- RSA is better for key exchange
- Never share passwords insecurely

## Learning Outcomes

- Hands-on experience with cryptographic algorithms
- Understanding of symmetric vs asymmetric encryption
- Knowledge of security vs performance trade-offs
- Practical file encryption skills
