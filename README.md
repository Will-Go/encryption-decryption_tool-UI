# File Encryption/Decryption Tool

This project was made for my internship program in HackSecure.

## Overview

A secure Python-based GUI application for encrypting and decrypting files using Fernet symmetric encryption. The tool provides an intuitive interface for protecting sensitive files with strong encryption.

## Features

- File encryption with AES-256 (Fernet implementation)
- File decryption with proper key authentication
- Key generation functionality
- Modern, user-friendly GUI with Tkinter
- Cross-platform compatibility (Windows, macOS, Linux)
- Secure file handling practices with options to:
  - Remove original file after encryption/decryption
  - Keep original file after encryption/decryption
- Detailed error messages and validation

## Requirements

- Python 3.7+
- Packages listed in `requirements.txt`:
  - cryptography

## Installation

1. Clone this repository
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/MacOS
   .\venv\Scripts\activate  # Windows
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running the Application

```bash
python file_crypt.py
```

### Encrypting a File

1. Select the "Encrypt File" tab
2. Click "Browse" to select ANY file type
3. Choose file handling option (remove or keep original)
4. Enter an encryption key or generate a new one
5. Click "Encrypt File"
6. Choose a location to save the encrypted file (.enc)

### Decrypting a File

1. Select the "Decrypt File" tab
2. Click "Browse" to select an encrypted file (.enc)
3. Choose file handling option (remove or keep encrypted file)
4. Enter the correct decryption key
5. Click "Decrypt File"
6. Choose a location to save the decrypted file (with original extension)

### Key Management

- Always store your encryption keys securely
- The same key used for encryption must be used for decryption
- Lost keys cannot be recovered - encrypted files will be permanently inaccessible

## Screenshots

#### Encrypt UI

![Application Screenshot](/screenshots/encrypt/SS_encrypt.png)

![Import a File](/screenshots/encrypt/SS_select.png)

![Choose the file to encript](/screenshots/encrypt/SS_FILE.png)

![Choose the file to encript](/screenshots/encrypt/SS_Contain.png)

![Choose the file to encript](/screenshots/encrypt/SS_Selected.png)

![Choose the file to encript](/screenshots/encrypt/SS_generateKey.png)

![Choose the file to encript](/screenshots/encrypt/SS_saveFILE.png)

![Choose the file to encript](/screenshots/encrypt/SS_Success_Encrypted.png)

#### Decrypt UI

![Application Screenshot](/screenshots/decrypt/SS_decrypt.png)

![Application Screenshot](/screenshots/decrypt/SS_choose_file.png)

![Application Screenshot](/screenshots/decrypt/SS_selectFile.png)

![Application Screenshot](/screenshots/decrypt/SS_decryptFile.png)

![Application Screenshot](/screenshots/decrypt/SS_saveDecrypt.png)

![Application Screenshot](/screenshots/decrypt/SS_Succesfull.png)

## Future Enhancements

- [ ] Support for multiple file types
- [ ] Drag and drop functionality
- [ ] Key export/import functionality
- [ ] File hashing verification
- [ ] Password-based key derivation

## Acknowledgements

- cryptography module for robust encryption implementation
- Python community for excellent documentation
