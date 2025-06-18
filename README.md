# EmojiVault
# Emoji-Secure Password Manager

A desktop password manager that combines a virtual emoji keyboard, hardware-based key derivation, AES-GCM encryption, and QR-code key recovery—built with Python and Tkinter. Store and retrieve your credentials securely without ever typing your master password on a physical keyboard.

---

## Features

- **Virtual Emoji Keyboard**  
  Enter your master password via on-screen emojis to defeat keyloggers and physical-keyboard attacks.

- **Hardware-Tied Key Derivation**  
  Combines your machine’s MAC address, RAM size, CPU info, and emoji inputs to generate a unique AES-128 key.

- **AES-128-GCM Encryption**  
  Ensures both confidentiality and integrity of stored credentials.

- **QR-Code Recovery**  
  If your hardware changes, recover your encryption key by scanning a previously generated QR code.

- **Secure Local Storage**  
  Uses a lightweight SQLite database (no server required) to store user accounts and encrypted passwords.

---

## Architecture Overview

1. **Presentation Layer**  
   - Tkinter GUI: Login/Register forms, main dashboard, emoji keyboard, dialogs.  
   - Disables physical keyboard input during password entry.

2. **Business Logic Layer**  
   - **Emoji Matrix Algorithm**: Transforms emoji selections into a 5×5 bit matrix.  
   - **Key Derivation Service**: Gathers hardware-specific data + emoji matrix → 16-byte AES key.  
   - **Encryption Service**: AES-128-GCM with PKCS#7 padding and Base64 encoding.  
   - **Hardware Change Detector**: Flags changes and triggers QR-code recovery.  
   - **QR Code Service**: Generates and reads encrypted key QR codes via `pyqrcode` & OpenCV.

3. **Data Layer**  
   - SQLite database with two tables:  
     - `users` (usernames + SHA-256 password hashes)  
     - `passwords` (site, account name, AES-encrypted password; linked to `users`)

---

## Requirements

- Python 3.8+  
- `tkinter`  
- `pycryptodome`  
- `pyqrcode` (or `qrcode`)  
- `opencv-python`  
- `psutil`  
- `sqlite3` (built-in)  

---

## Installation

```bash
git clone https://github.com/MRashad01/EmojiVault/tree/main/EmojiVault.git
cd emoji-secure-password-manager

python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt
