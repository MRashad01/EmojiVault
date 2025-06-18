# EmojiVault🔐


This project is a user-friendly password manager designed to generate and manage secure passwords using emojis, letters, and numbers. It includes advanced security features like AES encryption, hardware-based key generation, QR-code backup, and a fully interactive GUI.

---

## 🧩 Features

- ✅ AES-GCM encryption for strong data protection
- 🔐 Hardware-specific AES key generation (based on MAC address, RAM, Disk, etc.)
- 🌈 Emoji + letters + numbers password generator
- 📷 QR code backup and recovery
- 📁 `.txt`-based site identification system
- 💻 GUI interface (built with Tkinter)
- 🧠 Physical keyboard is blocked for secure input via virtual keyboard
- 📦 SQLite database for user and password storage

---

## 📁 File Structure

- `main.py`: Main application file. Manages GUI, encryption, database operations, QR code logic, and user interactions.
- `Algorithm.py`: Handles emoji-based password generation, including binary logic, XOR operations, S-box substitutions, etc.
- `supported_emojis_with_symbols.csv`: Maps emojis to their symbolic/ASCII equivalents.
- `site/`: Contains `.txt` files representing registered sites.
- `users2.db`: SQLite database file storing encrypted user credentials.

---

## 🚀 Installation

```bash
git clone https://github.com/MRashad01/EmojiVault.git
cd emoji-password-manager
pip install -r requirements.txt


