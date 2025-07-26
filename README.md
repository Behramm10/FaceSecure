# 🔐 FaceSecure

**FaceSecure** is an advanced biometric file security system that protects sensitive files using facial recognition and AES-256 encryption. It allows users to encrypt and decrypt files using their face as the authentication key, offering both strong security and seamless access.

<br>

## 🚀 Features

* 🧠 **Facial Recognition Login**
  Secure authentication using OpenCV and the `face_recognition` library.

* 🔒 **AES-256-CBC File Encryption**
  Uses PBKDF2-HMAC for key derivation with AES-256 encryption in CBC mode.

* 💻 **Modern GUI**
  Built with `CustomTkinter` (or falls back to classic Tkinter).

* 📂 **Automatic Cleanup**
  Decrypted files are auto-deleted after a set timeout.

* 🧾 **Access Logging**
  CSV logs of registration, login attempts, encryption, and decryption actions.

* 🔐 **No Passwords Stored**
  All cryptographic keys are derived per-session; no key is stored on disk.

---

## 📁 Project Structure

```
FaceSecure/
│
├── db/               # Stores facial encodings (face_encodings.pkl)
├── encrypted/        # Contains encrypted .enc files
├── unlocked/         # Temporarily holds decrypted files (auto-deleted)
├── logs/             # CSV logs for access and file activity
├── facesecure.py     # 🔑 Main script
└── README.md         # 📄 Project documentation
```

---

## 🛠️ Requirements

* Python 3.8+
* OpenCV
* face\_recognition
* Pillow
* pycryptodome
* (Optional) customtkinter

Install dependencies:

```bash
pip install -r requirements.txt
```

Or individually:

```bash
pip install opencv-python face_recognition pillow pycryptodome customtkinter
```

---

## 🧑‍💻 Usage

```bash
python facesecure.py
```

### Functions:

* 👤 **Register** – Capture and save your facial encoding.
* 🔍 **Unlock** – Authenticate with your face to decrypt files.
* 🔒 **Encrypt** – Select files to encrypt using your identity.
* 📊 **Logs** – View recent access and activity logs.
* 🧹 **Cleanup** – Manually delete decrypted files early.

---

## 🔐 Security Notes

* Encryption uses **AES-256 in CBC mode** with secure padding.
* **PBKDF2-HMAC-SHA256** derives keys with 100,000 iterations and unique salts.
* Facial data is stored locally and never shared.
* Decrypted files are automatically deleted after `5 minutes` (configurable).
* Logs are stored in plaintext by default — consider encrypting `logs/access_log.csv` for production.

---

## 📸 Screenshots

> <img width="1112" height="585" alt="image" src="https://github.com/user-attachments/assets/846f5989-3527-4d0f-bb53-0aa870e363e5" />

---

## 👤 Author

**BEHRAMM UMRIGAR** — (https://github.com/Behramm10)

---

## 📄 License

This project is licensed under the MIT License. See `LICENSE` for details.

