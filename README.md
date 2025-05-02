# Secure Email System

## 📦 What It Contains
- **Key Server** (`keyserver.cpp`): Manages public keys and digital signatures
- **Email Server** (`gmailserver.cpp`): Handles user authentication and encrypted email storage
- **Client Application** (`client.cpp`): Provides user interface for sending/receiving encrypted emails
- **Cryptographic Modules**: RSA-2048, AES-256, SHA-256 implementations using OpenSSL

## 🎯 What It Is
A **secure email communication system** that provides:
- End-to-end encryption for messages
- Tamper-proof message integrity
- Secure key exchange
- Hashed password storage

## 🚀 Execution Process
1. **Compile**:
   ```bash
   # Build all components
   g++ -std=c++17 keyserver.cpp -o keyserver -lssl -lcrypto
   g++ -std=c++17 gmailserver.cpp -o gmailserver -lssl -lcrypto
   g++ -std=c++17 client.cpp -o client -lssl -lcrypto
   ```
2.**Running**(in seperate terminals):
  ```bash
    ./keyserver    # Key Server (Port 5555)
    ./mailserver   # Email Server (Port 4444)
    ./client       #client
  ```
**Step-by-Step Usage**
```
**1.Register Client:**
Enter unique client ID when prompted
System generates RSA key pair automatically

**2.Authenticate:**
Choose:
1. Login (existing users)
2. Signup (new users)
Enter username/password

**3.Send Email:**
Select 1. Send email
Enter recipient ID and message
Encryption happens automatically

**4.Receive Email:**
Select 2. Receive emails
System decrypts and verifies messages automatically

**5.Exit:**
Select 0. Exit to quit

```
**🛠️ Requirements**
```
Linux OS
OpenSSL 1.1.1+
g++ (C++17 compatible)
4GB RAM (minimum)
```
**🔐 Security Features**
```
All emails encrypted with unique AES-256 session keys
RSA-2048 for key exchange
HMAC-SHA256 for message integrity
Server-signed public keys prevent MITM attacks
time-stamp based emails to prevent replay attacks
```
