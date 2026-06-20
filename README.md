# Secure Email System with Distributed Key Management & Account Recovery

---

## 📦 Project Components

### 1. Gmail Server (`gmailserver.cpp`)
- User authentication and session management
- Argon2id password hashing and verification
- Signed Session Token generation and validation
- One-Time Operation Token generation and validation
- Encrypted email storage and retrieval
- Internal verification service for Key Server and Recovery Server

### 2. Key Server (`keyserver.cpp`)
- Public key storage, distribution, and RSA signature
- Share1 storage, retrieval, and post-recovery updates
- Session Token and Operation Token verification before releasing shares

### 3. Recovery Server (`recovery_server.cpp`)
- Share2 storage, retrieval, and post-recovery updates
- Session Token and Operation Token verification before releasing shares

### 4. Client Application (`client.cpp`)
- User signup and login
- RSA-2048 key pair generation
- Shamir Secret Sharing (split and reconstruct)
- Email encryption, decryption, signing, and verification
- Account recovery and share rotation

### 5. Shared Modules
| File | Purpose |
|---|---|
| `shamir.cpp / shamir.h` | 2-of-3 Shamir Secret Sharing over GF(2⁸) |
| `tls_common.cpp / tls_common.h` | Shared TLS transport layer (wraps OpenSSL) |

---

## 🎯 Project Overview

This is a secure email communication system that ensures no single server can reconstruct a user's private key. It combines:

- End-to-end encrypted email
- Distributed private key storage via Shamir Secret Sharing
- TLS-secured communication on every channel
- Signed Session Tokens with expiry
- Single-use Operation Tokens with replay protection
- Secure account recovery without administrator involvement
- Share rotation after every recovery

---

## 🏗️ System Architecture

```
                        ┌─────────────────────────────┐
                        │   CLIENT (client.cpp)        │
                        │  RSA-2048 │ AES-256 │ Shamir │
                        └────┬──────────┬──────────┬───┘
                             │ TLS      │ TLS      │ TLS
                             ▼          ▼          ▼
                ┌──────────────┐  ┌──────────┐  ┌─────────────────┐
                │ Gmail Server │  │Key Server│  │ Recovery Server │
                │  Port 4444   │  │ Port 5555│  │   Port 6666     │
                │  Port 4446*  │  │          │  │                 │
                │              │  │ Public   │  │ Share2 Store    │
                │ Auth + Email │  │ Key Store│  │                 │
                │ Argon2id     │  │ Share1   │  │                 │
                │ Signed Token │  │ Store    │  │                 │
                └──────┬───────┘  └────┬─────┘  └───────┬─────────┘
                       │  TLS (4446*)  │                 │
                       └──────────────┘                  │
                       │  TLS (4446*)                     │
                       └─────────────────────────────────┘

  * Port 4446 is an internal server-to-server verification port (TLS, not client-facing)
```

### Private Key Distribution

```
User's RSA-2048 Private Key
           │
           ▼
  Shamir Secret Sharing (2-of-3)
           │
    ┌──────┴──────┬───────────────┐
    ▼             ▼               ▼
 Share1        Share2          Share3
Key Server  Recovery Server  Local disk
                             (Argon2id
                              encrypted)

Any 2 of the 3 shares reconstruct the key.
A single share reveals nothing.
```

---

## 🔐 Security Features

### Email Confidentiality
- AES-256-CBC encrypts email contents with a unique session key per message
- Session key encrypted using RSA-OAEP with the recipient's public key

### Integrity Protection
- HMAC-SHA256 computed over the ciphertext detects any tampering

### Sender Authentication
- HMAC and session key are each signed with the sender's RSA private key
- Recipient verifies both signatures against the sender's public key before decrypting

### Public Key Integrity
- Key Server signs every public key it distributes with its own RSA private key
- Prevents public key substitution and man-in-the-middle attacks

### Password Security
- Argon2id (memory-hard, from libsodium) with a random salt per user
- No plaintext or reversible password representation is ever stored

### Transport Security
- TLS 1.2+ on every connection (client ↔ all servers, server ↔ server verify port)
- Self-signed certificates pinned via `certs/trusted_servers.pem` — no system CA store consulted
- A substituted server is rejected at the TLS handshake

### Session Security — Signed Session Tokens

After successful login the Gmail Server issues a signed token:

```
base64(payload) . base64(RSA-SHA256 signature)
```

Payload contains: `username`, `issued_at`, `expires_at`, `nonce`

The Key Server and Recovery Server verify the RSA signature and expiry independently before accepting any request.

### Operation Security — One-Time Operation Tokens

Every sensitive share operation requires a fresh single-use token:

| Operation | Protected By |
|---|---|
| `STORE_SHARE1` | Operation Token |
| `FETCH_SHARE1` | Operation Token |
| `UPDATE_SHARE1` | Operation Token |
| `STORE_SHARE` | Operation Token |
| `GET_SHARE` | Operation Token |
| `UPDATE_SHARE` | Operation Token |

Each token is bound to: username · operation type · target server · expiry.  
Used once, then invalidated — prevents replay attacks even if a token is captured.

### Distributed Key Protection

| Location | Stores | Alone it reveals |
|---|---|---|
| Key Server | Share1 | Nothing |
| Recovery Server | Share2 | Nothing |
| Client disk | Share3 (Argon2id encrypted) | Nothing |

An attacker must compromise **two independent locations simultaneously** to reconstruct the private key.

### Share Rotation

After every successful account recovery, `split_private_key()` is called again on the recovered key, producing a brand-new Share1, Share2, and Share3 from fresh random polynomial coefficients. The new shares replace the old ones on both servers and locally. This means:

- Previously captured shares are permanently invalidated
- Each recovery cycle produces a completely independent share set
- A partial compromise (one share stolen before recovery) becomes worthless after rotation

---

## 🔄 Account Recovery

If Share3 is lost (device lost, forgotten password, corrupted file):

1. User authenticates with Gmail Server — receives a Signed Session Token.
2. Client fetches Share1 from Key Server (token verified server-side).
3. Client fetches Share2 from Recovery Server (token verified server-side).
4. Private key is reconstructed from Share1 + Share2.
5. `split_private_key()` is called on the recovered key — new polynomial coefficients, brand-new Share1/Share2/Share3.
6. New Share1 replaces the old one on Key Server.
7. New Share2 replaces the old one on Recovery Server.
8. New Share3 is encrypted with Argon2id and saved locally.

Old shares are permanently invalidated after rotation. The recovered key is identical; only its representation changes.

---

## ✅ Verified Security Properties

The system has been tested for:

- Session token tampering detection
- Session token expiry enforcement
- Username mismatch attacks
- Operation token replay attack prevention
- Wrong-operation token rejection
- Wrong-target-server token rejection
- TLS certificate validation and pinning
- Account recovery and share rotation correctness
- End-to-end encrypted email delivery and decryption

---

## 🚀 Setup and Build

### Requirements

| Dependency | Version | Purpose |
|---|---|---|
| g++ | C++17 or later | Compilation |
| OpenSSL | 3.x | TLS, RSA, AES, HMAC, SHA |
| libsodium | 1.0.18+ | Argon2id password hashing and KDF |

**Ubuntu / Debian:**
```bash
sudo apt update && sudo apt install g++ libssl-dev libsodium-dev
```

**Fedora / RHEL:**
```bash
sudo dnf install gcc-c++ openssl-devel libsodium-devel
```

---

### Step 1 — Generate TLS Certificates (run once)

```bash
chmod +x certs/gen_certs.sh
./certs/gen_certs.sh
```

Produces:
```
certs/gmailserver_cert.pem    certs/gmailserver_key.pem
certs/keyserver_cert.pem      certs/keyserver_key.pem
certs/recoveryserver_cert.pem certs/recoveryserver_key.pem
certs/trusted_servers.pem     ← pinned bundle trusted by all clients
```

> If you regenerate certificates, restart all servers and the client.

---

### Step 2 — Create Build Directory

```bash
mkdir -p build
```

---

### Step 3 — Compile

```bash
# Gmail Server
g++ -std=c++17 gmailserver.cpp tls_common.cpp \
    -lssl -lcrypto -lsodium -lpthread -o build/gmailserver

# Key Server
g++ -std=c++17 keyserver.cpp tls_common.cpp \
    -lssl -lcrypto -lsodium -lpthread -o build/keyserver

# Recovery Server
g++ -std=c++17 recovery_server.cpp tls_common.cpp \
    -lssl -lcrypto -lsodium -lpthread -o build/recovery_server

# Client
g++ -std=c++17 client.cpp shamir.cpp tls_common.cpp \
    -lssl -lcrypto -lsodium -lpthread -o build/client
```

---

### Step 4 — Start Servers (in order)

**Startup order matters.** Always follow this sequence:

```
1. Gmail Server   — generates signing keys; hosts the session verify port (4446)
2. Key Server     — connects to Gmail Server at startup for token verification
3. Recovery Server — connects to Gmail Server at startup for token verification
4. Client
```

This ensures:
- Gmail signing keys are generated before other servers need them
- TLS certificates are in place before any handshake is attempted
- Session Token and Operation Token verification works correctly from the first request

```bash
# Terminal 1
./build/gmailserver

# Terminal 2
./build/keyserver

# Terminal 3
./build/recovery_server

# Terminal 4
./build/client
```

---

## 📧 Usage

### New User Signup
1. Select **Signup**
2. Enter username and password
3. RSA-2048 key pair is generated
4. Private key split into three Shamir shares
5. Share1 → Key Server, Share2 → Recovery Server, Share3 → local (Argon2id encrypted)

### Login
1. Authenticate → receive Signed Session Token
2. Request One-Time Operation Token
3. Fetch Share1 from Key Server
4. Decrypt Share3 from local storage
5. Reconstruct private key from Share1 + Share3

### Send Email
1. Enter recipient ID and message
2. Random AES-256-CBC session key generated
3. Message encrypted → HMAC computed → both signed with sender's RSA key
4. Session key encrypted with recipient's RSA public key
5. Complete packet sent to Gmail Server

### Receive Email
1. Fetch encrypted emails from Gmail Server
2. Verify Key Server's signature on sender's public key
3. Verify RSA signature on session key and HMAC
4. Verify HMAC-SHA256 over ciphertext
5. Decrypt session key → decrypt message

### Account Recovery
1. Select **Account Recovery** from the main menu
2. System fetches Share1 and Share2 from servers (both token-verified)
3. Private key reconstructed from Share1 + Share2
4. All three shares rotated automatically with fresh polynomial coefficients

---

## 🛡️ Cryptographic Primitives Reference

| Primitive | Algorithm | Used For |
|---|---|---|
| Transport encryption | TLS 1.2+ (OpenSSL) | All network connections |
| Asymmetric encryption | RSA-2048, OAEP padding | Email session key encryption |
| Symmetric encryption | AES-256-CBC | Email body; Share3 local storage |
| Message authentication | HMAC-SHA256 | Email integrity |
| Digital signatures | RSA-SHA256 | Email sender auth; public key certification; session tokens |
| Password hashing | Argon2id (libsodium) | User passwords; Share3 key derivation |
| Secret sharing | Shamir 2-of-3 over GF(2⁸) | Splitting RSA private key |
| Random generation | `RAND_bytes` (OpenSSL) | Session keys, IVs, Shamir coefficients, nonces |

---

# 🚀 Future Enhancements

### 1. Public Key Revocation

Currently, registered public keys remain valid indefinitely. Future versions can introduce a key revocation mechanism that allows users to securely invalidate compromised or retired key pairs and register new public keys.

---

### 2. Periodic Key Rotation

The current system performs share rotation after successful account recovery. Future versions can extend this approach to periodic RSA key-pair rotation, further reducing long-term exposure and strengthening overall security.

---

### 3. Perfect Forward Secrecy (PFS)

At present, email confidentiality relies on the recipient's long-term RSA private key. Future versions can incorporate ephemeral key exchange mechanisms such as ECDHE or X25519 to ensure previously exchanged emails remain secure even if long-term private keys are compromised.

---

### 4. Multi-Factor Authentication (MFA)

Additional authentication factors such as TOTP-based authenticator applications or hardware security keys can be integrated to provide stronger protection against credential theft and unauthorized access.

---

### 5. Threshold Cryptography

Currently, account recovery reconstructs the private key using Shamir Secret Sharing. Future versions can explore threshold cryptographic techniques that enable cryptographic operations without ever reconstructing the complete private key, providing stronger security guarantees.

---
