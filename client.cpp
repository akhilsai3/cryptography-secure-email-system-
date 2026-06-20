#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <limits>
#include <sstream> 
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sodium.h>        // Argon2id for Share3 key derivation
#include "shamir.h"        // split_private_key / reconstruct_private_key
#include "tls_common.h"    // TLS transport helpers (tls_send/tls_recv/tls_client_connect/...)
#define BUFFER_SIZE 4096
#define RSA_KEY_SIZE 2048
#define AES_KEY_SIZE 32
#define HMAC_SIZE 32
#define AES_BLOCK_SIZE 16

// Pepper: hardcoded in the binary, never transmitted, never stored.
// Change this string to invalidate all existing Share3 files (forces
// users to recover via Share1+Share2 and re-derive).
static const char* SHARE3_PEPPER = "ZKEmail_Pepper_v1_NIT_WGl_2025";

// ---- Task 5: Legacy fallback flag ----
// Set to 1 during development/debugging so a login can fall back to
// <username>_private_key.pem if Shamir reconstruction fails.
// Set to 0 (or remove) once you are confident Share1+Share3 always works.
#define LEGACY_FALLBACK 0

// Recovery Server address (acts as iCloud/Google Drive in the architecture)
static const char* RECOVERY_SERVER_IP   = "127.0.0.1";
static const int   RECOVERY_SERVER_PORT = 6666;

// ---- TLS configuration ----
// Single trust bundle containing the self-signed certificates of all three
// servers this client talks to (Gmail Server, Key Server, Recovery
// Server). Built by certs/gen_certs.sh. One client SSL_CTX, trusting
// exactly these three certs, is used for every outbound connection -
// no external/system CA store is consulted.
static const char* TLS_TRUSTED_BUNDLE_PATH = "certs/trusted_servers.pem";
static SSL_CTX* g_client_ctx = nullptr;

using namespace std;
#define MAX_EMAIL_SIZE (10 * 1024 * 1024) // 10MB maximum email size
void process_email(const string& email, SSL* key_sock, EVP_PKEY* pkey);

// ----- Task 3/4 forward declarations (defined later in file) -----
string export_private_key_to_pem(EVP_PKEY* pkey);
bool save_local_share3(const string& username, const string& password, const string& share3);

// ----- Task 5 forward declarations -----
// fetch_share2_from_recoveryserver: connects to Recovery Server, sends
//   GET_SHARE|username|session_token|op_token, returns raw Share2 bytes (empty on failure).
//   Phase 2: requests a single-use Operation Token from Gmail Server
//   (gmail_sock) immediately before sending.
string fetch_share2_from_recoveryserver(SSL* gmail_sock, const string& username, const string& session_token);

// update_share1_on_keyserver / update_share2_on_recoveryserver: replace an
// already-stored share during recovery, when a fresh split() has produced
// a brand-new Share1/Share2/Share3 triple that must move to the servers
// together so a later Share1+Share3 login matches what Share1+Share2
// recovery just verified. Phase 2: both now also take gmail_sock to
// request a single-use Operation Token immediately before sending.
bool update_share1_on_keyserver(SSL* key_sock, SSL* gmail_sock, const string& username,
                                 const string& session_token, const string& new_share1);
bool update_share2_on_recoveryserver(SSL* gmail_sock, const string& username, const string& session_token,
                                      const string& new_share2);

// recover_account_flow: interactive account-recovery mode entered when the
//   user has lost their device / password but can authenticate to both the
//   Key Server (via a fresh Gmail session) and the Recovery Server.
//   On success: returns a fully-reconstructed EVP_PKEY* and also saves a
//   new Share3 file encrypted with the current session password.
//   On failure: returns nullptr.
//   Phase 2: now also takes gmail_sock, threaded through to the
//   fetch/update calls inside, each of which requests its own
//   single-use Operation Token immediately before use.
EVP_PKEY* recover_account_flow(SSL* key_sock,
                                SSL* gmail_sock,
                                const string& username,
                                const string& session_token,
                                const string& password);
// Base64 encode
string base64_encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, buffer, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);

    string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);
    return encoded;
}

// Base64 decode
string base64_decode(const string &encoded) {
    BIO *bio, *b64;
    char* buffer = new char[encoded.size()];
    memset(buffer, 0, encoded.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.c_str(), -1);
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    int decoded_size = BIO_read(b64, buffer, encoded.size());
    string decoded(buffer, decoded_size);

    BIO_free_all(b64);
    delete[] buffer;
    return decoded;
}

// ---- One-Time Operation Tokens (Phase 2) ----
// Requests a short-lived, single-use Operation Token from Gmail Server,
// scoped to (operation, target_service), over the already-open gmail_sock
// connection (the same authenticated connection authenticate_with_gmail_server
// used). Must be called immediately before the share-related call it's
// for, since these tokens are short-lived by design.
//
// Wire format sent: "REQUEST_OP_TOKEN\n<operation>\n<target_service>\n"
// Expected response: "OP_TOKEN\n<op_token>\n" on success, or an
// "ERROR:...\n" line on failure. Returns "" on any failure - callers must
// check for an empty result before proceeding with the share operation.
string request_operation_token(SSL* gmail_sock, const string& operation, const string& target_service) {
    string req = "REQUEST_OP_TOKEN\n" + operation + "\n" + target_service + "\n";
    if (tls_send(gmail_sock, req.c_str(), req.size()) <= 0) {
        cerr << "[OPTOKEN] Failed to send REQUEST_OP_TOKEN to Gmail Server" << endl;
        return "";
    }

    string status = tls_read_line(gmail_sock);
    if (status != "OP_TOKEN") {
        cerr << "[OPTOKEN] Gmail Server did not issue an operation token for "
             << operation << "/" << target_service << ": " << status << endl;
        return "";
    }

    string op_token = tls_read_line(gmail_sock);
    if (op_token.empty()) {
        cerr << "[OPTOKEN] Gmail Server sent an empty operation token" << endl;
        return "";
    }
    return op_token;
}

// Verify signature using EVP API
bool verify_signature(const unsigned char* signature, size_t sig_len, 
                     const unsigned char* data, size_t data_len, EVP_PKEY* pub_key) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub_key) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int result = EVP_DigestVerifyFinal(ctx, signature, sig_len);
    EVP_MD_CTX_free(ctx);

    return (result == 1);
}

// Generate HMAC
vector<unsigned char> generate_HMAC(const unsigned char* data, size_t data_len, 
                                  const unsigned char* key, size_t key_len) {
    vector<unsigned char> hmac(EVP_MAX_MD_SIZE);
    unsigned int hmac_len;
    
    // Use the full key for HMAC generation
    HMAC(EVP_sha256(), key, key_len, data, data_len, hmac.data(), &hmac_len);
    
    hmac.resize(hmac_len);
    return hmac;
}

// AES encrypt/decrypt
vector<unsigned char> aes_crypt(const unsigned char* input, size_t length,
                              const unsigned char* key, const unsigned char* iv,
                              bool encrypt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> output(length + AES_BLOCK_SIZE);
    int out_len, final_len;

    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, encrypt);
    EVP_CipherUpdate(ctx, output.data(), &out_len, input, length);
    EVP_CipherFinal_ex(ctx, output.data() + out_len, &final_len);
    output.resize(out_len + final_len);
    
    EVP_CIPHER_CTX_free(ctx);
    return output;
}

// Generate RSA keys using EVP API
EVP_PKEY* generate_keys() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Build the per-client private key filename
string private_key_filename(const string& client_id) {
    return client_id + "_private_key.pem";
}

// Save a private key to disk, encrypted with the given passphrase
// (AES-256-CBC PEM encryption, via OpenSSL's standard PEM_write_bio_PrivateKey).
bool save_private_key(EVP_PKEY* pkey, const string& client_id, const string& passphrase) {
    string filename = private_key_filename(client_id);
    BIO* bio = BIO_new_file(filename.c_str(), "w");
    if (!bio) {
        cerr << "ERROR: Could not open " << filename << " for writing" << endl;
        return false;
    }

    // EVP_aes_256_cbc() encrypts the PEM body; passphrase is supplied directly
    // (no interactive callback) since we already have it from Gmail login.
    int result = PEM_write_bio_PrivateKey(
        bio, pkey, EVP_aes_256_cbc(),
        (unsigned char*)passphrase.c_str(), (int)passphrase.size(),
        nullptr, nullptr);

    BIO_free(bio);

    if (result != 1) {
        cerr << "ERROR: Failed to write encrypted private key to " << filename << endl;
        return false;
    }

    cout << "[STATUS] Private key saved (encrypted) to " << filename << endl;
    return true;
}

// Load a private key from disk, decrypting with the given passphrase.
// Returns nullptr if the file doesn't exist or the passphrase is wrong.
EVP_PKEY* load_private_key(const string& client_id, const string& passphrase) {
    string filename = private_key_filename(client_id);
    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) {
        return nullptr; // file doesn't exist - not an error, caller should generate a new key
    }

    // Pass the passphrase directly as the callback "userdata" with a null
    // callback - OpenSSL then treats it as the literal passphrase string.
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(
        bio, nullptr, nullptr, (void*)passphrase.c_str());

    BIO_free(bio);

    if (!pkey) {
        cerr << "ERROR: Failed to decrypt private key in " << filename
             << " (wrong passphrase or corrupted file)" << endl;
        return nullptr;
    }

    cout << "[STATUS] Loaded existing private key from " << filename << endl;
    return pkey;
}

// Check if a key file exists; load it if so, otherwise generate a new one
// and save it. This is the single entry point main() should call.
EVP_PKEY* load_or_generate_keys(const string& client_id, const string& passphrase) {
    // Quick existence check first, so a missing file never gets logged as a
    // decryption failure.
    string filename = private_key_filename(client_id);
    ifstream check(filename);
    bool exists = check.good();
    check.close();

    if (exists) {
        EVP_PKEY* pkey = load_private_key(client_id, passphrase);
        if (pkey) {
            return pkey;
        }
        // File exists but couldn't be loaded (wrong password / corrupted).
        // Do NOT silently generate a new key here - that would orphan the
        // existing identity. Surface the failure to the caller instead.
        cerr << "ERROR: Existing key file found but could not be decrypted. "
             << "Check your password." << endl;
        return nullptr;
    }

    cout << "[STATUS] No existing key found for " << client_id
         << " - generating a new key pair." << endl;
    EVP_PKEY* pkey = generate_keys();
    if (!pkey) {
        cerr << "ERROR: Key generation failed" << endl;
        return nullptr;
    }

    if (!save_private_key(pkey, client_id, passphrase)) {
        cerr << "WARNING: Generated key but failed to save it to disk. "
             << "It will not persist after this session." << endl;
    }

    // ----- Task 3: Shamir split (runs alongside existing key save) -----
    // Export the private key to a PEM string, split it into 3 shares.
    // Shares are stored now; the caller (main) will push Share1 and Share2
    // to their respective servers right after this function returns.
    // We store Share3 locally here because we already have the passphrase.
    string pem = export_private_key_to_pem(pkey);
    if (pem.empty()) {
        cerr << "[SHAMIR] WARNING: Could not export private key to PEM for splitting. "
             << "Shares will NOT be stored this session." << endl;
    } else {
        vector<string> shares = split_private_key(pem);
        if (shares.size() != 3) {
            cerr << "[SHAMIR] WARNING: split_private_key() failed. "
                 << "Shares will NOT be stored this session." << endl;
        } else {
            // Save Share3 locally right now (we have the passphrase here).
            // Share1 and Share2 are stored by main() after authentication,
            // because the key_sock / recovery_sock are not in scope here.
            // We stash them in a temporary file for main() to pick up.
            if (!save_local_share3(client_id, passphrase, shares[2])) {
                cerr << "[SHAMIR] WARNING: Failed to save Share3 locally." << endl;
            }

            // Write Share1 and Share2 to temp files so main() can upload them.
            // These are short-lived; main() deletes them after upload.
            {
                ofstream s1f(client_id + "_share1.tmp", ios::binary | ios::trunc);
                if (s1f) s1f.write(shares[0].data(), shares[0].size());
            }
            {
                ofstream s2f(client_id + "_share2.tmp", ios::binary | ios::trunc);
                if (s2f) s2f.write(shares[1].data(), shares[1].size());
            }
            cout << "[SHAMIR] Private key split into 3 shares. "
                 << "Share3 saved locally. Share1/Share2 queued for upload." << endl;
        }
    }
    // ----- end Task 3 block -----

    return pkey;
}

// Get public key as string
string get_public_key_string(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    
    char* key_data;
    long key_len = BIO_get_mem_data(bio, &key_data);
    string public_key(key_data, key_len);
    
    BIO_free(bio);
    return public_key;
}

// Export a private key to an unencrypted PEM string in memory.
// This is the string we hand to split_private_key() — it never touches disk
// in this raw form.
string export_private_key_to_pem(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    // No cipher, no passphrase — we are splitting it ourselves via Shamir.
    if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bio);
        return "";
    }

    char* data;
    long len = BIO_get_mem_data(bio, &data);
    string pem(data, len);
    BIO_free(bio);
    return pem;
}

// Send Share1 to Key Server using command byte '3'.
// Wire format: '3' then "STORE_SHARE1|username|session_token|op_token|<share_bytes>"
// Phase 2: requests a single-use Operation Token from Gmail Server
// (gmail_sock) scoped to (STORE_SHARE1, KEYSERVER) immediately before
// sending, and appends it as a new field - additive to the existing
// session_token check Key Server already performs.
bool store_share1_on_keyserver(SSL* key_sock,
                                SSL* gmail_sock,
                                const string& username,
                                const string& session_token,
                                const string& share1) {
    string op_token = request_operation_token(gmail_sock, "STORE_SHARE1", "KEYSERVER");
    if (op_token.empty()) {
        cerr << "[SHARE1] Could not obtain operation token for STORE_SHARE1" << endl;
        return false;
    }

    // Send command selector
    if (tls_send(key_sock, "3", 1) <= 0) {
        cerr << "[SHARE1] Failed to send command byte to Key Server" << endl;
        return false;
    }

    string payload = "STORE_SHARE1|" + username + "|" + session_token + "|" + op_token + "|" + share1;
    if (tls_send(key_sock, payload.data(), payload.size()) <= 0) {
        cerr << "[SHARE1] Failed to send Share1 payload to Key Server" << endl;
        return false;
    }

    char buf[256] = {0};
    int bytes = tls_recv(key_sock, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        cerr << "[SHARE1] No response from Key Server for STORE_SHARE1" << endl;
        return false;
    }
    string resp(buf, bytes);
    if (resp == "SHARE1_STORED") {
        cout << "[SHARE1] Key Server confirmed Share1 stored." << endl;
        return true;
    }
    cerr << "[SHARE1] Key Server response: " << resp << endl;
    return false;
}

// Replace an already-stored Share1 on the Key Server.
// Used only during account recovery, where a fresh split() produces a new
// Share1/Share2/Share3 triple together - the old Share1 (from registration
// or a previous recovery) must be replaced with the new one from THIS
// split, or it will silently stop matching the new Share2/Share3 and the
// next login (Share1 + Share3) will fail with an unparseable PEM.
// Wire format matches keyserver.cpp's updateShare1: command byte '5', then
// "UPDATE_SHARE1|username|session_token|op_token|<share1_bytes>".
bool update_share1_on_keyserver(SSL* key_sock,
                                 SSL* gmail_sock,
                                 const string& username,
                                 const string& session_token,
                                 const string& new_share1) {
    string op_token = request_operation_token(gmail_sock, "UPDATE_SHARE1", "KEYSERVER");
    if (op_token.empty()) {
        cerr << "[SHARE1] Could not obtain operation token for UPDATE_SHARE1" << endl;
        return false;
    }

    if (tls_send(key_sock, "5", 1) <= 0) {
        cerr << "[SHARE1] Failed to send command byte to Key Server" << endl;
        return false;
    }

    string payload = "UPDATE_SHARE1|" + username + "|" + session_token + "|" + op_token + "|" + new_share1;
    if (tls_send(key_sock, payload.data(), payload.size()) <= 0) {
        cerr << "[SHARE1] Failed to send UPDATE_SHARE1 payload to Key Server" << endl;
        return false;
    }

    char buf[256] = {0};
    int bytes = tls_recv(key_sock, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        cerr << "[SHARE1] No response from Key Server for UPDATE_SHARE1" << endl;
        return false;
    }
    string resp(buf, bytes);
    if (resp == "SHARE1_UPDATED") {
        cout << "[SHARE1] Key Server confirmed Share1 updated." << endl;
        return true;
    }
    cerr << "[SHARE1] Key Server response: " << resp << endl;
    return false;
}

// Send Share2 to Recovery Server.
// Wire format matches recovery_server.cpp: "STORE_SHARE|username|session_token|op_token|<share_bytes>"
// Recovery Server now verifies session_token against Gmail Server's VERIFY
// port before accepting Share2 - same authentication guarantee Share1 has
// on Key Server. Phase 2 additionally requires a single-use Operation
// Token scoped to (STORE_SHARE2, RECOVERYSERVER).
bool store_share2_on_recoveryserver(SSL* gmail_sock, const string& username, const string& session_token, const string& share2) {
    string op_token = request_operation_token(gmail_sock, "STORE_SHARE2", "RECOVERYSERVER");
    if (op_token.empty()) {
        cerr << "[SHARE2] Could not obtain operation token for STORE_SHARE2" << endl;
        return false;
    }

    SSL* ssl = tls_client_connect(RECOVERY_SERVER_IP, RECOVERY_SERVER_PORT, g_client_ctx);
    if (!ssl) {
        cerr << "[SHARE2] Could not connect to Recovery Server on port "
             << RECOVERY_SERVER_PORT << endl;
        return false;
    }

    string payload = "STORE_SHARE|" + username + "|" + session_token + "|" + op_token + "|" + share2;
    if (tls_send(ssl, payload.data(), payload.size()) <= 0) {
        cerr << "[SHARE2] Failed to send Share2 to Recovery Server" << endl;
        tls_close(ssl);
        return false;
    }

    char buf[256] = {0};
    int bytes = tls_recv(ssl, buf, sizeof(buf) - 1);
    tls_close(ssl);

    if (bytes <= 0) {
        cerr << "[SHARE2] No response from Recovery Server" << endl;
        return false;
    }
    string resp(buf, bytes);
    if (resp == "SHARE_STORED") {
        cout << "[SHARE2] Recovery Server confirmed Share2 stored." << endl;
        return true;
    }
    cerr << "[SHARE2] Recovery Server response: " << resp << endl;
    return false;
}

// Replace an already-stored Share2 on the Recovery Server.
// Used only during account recovery, where a fresh split() produces a new
// Share1/Share2/Share3 triple together - the old Share2 (from registration
// or a previous recovery) must be replaced with the new one from THIS
// split, or it will silently stop matching the new Share1/Share3 and the
// next login (Share1 + Share3) will fail with an unparseable PEM.
// Wire format matches recovery_server.cpp's updateShare:
// "UPDATE_SHARE|username|session_token|op_token|<share2_bytes>".
bool update_share2_on_recoveryserver(SSL* gmail_sock,
                                      const string& username,
                                      const string& session_token,
                                      const string& new_share2) {
    string op_token = request_operation_token(gmail_sock, "UPDATE_SHARE2", "RECOVERYSERVER");
    if (op_token.empty()) {
        cerr << "[SHARE2] Could not obtain operation token for UPDATE_SHARE2" << endl;
        return false;
    }

    SSL* ssl = tls_client_connect(RECOVERY_SERVER_IP, RECOVERY_SERVER_PORT, g_client_ctx);
    if (!ssl) {
        cerr << "[SHARE2] Could not connect to Recovery Server on port "
             << RECOVERY_SERVER_PORT << endl;
        return false;
    }

    string payload = "UPDATE_SHARE|" + username + "|" + session_token + "|" + op_token + "|" + new_share2;
    if (tls_send(ssl, payload.data(), payload.size()) <= 0) {
        cerr << "[SHARE2] Failed to send UPDATE_SHARE to Recovery Server" << endl;
        tls_close(ssl);
        return false;
    }

    char buf[256] = {0};
    int bytes = tls_recv(ssl, buf, sizeof(buf) - 1);
    tls_close(ssl);

    if (bytes <= 0) {
        cerr << "[SHARE2] No response from Recovery Server for UPDATE_SHARE" << endl;
        return false;
    }
    string resp(buf, bytes);
    if (resp == "SHARE_UPDATED") {
        cout << "[SHARE2] Recovery Server confirmed Share2 updated." << endl;
        return true;
    }
    cerr << "[SHARE2] Recovery Server response: " << resp << endl;
    return false;
}


// Encrypt Share3 with an Argon2id-derived key and save to <username>_share3.enc.
//
// File layout (all binary, concatenated):
//   [16 bytes: Argon2id salt]
//   [16 bytes: AES-256-CBC IV]
//   [N bytes:  AES-256-CBC ciphertext of share3]
//
// The Argon2id input is: password + username + PEPPER
// This matches the architecture doc's "password + username + pepper -> Share3".
bool save_local_share3(const string& username,
                        const string& password,
                        const string& share3) {
    // Generate fresh random salt (16 bytes is fine; crypto_pwhash needs >= 16)
    unsigned char salt[crypto_pwhash_SALTBYTES];   // 16 bytes
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        cerr << "[SHARE3] Failed to generate salt" << endl;
        return false;
    }

    // Build the Argon2id input: password + username + pepper
    string kdf_input = password + username + SHARE3_PEPPER;

    // Derive a 32-byte AES key via Argon2id
    unsigned char aes_key[AES_KEY_SIZE];
    if (crypto_pwhash(
            aes_key, sizeof(aes_key),
            kdf_input.c_str(), kdf_input.size(),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        cerr << "[SHARE3] Argon2id key derivation failed (out of memory?)" << endl;
        return false;
    }

    // Generate random AES IV
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        cerr << "[SHARE3] Failed to generate AES IV" << endl;
        return false;
    }

    // AES-256-CBC encrypt Share3
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    vector<unsigned char> ciphertext(share3.size() + AES_BLOCK_SIZE);
    int out_len = 0, final_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key, iv) != 1 ||
        EVP_EncryptUpdate(ctx,
            ciphertext.data(), &out_len,
            reinterpret_cast<const unsigned char*>(share3.data()),
            (int)share3.size()) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1) {
        cerr << "[SHARE3] AES encryption of Share3 failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(out_len + final_len);

    // Write salt || IV || ciphertext
    string filename = username + "_share3.enc";
    ofstream f(filename, ios::binary | ios::trunc);
    if (!f.is_open()) {
        cerr << "[SHARE3] Could not open " << filename << " for writing" << endl;
        return false;
    }
    f.write(reinterpret_cast<char*>(salt),        sizeof(salt));
    f.write(reinterpret_cast<char*>(iv),          sizeof(iv));
    f.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    f.close();

    cout << "[SHARE3] Share3 encrypted and saved to " << filename << endl;
    return true;
}

// ----- Task 4: helpers for login reconstruction -----

// Decrypt Share3 from <username>_share3.enc and return the raw share bytes.
// File layout (written by save_local_share3):
//   [16 bytes: Argon2id salt]
//   [16 bytes: AES-256-CBC IV]
//   [N bytes:  AES-256-CBC ciphertext]
//
// Returns an empty string on any failure (file missing, wrong password, etc.).
string load_local_share3(const string& username, const string& password) {
    string filename = username + "_share3.enc";
    ifstream f(filename, ios::binary);
    if (!f.is_open()) {
        cerr << "[SHARE3] Share3 file not found: " << filename << endl;
        return "";
    }

    // Read salt (16 bytes)
    unsigned char salt[crypto_pwhash_SALTBYTES];
    if (!f.read(reinterpret_cast<char*>(salt), sizeof(salt))) {
        cerr << "[SHARE3] Failed to read salt from " << filename << endl;
        return "";
    }

    // Read IV (16 bytes)
    unsigned char iv[AES_BLOCK_SIZE];
    if (!f.read(reinterpret_cast<char*>(iv), sizeof(iv))) {
        cerr << "[SHARE3] Failed to read IV from " << filename << endl;
        return "";
    }

    // Read ciphertext (remainder of file)
    ostringstream ss;
    ss << f.rdbuf();
    string ciphertext_str = ss.str();
    f.close();

    if (ciphertext_str.empty()) {
        cerr << "[SHARE3] Ciphertext is empty in " << filename << endl;
        return "";
    }

    // Re-derive the AES key using the same Argon2id inputs as save_local_share3
    string kdf_input = password + username + SHARE3_PEPPER;
    unsigned char aes_key[AES_KEY_SIZE];
    if (crypto_pwhash(
            aes_key, sizeof(aes_key),
            kdf_input.c_str(), kdf_input.size(),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        cerr << "[SHARE3] Argon2id key derivation failed (out of memory?)" << endl;
        return "";
    }

    // AES-256-CBC decrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    vector<unsigned char> plaintext(ciphertext_str.size() + AES_BLOCK_SIZE);
    int out_len = 0, final_len = 0;

    bool ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key, iv) == 1 &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
            reinterpret_cast<const unsigned char*>(ciphertext_str.data()),
            (int)ciphertext_str.size()) == 1 &&
        EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) == 1;

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        cerr << "[SHARE3] AES decryption of Share3 failed (wrong password?)" << endl;
        return "";
    }

    cout << "[SHARE3] Share3 decrypted successfully." << endl;
    return string(reinterpret_cast<char*>(plaintext.data()), out_len + final_len);
}

// Ask Key Server for Share1 using command byte '4' and FETCH_SHARE1 protocol.
// Wire format sent: '4' then "FETCH_SHARE1|username|session_token|op_token"
// Returns the raw Share1 bytes on success, or empty string on failure.
// Phase 2: requests a single-use Operation Token from Gmail Server
// (gmail_sock) scoped to (FETCH_SHARE1, KEYSERVER) immediately before
// sending, and appends it as a new field.
string fetch_share1_from_keyserver(SSL* key_sock,
                                    SSL* gmail_sock,
                                    const string& username,
                                    const string& session_token) {
    string op_token = request_operation_token(gmail_sock, "FETCH_SHARE1", "KEYSERVER");
    if (op_token.empty()) {
        cerr << "[SHARE1] Could not obtain operation token for FETCH_SHARE1" << endl;
        return "";
    }

    // Send command selector
    if (tls_send(key_sock, "4", 1) <= 0) {
        cerr << "[SHARE1] Failed to send command byte '4' to Key Server" << endl;
        return "";
    }

    string payload = "FETCH_SHARE1|" + username + "|" + session_token + "|" + op_token;
    if (tls_send(key_sock, payload.data(), payload.size()) <= 0) {
        cerr << "[SHARE1] Failed to send FETCH_SHARE1 payload" << endl;
        return "";
    }

    // Receive the raw share bytes (Key Server sends them back without base64)
    // Use a large buffer; shares are ~PEM length + 1 byte header (~1800 bytes)
    vector<char> buf(8192, 0);
    int bytes = tls_recv(key_sock, buf.data(), buf.size() - 1);
    if (bytes <= 0) {
        cerr << "[SHARE1] No response from Key Server for FETCH_SHARE1" << endl;
        return "";
    }

    string response(buf.data(), bytes);

    // Check for known error responses (they are short ASCII strings)
    if (response == "INVALID_FORMAT"  || response == "EMPTY_FIELDS"         ||
        response == "RECV_ERROR"      || response == "IDENTITY_VERIFICATION_FAILED" ||
        response == "OP_TOKEN_VERIFICATION_FAILED" ||
        response == "SHARE1_NOT_FOUND") {
        cerr << "[SHARE1] Key Server error: " << response << endl;
        return "";
    }

    cout << "[SHARE1] Received Share1 from Key Server (" << bytes << " bytes)." << endl;
    return response;
}

// Convert a raw PEM string (as returned by reconstruct_private_key) back into
// an EVP_PKEY* that OpenSSL can use for signing and decryption.
// Returns nullptr on failure (caller should fall back to the legacy key file).
EVP_PKEY* pem_string_to_evp_pkey(const string& pem) {
    if (pem.empty()) return nullptr;

    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    if (!bio) return nullptr;

    // No passphrase — the PEM written by export_private_key_to_pem() is unencrypted.
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        cerr << "[SHAMIR] Failed to parse reconstructed PEM into EVP_PKEY" << endl;
        return nullptr;
    }

    cout << "[SHAMIR] Reconstructed private key parsed into EVP_PKEY successfully." << endl;
    return pkey;
}

// ----- end Task 4 helpers -----

// Register with key server
// Now includes the session token GmailServer issued at login/signup, so
// KeyServer can confirm with GmailServer that this client really is client_id.
void register_with_key_server(SSL* key_sock, const string& client_id, EVP_PKEY* pkey, const string& session_token) {
    string pub_key = get_public_key_string(pkey);
    string msg = client_id + "|" + session_token + "|" + pub_key;
    
    tls_send(key_sock, "1", 1);
    tls_send(key_sock, msg.c_str(), msg.size());
    
    char buffer[BUFFER_SIZE] = {0};
    int bytes = tls_recv(key_sock, buffer, BUFFER_SIZE);
    if (bytes > 0) {
        buffer[bytes] = '\0';
    }
    cout << "Key Server: " << buffer << endl;
}

// Load Key Server's public key
EVP_PKEY* loadKeyServerPublicKey() {
    BIO* bio = BIO_new_file("keyserver_public.pem", "r");
    if (!bio) return NULL;
    
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

// Get recipient's public key


EVP_PKEY* get_recipient_pubkey(SSL* key_sock, const string& recipient_id) {
    cout << "[DEBUG] Starting key request for " << recipient_id << endl;
    
    // Send request type
    if (tls_send(key_sock, "2", 1) <= 0) {
        cerr << "[ERROR] Failed to send request type to key server" << endl;
        return nullptr;
    }

    // Send recipient ID
    string request = "REQUEST_KEY|" + recipient_id;
    if (tls_send(key_sock, request.c_str(), request.size()) <= 0) {
        cerr << "[ERROR] Failed to send recipient ID to key server" << endl;
        return nullptr;
    }

    // Set receive timeout (5 seconds)
    tls_set_recv_timeout(key_sock, 5);

    // Receive response
    char buffer[BUFFER_SIZE] = {0};
    int bytes = tls_recv(key_sock, buffer, BUFFER_SIZE);
    if (bytes <= 0) {
        cerr << "[ERROR] No response from key server (timeout or error)" << endl;
        return nullptr;
    }

    string response(buffer, bytes);
    cout << "[DEBUG] Raw response from key server: " << response << endl;

    size_t delim = response.find("|");
    if (delim == string::npos) {
        cerr << "[ERROR] Invalid response format from key server" << endl;
        return nullptr;
    }

    string pub_key_pem = response.substr(0, delim);
    string signature_b64 = response.substr(delim + 1);

    // Verify signature
    EVP_PKEY* key_server_pub = loadKeyServerPublicKey();
    if (!key_server_pub) {
        cerr << "[ERROR] Failed to load key server's public key" << endl;
        return nullptr;
    }

    string signature = base64_decode(signature_b64);
    if (!verify_signature((unsigned char*)signature.c_str(), signature.size(),
                         (unsigned char*)pub_key_pem.c_str(), pub_key_pem.size(),
                         key_server_pub)) {
        cerr << "[ERROR] Signature verification failed" << endl;
        EVP_PKEY_free(key_server_pub);
        return nullptr;
    }
    cout<<"Signature verified"<<endl;
    EVP_PKEY_free(key_server_pub);

    // Load recipient's public key
    BIO* bio = BIO_new_mem_buf(pub_key_pem.c_str(), -1);
    if (!bio) {
        cerr << "[ERROR] Failed to create BIO for public key" << endl;
        return nullptr;
    }

    EVP_PKEY* pub_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pub_key) {
        cerr << "[ERROR] Failed to parse recipient's public key" << endl;
        return nullptr;
    }

    cout << "[DEBUG] Successfully retrieved public key for " << recipient_id << endl;
    return pub_key;
}

// Authenticate with Gmail server
// Returns the session token GmailServer issues on success (empty string on failure).
// out_password is filled with the password the user typed, so callers can
// reuse it to encrypt/decrypt the local private key file.
string authenticate_with_gmail_server(SSL* gmail_sock, string& out_password) {
    while (true) {
        cout << "1. Login\n2. Signup\nChoice: ";
        int choice;
        cin >> choice;
        cin.ignore();

        string username, password;
        cout << "Username: ";
        getline(cin, username);
        cout << "Password: ";
        getline(cin, password);

        // Send as single delimited message
        string message = to_string(choice) + "\n" + username + "\n" + password + "\n";
        tls_send(gmail_sock, message.c_str(), message.size());
        
        // Receive response
        char response[BUFFER_SIZE] = {0};
        int bytes = tls_recv(gmail_sock, response, BUFFER_SIZE);
        if (bytes <= 0) {
            cout << "Server disconnected\n";
            return "";
        }
        
        string responseStr(response, bytes);
        size_t first_nl = responseStr.find('\n');
        string status = responseStr.substr(0, first_nl);

        if (status == "AUTH_SUCCESS") {
            string token;
            if (first_nl != string::npos) {
                size_t second_nl = responseStr.find('\n', first_nl + 1);
                token = responseStr.substr(first_nl + 1,
                            (second_nl == string::npos) ? string::npos : second_nl - first_nl - 1);
            }
            if (token.empty()) {
                cerr << "[WARNING] AUTH_SUCCESS received but no session token found\n";
            }
            out_password = password;
            cout << "Authentication successful\n";
            return token;
        } else {
            cout << "Authentication failed: " << responseStr << endl;
        }
    }
}
//send mail
void send_email(SSL* gmail_sock, SSL* key_sock, EVP_PKEY* pkey, const string& sender_id) {
    // Validate connections
    if (!gmail_sock || !key_sock) {
        cerr << "ERROR: Invalid server connections" << endl;
        return;
    }

    // Get recipient ID
    string recipient_id;
    cout << "Recipient ID: ";
    if (!(cin >> recipient_id)) {
        cerr << "ERROR: Invalid recipient ID input" << endl;
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        return;
    }
    cin.ignore(); // Clear newline

    // Get recipient's public key
    EVP_PKEY* recipient_pub = get_recipient_pubkey(key_sock, recipient_id);
    if (!recipient_pub) {
        cerr << "\nERROR: Could not retrieve public key for " << recipient_id << endl;
        cerr << "Please verify:\n";
        cerr << "1. The recipient '" << recipient_id << "' exists\n";
        cerr << "2. The key server is running\n";
        cerr << "3. The network connection is working\n\n";
        cout << "Press Enter to return to main menu...";
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        return;
    }

    // Generate session key and IV
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(aes_key, AES_KEY_SIZE) != 1 || RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        cerr << "ERROR: Failed to generate cryptographic keys" << endl;
        EVP_PKEY_free(recipient_pub);
        return;
    }

    // Get message content and add timestamp
    string message;
    cout << "Message: ";
    getline(cin, message);

    if (message.empty()) {
        cerr << "ERROR: Message cannot be empty" << endl;
        EVP_PKEY_free(recipient_pub);
        return;
    }

    // Add timestamp to message
    time_t now = time(0);
    string timestamp = "Time: " + string(ctime(&now));
    timestamp.erase(timestamp.find_last_not_of("\n") + 1); // Remove newline
    string message_with_timestamp = timestamp + "\n" + message;

    // Encrypt the message with timestamp
    vector<unsigned char> encrypted_msg = aes_crypt(
        (unsigned char*)message_with_timestamp.c_str(), 
        message_with_timestamp.size(), 
        aes_key, 
        iv, 
        true);

    // Generate HMAC now includes timestamp
    vector<unsigned char> hmac = generate_HMAC(
        encrypted_msg.data(), encrypted_msg.size(), aes_key, AES_KEY_SIZE);

    // Sign the HMAC
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    size_t sig_len;
    vector<unsigned char> signed_hmac;

    if (!md_ctx || 
        EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0 ||
        EVP_DigestSignUpdate(md_ctx, hmac.data(), hmac.size()) <= 0 ||
        EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) <= 0) {
        cerr << "ERROR: Failed to sign HMAC" << endl;
        if (md_ctx) EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(recipient_pub);
        return;
    }

    signed_hmac.resize(sig_len);
    if (EVP_DigestSignFinal(md_ctx, signed_hmac.data(), &sig_len) <= 0) {
        cerr << "ERROR: Failed to finalize HMAC signature" << endl;
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(recipient_pub);
        return;
    }
    EVP_MD_CTX_free(md_ctx);

    // Encrypt the session key
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(recipient_pub, nullptr);
    size_t enc_key_len;
    vector<unsigned char> encrypted_key;

    if (!ctx ||
        EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_encrypt(ctx, nullptr, &enc_key_len, aes_key, AES_KEY_SIZE) <= 0) {
        cerr << "ERROR: Failed to initialize key encryption" << endl;
        if (ctx) EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(recipient_pub);
        return;
    }

    encrypted_key.resize(enc_key_len);
    if (EVP_PKEY_encrypt(ctx, encrypted_key.data(), &enc_key_len, aes_key, AES_KEY_SIZE) <= 0) {
        cerr << "ERROR: Failed to encrypt session key" << endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(recipient_pub);
        return;
    }
    EVP_PKEY_CTX_free(ctx);

    // Sign the encrypted key
    md_ctx = EVP_MD_CTX_new();
    vector<unsigned char> signed_key;

    if (!md_ctx ||
        EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0 ||
        EVP_DigestSignUpdate(md_ctx, encrypted_key.data(), encrypted_key.size()) <= 0 ||
        EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) <= 0) {
        cerr << "ERROR: Failed to sign encrypted key" << endl;
        if (md_ctx) EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(recipient_pub);
        return;
    }

    signed_key.resize(sig_len);
    if (EVP_DigestSignFinal(md_ctx, signed_key.data(), &sig_len) <= 0) {
        cerr << "ERROR: Failed to finalize key signature" << endl;
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(recipient_pub);
        return;
    }
    EVP_MD_CTX_free(md_ctx);

    // Prepare the complete email packet (now with 7 parts including IV)
    string packet = sender_id + "~" +
                   base64_encode(iv, AES_BLOCK_SIZE) + "~" +
                   base64_encode(encrypted_msg.data(), encrypted_msg.size()) + "~" +
                   base64_encode(hmac.data(), hmac.size()) + "~" +
                   base64_encode(signed_hmac.data(), signed_hmac.size()) + "~" +
                   base64_encode(encrypted_key.data(), encrypted_key.size()) + "~" +
                   base64_encode(signed_key.data(), signed_key.size());

    // Prepare the complete message to send
    string complete_message = "EMAIL_SEND\n" + recipient_id + "\n" + packet + "\nEND_TRANSMISSION\n";

    if (tls_send(gmail_sock, complete_message.c_str(), complete_message.size()) <= 0) {
        cerr << "ERROR: Failed to send email data" << endl;
        EVP_PKEY_free(recipient_pub);
        return;
    }

    // Wait for response
    char response[BUFFER_SIZE] = {0};
    int bytes_received = tls_recv(gmail_sock, response, BUFFER_SIZE);
    if (bytes_received <= 0) {
        cerr << "ERROR: No response from server" << endl;
    } else {
        response[bytes_received] = '\0';
        cout << "Server response: " << response << endl;
    }

    EVP_PKEY_free(recipient_pub);
}

// Receive emails
void receive_emails(SSL* gmail_sock, SSL* key_sock, EVP_PKEY* pkey, const string& client_id) {
    // Send retrieve command with terminator
    string command = "4\n";
    if (tls_send(gmail_sock, command.c_str(), command.size()) <= 0) {
        cerr << "ERROR: Failed to send retrieve command\n";
        return;
    }

    // Set receive timeout (5 seconds)
    tls_set_recv_timeout(gmail_sock, 5);

    // Receive all email data
    string all_emails;
    char buffer[BUFFER_SIZE];
    while (true) {
        int bytes = tls_recv(gmail_sock, buffer, BUFFER_SIZE);
        if (bytes <= 0) break;
        
        all_emails.append(buffer, bytes);
        if (all_emails.find("---EMAIL_END---") != string::npos) {
            break;
        }
        if (all_emails.size() > MAX_EMAIL_SIZE) {
            cerr << "ERROR: Exceeded maximum email size\n";
            break;
        }
    }

    if (all_emails.empty()) {
        cout << "No emails received from server\n";
        return;
    }
     cout<<"email reeived succesfully:"<<endl;
    // Parse emails
    size_t pos = 0;
    while ((pos = all_emails.find("---EMAIL_END---")) != string::npos) {
        string email = all_emails.substr(0, pos);
        // Trim whitespace
        email.erase(email.find_last_not_of(" \n\r\t") + 1);
        if (!email.empty()) {
        
            process_email(email, key_sock, pkey);
        }
        all_emails.erase(0, pos + 15); // 15 is length of "---EMAIL_END---"
    }
}
void process_email(const string& email, SSL* key_sock, EVP_PKEY* pkey) {
    // Initial check
    if (email.empty() || email.find("No emails found") != string::npos) {
        cout << "[STATUS] No emails to process (empty or 'no emails' message)" << endl;
        cout << email << endl;
        return;
    }

    cout << "\n[STATUS] Starting email processing..." << endl;

    // Split email into parts
    vector<string> parts;
    size_t start = 0, end = email.find('~');
    while (end != string::npos) {
        string part = email.substr(start, end - start);
        // Trim whitespace from each part
        part.erase(0, part.find_first_not_of(" \t\n\r\f\v"));
        part.erase(part.find_last_not_of(" \t\n\r\f\v") + 1);
        parts.push_back(part);
        start = end + 1;
        end = email.find('~', start);
    }
    // Trim last part
    string last_part = email.substr(start);
    last_part.erase(0, last_part.find_first_not_of(" \t\n\r\f\v"));
    last_part.erase(last_part.find_last_not_of(" \t\n\r\f\v") + 1);
    parts.push_back(last_part);

    cout << "[DEBUG] Email split into " << parts.size() << " parts" << endl;

    // Validate structure
    if (parts.size() != 7) {
        cerr << "[ERROR] Invalid email format (expected 7 parts, got " << parts.size() << ")" << endl;
        cerr << "Raw email: " << email << endl;
        return;
    }

    cout << "[STATUS] Email structure validated successfully" << endl;

    try {
        // Extract and clean sender ID
        string sender_id = parts[0];
        sender_id.erase(0, sender_id.find_first_not_of(" \t\n\r\f\v"));
        sender_id.erase(sender_id.find_last_not_of(" \t\n\r\f\v") + 1);
        
        if (sender_id.empty()) {
            cerr << "[ERROR] Empty sender ID in email" << endl;
            return;
        }

        cout << "[INFO] Sender ID: " << sender_id << endl;
        // Base64 decoding
        cout << "[STATUS] Decoding Base64 components..." << endl;
        string iv = base64_decode(parts[1]);
        string enc_msg = base64_decode(parts[2]);
        string hmac = base64_decode(parts[3]);
        string signed_hmac = base64_decode(parts[4]);
        string enc_key = base64_decode(parts[5]);
        string signed_key = base64_decode(parts[6]);
        cout << "[STATUS] All components Base64 decoded successfully" << endl;

        // Get sender's public key
        cout << "[STATUS] Fetching sender's public key..." << endl;
        EVP_PKEY* sender_pub = get_recipient_pubkey(key_sock, sender_id);
        if (!sender_pub) {
            cerr << "[ERROR] Failed to get public key for " << sender_id << endl;
            return;
        }
        cout << "[STATUS] Sender's public key retrieved successfully" << endl;

        // Verify session key signature
        cout << "[STATUS] Verifying session key signature..." << endl;
        if (!verify_signature((unsigned char*)signed_key.c_str(), signed_key.size(),
                            (unsigned char*)enc_key.c_str(), enc_key.size(),
                            sender_pub)) {
            cerr << "[ERROR] Session key signature verification FAILED" << endl;
            EVP_PKEY_free(sender_pub);
            return;
        }
        cout << "[STATUS] Session key signature verified successfully" << endl;

        // Decrypt session key
        cout << "[STATUS] Decrypting session key..." << endl;
        size_t dec_key_len;
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_decrypt(ctx, NULL, &dec_key_len, 
                           (unsigned char*)enc_key.c_str(), enc_key.size()) <= 0) {
            cerr << "[ERROR] Session key decryption initialization failed" << endl;
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(sender_pub);
            return;
        }

        vector<unsigned char> aes_key(dec_key_len);
        if (EVP_PKEY_decrypt(ctx, aes_key.data(), &dec_key_len, 
                           (unsigned char*)enc_key.c_str(), enc_key.size()) <= 0) {
            cerr << "[ERROR] Session key decryption failed" << endl;
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(sender_pub);
            return;
        }
        EVP_PKEY_CTX_free(ctx);
        cout << "[STATUS] Session key decrypted successfully" << endl;

        // Verify HMAC signature
        cout << "[STATUS] Verifying HMAC signature..." << endl;
        if (!verify_signature((unsigned char*)signed_hmac.c_str(), signed_hmac.size(),
                            (unsigned char*)hmac.c_str(), hmac.size(),
                            sender_pub)) {
            cerr << "[ERROR] HMAC signature verification FAILED" << endl;
            EVP_PKEY_free(sender_pub);
            return;
        }
        cout << "[STATUS] HMAC signature verified successfully" << endl;

        // Verify HMAC integrity
        cout << "[STATUS] Verifying message integrity (HMAC)..." << endl;
        vector<unsigned char> computed_hmac = generate_HMAC(
            (unsigned char*)enc_msg.c_str(), enc_msg.size(), aes_key.data(), AES_KEY_SIZE);
        
        if (hmac.size() != computed_hmac.size() || 
            memcmp(hmac.data(), computed_hmac.data(), hmac.size()) != 0) {
            cerr << "[ERROR] HMAC mismatch - message tampering detected!" << endl;
            cerr << "Expected HMAC: ";
            for (auto b : computed_hmac) cerr << hex << setw(2) << setfill('0') << (int)b;
            cerr << "\nActual HMAC:   ";
            for (size_t i = 0; i < hmac.size(); i++) cerr << hex << setw(2) << setfill('0') << (int)hmac[i];
            cerr << dec << endl; // Reset to decimal
            EVP_PKEY_free(sender_pub);
            return;
        }
        cout << "[STATUS] Message integrity verified (HMAC matched)" << endl;

        // Decrypt message
        cout << "[STATUS] Decrypting message with session key and IV..." << endl;
        vector<unsigned char> decrypted = aes_crypt(
            (unsigned char*)enc_msg.c_str(), enc_msg.size(), 
            aes_key.data(), (unsigned char*)iv.c_str(), false);
        cout << "[STATUS] Message decrypted successfully" << endl;

        // Display final output with timestamp preserved
cout << "\n========================================" << endl;
cout << "From: " << sender_id << endl;

// Find the first newline to separate timestamp from message
string decrypted_str((char*)decrypted.data(), decrypted.size());
size_t timestamp_end = decrypted_str.find('\n');
if (timestamp_end != string::npos) {
    cout << decrypted_str.substr(0, timestamp_end) << endl; // Timestamp
    cout << "Message: " << decrypted_str.substr(timestamp_end + 1) << endl;
} else {
    cout << "Message: " << decrypted_str << endl;
}
cout << "========================================\n" << endl;

        EVP_PKEY_free(sender_pub);
        cout << "[STATUS] Email processing completed successfully" << endl;
    } catch (const exception& e) {
        cerr << "[CRITICAL ERROR] Exception: " << e.what() << endl;
    }
}

// ----- Task 5: Recovery Server fetch -----
// Connects to Recovery Server and asks for Share2 for the given username.
// Returns raw Share2 bytes on success, empty string on failure.
// Recovery Server now verifies session_token against Gmail Server's VERIFY
// port before handing out Share2 - matches Key Server's Share1 protection.
// Phase 2: requests a single-use Operation Token from Gmail Server
// (gmail_sock) scoped to (GET_SHARE, RECOVERYSERVER) immediately before
// sending, and appends it as a new field.
string fetch_share2_from_recoveryserver(SSL* gmail_sock, const string& username, const string& session_token) {
    string op_token = request_operation_token(gmail_sock, "GET_SHARE", "RECOVERYSERVER");
    if (op_token.empty()) {
        cerr << "[SHARE2] Could not obtain operation token for GET_SHARE" << endl;
        return "";
    }

    SSL* ssl = tls_client_connect(RECOVERY_SERVER_IP, RECOVERY_SERVER_PORT, g_client_ctx);
    if (!ssl) {
        cerr << "[SHARE2] Could not connect to Recovery Server on port "
             << RECOVERY_SERVER_PORT << endl;
        return "";
    }

    string payload = "GET_SHARE|" + username + "|" + session_token + "|" + op_token;
    if (tls_send(ssl, payload.data(), payload.size()) <= 0) {
        cerr << "[SHARE2] Failed to send GET_SHARE request" << endl;
        tls_close(ssl);
        return "";
    }

    // Share2 is ~PEM length + 1 header byte (~1800 bytes); 8 KB is plenty.
    vector<char> buf(8192, 0);
    int bytes = tls_recv(ssl, buf.data(), (int)buf.size() - 1);
    tls_close(ssl);

    if (bytes <= 0) {
        cerr << "[SHARE2] No response from Recovery Server" << endl;
        return "";
    }

    string response(buf.data(), bytes);
    // Check for known text error responses (all short ASCII)
    if (response == "INVALID_REQUEST" || response == "EMPTY_USERNAME" ||
        response == "SHARE_NOT_FOUND" || response == "INVALID_COMMAND" ||
        response == "IDENTITY_VERIFICATION_FAILED" ||
        response == "OP_TOKEN_VERIFICATION_FAILED") {
        cerr << "[SHARE2] Recovery Server error: " << response << endl;
        return "";
    }

    cout << "[SHARE2] Received Share2 from Recovery Server (" << bytes << " bytes)." << endl;
    return response;
}

// ----- Task 5: Full account-recovery flow -----
// Called from the main menu when the user chooses option 3.
//
// Flow:
//   1. Fetch Share1 from Key Server  (requires active Gmail session token)
//   2. Fetch Share2 from Recovery Server
//   3. reconstruct_private_key(share1, share2) -> PEM
//   4. pem_string_to_evp_pkey(PEM) -> EVP_PKEY*
//   5. Save a new Share3 encrypted with the current session password
//      (so normal Share1+Share3 login works again next time)
//
// Phase 2: gmail_sock is the already-authenticated connection to Gmail
// Server, threaded through to each fetch/update call below so each can
// request its own single-use Operation Token immediately before use.
//
// Returns a valid EVP_PKEY* on success, nullptr on any failure.
EVP_PKEY* recover_account_flow(SSL* key_sock,
                                SSL* gmail_sock,
                                const string& username,
                                const string& session_token,
                                const string& password) {
    cout << "[RECOVERY] Step 1/4: Fetching Share1 from Key Server...\n";
    string share1 = fetch_share1_from_keyserver(key_sock, gmail_sock, username, session_token);
    if (share1.empty()) {
        cerr << "[RECOVERY] Could not fetch Share1 from Key Server.\n";
        return nullptr;
    }
    cout << "[RECOVERY] Share1 obtained (" << share1.size() << " bytes).\n";

    cout << "[RECOVERY] Step 2/4: Fetching Share2 from Recovery Server...\n";
    string share2 = fetch_share2_from_recoveryserver(gmail_sock, username, session_token);
    if (share2.empty()) {
        cerr << "[RECOVERY] Could not fetch Share2 from Recovery Server.\n";
        return nullptr;
    }
    cout << "[RECOVERY] Share2 obtained (" << share2.size() << " bytes).\n";

    cout << "[RECOVERY] Step 3/4: Reconstructing private key from Share1 + Share2...\n";
    string recovered_pem = reconstruct_private_key(share1, share2);
    EVP_PKEY* recovered_pkey = pem_string_to_evp_pkey(recovered_pem);
    if (!recovered_pkey) {
        cerr << "[RECOVERY] Failed to reconstruct private key from Share1 + Share2.\n";
        return nullptr;
    }
    cout << "[RECOVERY] Private key reconstructed successfully.\n";

    cout << "[RECOVERY] Step 4/4: Rotating all three shares together...\n";
    // Re-split the recovered key to rotate Share3's password binding.
    // IMPORTANT: this produces a brand-new, independent {Share1, Share2,
    // Share3} triple - new_shares[0] and new_shares[1] are NOT
    // interchangeable with the old Share1/Share2 fetched above, even
    // though every triple decodes to the same secret PEM. Each
    // split_private_key() call draws fresh random polynomial
    // coefficients (see shamir.cpp), so a byte from the OLD Share1
    // combined with a byte from the NEW Share3 reconstructs garbage, not
    // the secret byte - that was the root cause of the Share1+Share3
    // login failure after recovery.
    //
    // The fix: push ALL THREE new shares out together. The old Share1 on
    // Key Server and old Share2 on Recovery Server must be REPLACED with
    // new_shares[0] and new_shares[1] from this exact split call, in the
    // same operation that saves new_shares[2] locally. Only then do
    // Share1+Share2 and Share1+Share3 agree going forward.
    string pem_for_split = export_private_key_to_pem(recovered_pkey);
    if (pem_for_split.empty()) {
        cerr << "[RECOVERY] WARNING: Could not export recovered key for re-splitting. "
             << "Shares NOT rotated. Next login must use recovery mode again.\n";
        // Still return the key - the session can proceed.
        return recovered_pkey;
    }

    vector<string> new_shares = split_private_key(pem_for_split);
    if (new_shares.size() != 3) {
        cerr << "[RECOVERY] WARNING: Re-split failed. "
             << "Shares NOT rotated. Next login must use recovery mode again.\n";
        return recovered_pkey;
    }

    // Push the new Share1 to the Key Server FIRST. If this fails, we bail
    // out before touching Share2 or Share3, so we never end up with a
    // mismatched set split across servers (e.g. new Share2 stored, but
    // still-old Share1 left in place).
    if (!update_share1_on_keyserver(key_sock, gmail_sock, username, session_token, new_shares[0])) {
        cerr << "[RECOVERY] WARNING: Failed to update Share1 on Key Server. "
             << "Shares NOT rotated - old Share1/Share2 remain authoritative. "
             << "Next login must use recovery mode again.\n";
        return recovered_pkey;
    }
    cout << "[RECOVERY] Share1 updated on Key Server.\n";

    // Push the new Share2 to the Recovery Server next.
    if (!update_share2_on_recoveryserver(gmail_sock, username, session_token, new_shares[1])) {
        cerr << "[RECOVERY] WARNING: Failed to update Share2 on Recovery Server. "
             << "Key Server now has the NEW Share1 but Recovery Server still has "
             << "the OLD Share2 - these no longer match each other. Run account "
             << "recovery again immediately to re-rotate and bring all three "
             << "shares back into agreement.\n";
        return recovered_pkey;
    }
    cout << "[RECOVERY] Share2 updated on Recovery Server.\n";

    // Finally, save the new Share3 locally, encrypted with the (possibly
    // new) password. This is the same share that came from the split call
    // whose Share1/Share2 we just pushed above, so Share1+Share3 will
    // reconstruct correctly on the next ordinary login.
    if (!save_local_share3(username, password, new_shares[2])) {
        cerr << "[RECOVERY] WARNING: Failed to save new Share3 file. "
             << "Key Server and Recovery Server now agree with each other, but "
             << "no local Share3 exists - next login must use recovery mode "
             << "again (Share1 + Share2) rather than the normal Share1 + Share3 path.\n";
    } else {
        cout << "[RECOVERY] New Share3 saved to " << username << "_share3.enc\n";
    }

    cout << "[RECOVERY] All three shares rotated and now agree: "
         << "Share1 + Share2 and Share1 + Share3 will both reconstruct this key.\n";

    return recovered_pkey;
}
// ----- end Task 5 helpers -----

int main() {
    tls_global_init();

    // Single client SSL_CTX, trusting exactly the three self-signed server
    // certificates in TLS_TRUSTED_BUNDLE_PATH. Used for every outbound
    // connection this client makes (Key Server, Gmail Server, Recovery
    // Server) - no external/system CA store is consulted.
    g_client_ctx = tls_create_client_ctx(TLS_TRUSTED_BUNDLE_PATH);
    if (!g_client_ctx) {
        cerr << "FATAL: Could not load trusted certificate bundle ("
             << TLS_TRUSTED_BUNDLE_PATH << "). Run certs/gen_certs.sh first.\n";
        return 1;
    }

    // Connect to servers
    SSL* key_sock = tls_client_connect("127.0.0.1", 5555, g_client_ctx);
    if (!key_sock) {
        cerr << "Failed to connect to key server\n";
        return 1;
    }

    SSL* gmail_sock = tls_client_connect("127.0.0.1", 4444, g_client_ctx);
    if (!gmail_sock) {
        tls_close(key_sock);
        return 1;
    }

    // Step 1: Authenticate with Gmail server FIRST.
    // This is the identity check that everything else now depends on, and
    // it's also where we get the password used to encrypt/decrypt the
    // locally-stored private key.
    cout << "Enter client ID: ";
    string client_id;
    cin >> client_id;
    cin.ignore();

    string password;
    string session_token = authenticate_with_gmail_server(gmail_sock, password);
    if (session_token.empty()) {
        cerr << "ERROR: Authentication with Gmail server failed or returned no session token.\n";
        tls_close(key_sock);
        tls_close(gmail_sock);
        return 1;
    }

    // Step 2: Load the existing private key from disk if one exists for this
    // client_id, otherwise generate a new one and save it (encrypted with
    // the password just used above).
    bool key_file_existed_before = ifstream(private_key_filename(client_id)).good();
    EVP_PKEY* pkey = load_or_generate_keys(client_id, password);
    if (!pkey) {
        cerr << "ERROR: Could not load or generate a private key. Exiting.\n";
        tls_close(key_sock);
        tls_close(gmail_sock);
        return 1;
    }

    // Set when Shamir reconstruction fails below and LEGACY_FALLBACK is off.
    // Tells the main menu that pkey is not yet trustworthy and recovery
    // (option 3) should be used before sending/receiving email.
    bool needs_recovery = false;

    // Step 3: Register with Key Server, proving identity using the session
    // token from Gmail server. Only needed the first time a key is created -
    // if we just loaded an existing key, this client_id should already be
    // registered, so skip it (Key Server would just reply CLIENT_EXISTS).
    if (!key_file_existed_before) {
        register_with_key_server(key_sock, client_id, pkey, session_token);

        // ----- Task 3: upload Share1 to Key Server, Share2 to Recovery Server -----
        // load_or_generate_keys() wrote the raw share bytes to .tmp files.
        // Read them back, upload, then delete the temp files.
        auto read_tmp = [&](const string& fname) -> string {
            ifstream f(fname, ios::binary);
            if (!f.is_open()) return "";
            ostringstream ss;
            ss << f.rdbuf();
            return ss.str();
        };

        string share1_path = client_id + "_share1.tmp";
        string share2_path = client_id + "_share2.tmp";
        string share1 = read_tmp(share1_path);
        string share2 = read_tmp(share2_path);

        if (share1.empty() || share2.empty()) {
            cerr << "[SHAMIR] WARNING: Could not read temp share files. "
                 << "Shares were not uploaded." << endl;
        } else {
            if (!store_share1_on_keyserver(key_sock, gmail_sock, client_id, session_token, share1)) {
                cerr << "[SHAMIR] WARNING: Share1 upload to Key Server FAILED." << endl;
            }
            if (!store_share2_on_recoveryserver(gmail_sock, client_id, session_token, share2)) {
                cerr << "[SHAMIR] WARNING: Share2 upload to Recovery Server FAILED." << endl;
            }
        }

        // Remove temp files regardless of upload outcome
        remove(share1_path.c_str());
        remove(share2_path.c_str());
        // ----- end Task 3 upload block -----
    } else {
        // ---- Task 5: Shamir-only login (Share1 + Share3 -> private key) ----
        // LEGACY_FALLBACK=1 keeps the old encrypted PEM as a safety net during
        // development. Set it to 0 once reconstruction is confirmed reliable.
        cout << "[SHAMIR] Reconstructing private key from Share1 + Share3...\n";

        string share3 = load_local_share3(client_id, password);
        string share1;
        if (!share3.empty()) {
            share1 = fetch_share1_from_keyserver(key_sock, gmail_sock, client_id, session_token);
        }

        bool reconstruction_ok = false;
        if (!share1.empty() && !share3.empty()) {
            string reconstructed_pem = reconstruct_private_key(share1, share3);
            EVP_PKEY* reconstructed_pkey = pem_string_to_evp_pkey(reconstructed_pem);

            if (reconstructed_pkey) {
                EVP_PKEY_free(pkey);
                pkey = reconstructed_pkey;
                reconstruction_ok = true;
                cout << "[SHAMIR] Private key reconstructed from Share1 + Share3.\n";
            } else {
                cerr << "[SHAMIR] Reconstruction produced an invalid key.\n";
            }
        } else {
            cerr << "[SHAMIR] Could not obtain both shares (Share3 empty="
                 << share3.empty() << ", Share1 empty=" << share1.empty() << ").\n";
        }

        if (!reconstruction_ok) {
#if LEGACY_FALLBACK
            cerr << "[SHAMIR] WARNING: Falling back to legacy private_key.pem "
                 << "(LEGACY_FALLBACK is ON).\n";
            // pkey is already loaded from load_or_generate_keys() above - keep it.
#else
            // No fallback: reconstruction failed. Do not exit - fall through
            // to the main menu so the user can run Account Recovery (option 3).
            // pkey currently still holds the stale legacy-PEM key loaded by
            // load_or_generate_keys() above; it is left untouched and will be
            // replaced via EVP_PKEY_free(pkey)/pkey = recovered_pkey in the
            // existing option-3 handler once recovery succeeds.
            cerr << "[SHAMIR] FATAL: Could not reconstruct private key from "
                 << "Share1 + Share3 and LEGACY_FALLBACK is OFF. "
                 << "Use account recovery (option 3) to restore access.\n";
            needs_recovery = true;
#endif
        }
        // ---- end Task 5 login block ----

        if (!needs_recovery) {
            cout << "[STATUS] Existing key loaded; skipping Key Server registration.\n";
        }
    }

    // Main menu
    while (true) {
        cout << "\n1. Send email\n2. Receive emails\n3. Account recovery (Share1 + Share2)\n0. Exit\nChoice: ";
        int choice;
        cin >> choice;
        cin.ignore();

        if (choice == 1) {
            send_email(gmail_sock, key_sock, pkey, client_id);
        } else if (choice == 2) {
            receive_emails(gmail_sock, key_sock, pkey, client_id);
        } else if (choice == 3) {
            // ---- Task 5: Account Recovery Mode ----
            // Used when: device lost, Share3 file missing, or password forgotten.
            // Requires: active Gmail session (already have one) + Share2 on Recovery Server.
            // Share3 is re-encrypted with the current session password so that
            // the next normal login (which uses the same Gmail password) can
            // decrypt it without any extra password prompt.
            EVP_PKEY* recovered_pkey = recover_account_flow(
                key_sock, gmail_sock, client_id, session_token, password);

            if (recovered_pkey) {
                EVP_PKEY_free(pkey);
                pkey = recovered_pkey;
                // Also update the legacy PEM file so LEGACY_FALLBACK still works.
                save_private_key(pkey, client_id, password);
                cout << "[RECOVERY] Account recovery successful. "
                     << "New Share3 saved. You can now send/receive emails.\n";
            } else {
                cerr << "[RECOVERY] Account recovery FAILED. "
                     << "Check that Share2 is on the Recovery Server "
                     << "and your Gmail session is still active.\n";
            }
            // ---- end recovery block ----
        } else if (choice == 0) {
            break;
        }
    }

    // Cleanup
    tls_close(key_sock);
    tls_close(gmail_sock);
    EVP_PKEY_free(pkey);
    return 0;
}