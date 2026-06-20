#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <mutex>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <limits>
#include <arpa/inet.h>
#include "tls_common.h"   // TLS transport helpers

// ---- TEMPORARY: Signed Session Token debug verification logging ----
// Set to 0 (or delete this block + the TOKEN_DEBUG-guarded lines below)
// once the Phase 1 token rollout is verified. Purely additive cout/cerr
// statements - no protocol, security, or control-flow changes.
#define TOKEN_DEBUG 1

#define PORT 5555
#define BUFFER_SIZE 4096
#define RSA_KEY_SIZE 2048
#define GMAIL_VERIFY_IP "127.0.0.1"   // single point of change if servers later run on separate machines
#define GMAIL_VERIFY_PORT 4446

// This server's own TLS identity (presented to clients connecting on PORT).
#define TLS_CERT_PATH "certs/keyserver_cert.pem"
#define TLS_KEY_PATH  "certs/keyserver_key.pem"

// Trust store used when KeyServer itself acts as a TLS *client* — i.e. when
// it calls out to GmailServer's internal verify port. Contains (at least)
// GmailServer's self-signed certificate.
#define TLS_TRUSTED_BUNDLE_PATH "certs/trusted_servers.pem"

// ---- Signed Session Tokens (Phase 1) ----
// GmailServer's token-signing public key (separate from its TLS cert).
// KeyServer only ever READS this file - it never generates it.
#define GMAIL_SIGNING_PUBLIC_KEY_PATH "gmailserver_public.pem"

using namespace std;

mutex file_mutex;
unordered_map<string, string> clientPublicKeys;
unordered_map<string, string> clientSignatures;

// Share1 store: username -> Share1 binary blob (stored as raw string)
unordered_map<string, string> clientShare1;

// Client SSL_CTX used for the outbound verify connection to GmailServer.
// Built once at startup in main() and reused for every verify call.
static SSL_CTX* g_verify_client_ctx = nullptr;

// Error handling macro
#define PRINT_SSL_ERROR(msg) \
    do { \
        cerr << msg << endl; \
        ERR_print_errors_fp(stderr); \
    } while(0)

// Initialize OpenSSL
void init_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// Clean up OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

// ---- Signed Session Tokens (Phase 1) ----
// Verifies the RSA signature embedded in a token issued by GmailServer,
// and that the token's username field matches `expected_username` and has
// not expired. Defined further below (needs base64Decode, defined later
// in this file); forward-declared here so verifyWithGmailServer can call
// it. This check is ADDITIVE: the existing TLS VERIFY-port round-trip
// below is left fully in place per the Phase 1 migration plan.
bool verifyTokenSignature(const string& expected_username, const string& token);

// Ask GmailServer's internal verify port whether (username, token) is a real,
// currently-active authenticated session. Returns true only on an explicit
// "VALID". This call is now made over TLS: KeyServer connects to GmailServer
// as a TLS client and verifies GmailServer's certificate against
// TLS_TRUSTED_BUNDLE_PATH before trusting anything it says.
//
// Phase 1: this function ALSO independently verifies the token's RSA
// signature (signed by GmailServer's signing key) before trusting it -
// both checks must pass. The original VERIFY-port call is unchanged and
// still required; signature verification is purely additive.
bool verifyWithGmailServer(const string& username, const string& token) {
#if TOKEN_DEBUG
    cout << "[TOKEN] Token received" << endl;
#endif
    if (!verifyTokenSignature(username, token)) {
        cerr << "[VERIFY] Token signature check FAILED for: " << username << endl;
        return false;
    }

#if TOKEN_DEBUG
    cout << "[TOKEN] Local verification successful" << endl;
    cout << "[TOKEN] Contacting Gmail VERIFY service" << endl;
#endif

    SSL* ssl = tls_client_connect(GMAIL_VERIFY_IP, GMAIL_VERIFY_PORT, g_verify_client_ctx);
    if (!ssl) {
        cerr << "[VERIFY] Could not establish TLS connection to GmailServer verify port" << endl;
        return false;
    }

    // Short timeout: this must not hang KeyServer if GmailServer is unreachable.
    tls_set_recv_timeout(ssl, 3);

    string request = "VERIFY\n" + username + "\n" + token + "\n";
    if (tls_send(ssl, request.c_str(), request.size()) <= 0) {
        cerr << "[VERIFY] Failed to send verify request" << endl;
        tls_close(ssl);
        return false;
    }

    string response = tls_read_line(ssl);
    tls_close(ssl);

#if TOKEN_DEBUG
    cout << "[TOKEN] Gmail VERIFY result = " << (response == "VALID" ? "VALID" : "INVALID") << endl;
#endif

    return response == "VALID";
}

// ---- One-Time Operation Tokens (Phase 2) ----
// Asks GmailServer's VERIFY_OP path whether a given Operation Token is
// valid, unused, unexpired, and scoped to (username, operation,
// "KEYSERVER"). This is ADDITIVE to verifyWithGmailServer() above: every
// share-related handler below calls BOTH - the existing session-token
// check is completely unchanged, this is a second, independent gate.
// Returns true only on an explicit "VALID" response; any other response
// (USED, EXPIRED, WRONG_OPERATION, WRONG_TARGET, NOT_FOUND, MALFORMED)
// is treated as a hard failure and logged with the specific reason.
bool verifyOperationToken(const string& username, const string& operation, const string& op_token) {
    static const char* kTargetService = "KEYSERVER";

#if TOKEN_DEBUG
    cout << "[OPTOKEN] Verifying operation token for op=" << operation << endl;
#endif

    SSL* ssl = tls_client_connect(GMAIL_VERIFY_IP, GMAIL_VERIFY_PORT, g_verify_client_ctx);
    if (!ssl) {
        cerr << "[OPTOKEN] Could not establish TLS connection to GmailServer verify port" << endl;
        return false;
    }

    tls_set_recv_timeout(ssl, 3);

    string request = "VERIFY_OP\n" + username + "\n" + operation + "\n" +
                      string(kTargetService) + "\n" + op_token + "\n";
    if (tls_send(ssl, request.c_str(), request.size()) <= 0) {
        cerr << "[OPTOKEN] Failed to send VERIFY_OP request" << endl;
        tls_close(ssl);
        return false;
    }

    string response = tls_read_line(ssl);
    tls_close(ssl);

#if TOKEN_DEBUG
    cout << "[OPTOKEN] GmailServer VERIFY_OP result = " << response << endl;
#endif

    if (response != "VALID") {
        cerr << "[OPTOKEN] Operation token rejected for " << username
             << " (op=" << operation << "): " << response << endl;
        return false;
    }
    return true;
}

// Generate RSA keys for server
void generateServerKeys() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        PRINT_SSL_ERROR("Error creating EVP_PKEY_CTX");
        return;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        PRINT_SSL_ERROR("Error initializing keygen");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0) {
        PRINT_SSL_ERROR("Error setting key length");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        PRINT_SSL_ERROR("Error generating key");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Save Private Key
    BIO *bio_private = BIO_new_file("keyserver_private.pem", "w+");
    if (!bio_private) {
        PRINT_SSL_ERROR("Error creating BIO for private key");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    
    if (!PEM_write_bio_PrivateKey(bio_private, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        PRINT_SSL_ERROR("Error writing private key");
    }
    BIO_free(bio_private);

    // Save Public Key
    BIO *bio_public = BIO_new_file("keyserver_public.pem", "w+");
    if (!bio_public) {
        PRINT_SSL_ERROR("Error creating BIO for public key");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    
    if (!PEM_write_bio_PUBKEY(bio_public, pkey)) {
        PRINT_SSL_ERROR("Error writing public key");
    }
    BIO_free(bio_public);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    cout << "Server keys generated successfully." << endl;
}

// Load server's private key
EVP_PKEY* loadServerPrivateKey() {
    BIO *bio_private = BIO_new_file("keyserver_private.pem", "r");
    if (!bio_private) {
        PRINT_SSL_ERROR("Error opening private key file");
        return nullptr;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio_private, nullptr, nullptr, nullptr);
    if (!pkey) {
        PRINT_SSL_ERROR("Error reading private key");
    }
    
    BIO_free(bio_private);
    return pkey;
}

// Base64 encode
string base64Encode(const unsigned char* input, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    if (BIO_write(b64, input, length) <= 0) {
        BIO_free_all(b64);
        return "";
    }
    
    if (BIO_flush(b64) != 1) {
        BIO_free_all(b64);
        return "";
    }

    BIO_get_mem_ptr(b64, &bufferPtr);
    string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);
    
    return encoded;
}

// Base64 decode — used when loading Share1 back from share1_store.txt
string base64Decode(const string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(encoded.data(), (int)encoded.size());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    vector<char> buf(encoded.size());
    int decoded_len = BIO_read(b64, buf.data(), (int)buf.size());
    BIO_free_all(b64);

    if (decoded_len <= 0) return "";
    return string(buf.data(), decoded_len);
}

// ---- Signed Session Tokens (Phase 1) ----
// Loads GmailServer's token-signing PUBLIC key. KeyServer only ever reads
// this file (gmailserver_public.pem) - GmailServer is the only process
// that ever generates or writes it. Loaded fresh on each verification
// call, mirroring the existing loadServerPrivateKey() pattern in this
// file (simple and correct; this is not a hot path).
EVP_PKEY* loadGmailSigningPublicKey() {
    BIO* bio = BIO_new_file(GMAIL_SIGNING_PUBLIC_KEY_PATH, "r");
    if (!bio) {
        cerr << "[VERIFY] Could not open " << GMAIL_SIGNING_PUBLIC_KEY_PATH << endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        cerr << "[VERIFY] Could not parse " << GMAIL_SIGNING_PUBLIC_KEY_PATH << endl;
    }
    return pkey;
}

// Token shape (must match GmailServer's generateSessionToken()):
//   base64(payload) + "." + base64(signature)
//   payload = "username|issued_at|expires_at|nonce"
//
// Verifies: signature valid under GmailServer's public key, username in
// the payload matches expected_username, and the token has not expired.
bool verifyTokenSignature(const string& expected_username, const string& token) {
    size_t dot = token.find('.');
    if (dot == string::npos || dot == 0 || dot == token.size() - 1) {
        cerr << "[VERIFY] Malformed token (missing '.' separator)" << endl;
        return false;
    }

    string payload_b64 = token.substr(0, dot);
    string signature_b64 = token.substr(dot + 1);

    string payload = base64Decode(payload_b64);
    string signature = base64Decode(signature_b64);
    if (payload.empty() || signature.empty()) {
        cerr << "[VERIFY] Malformed token (base64 decode failed)" << endl;
        return false;
    }

    // Parse payload: username|issued_at|expires_at|nonce
    size_t p1 = payload.find('|');
    size_t p2 = (p1 == string::npos) ? string::npos : payload.find('|', p1 + 1);
    size_t p3 = (p2 == string::npos) ? string::npos : payload.find('|', p2 + 1);
    if (p1 == string::npos || p2 == string::npos || p3 == string::npos) {
        cerr << "[VERIFY] Malformed token payload (expected 4 fields)" << endl;
        return false;
    }

    string token_username = payload.substr(0, p1);
    string expires_at_str = payload.substr(p2 + 1, p3 - p2 - 1);

#if TOKEN_DEBUG
    cout << "[TOKEN] Username extracted = " << token_username << endl;
    cout << "[TOKEN] Expiry extracted = " << expires_at_str << endl;
#endif

    if (token_username != expected_username) {
        cerr << "[VERIFY] Token username mismatch (token says '" << token_username
             << "', expected '" << expected_username << "')" << endl;
#if TOKEN_DEBUG
        cout << "[TOKEN] Username match FAILED" << endl;
#endif
        return false;
    }
#if TOKEN_DEBUG
    cout << "[TOKEN] Username match PASSED" << endl;
#endif

    long long expires_at = 0;
    try {
        expires_at = stoll(expires_at_str);
    } catch (...) {
        cerr << "[VERIFY] Malformed token expiry field" << endl;
        return false;
    }

    time_t now = time(nullptr);
    if (now > (time_t)expires_at) {
        cerr << "[VERIFY] Token expired for: " << expected_username << endl;
#if TOKEN_DEBUG
        cout << "[TOKEN] Expiry check FAILED" << endl;
#endif
        return false;
    }
#if TOKEN_DEBUG
    cout << "[TOKEN] Expiry check PASSED" << endl;
#endif

    EVP_PKEY* gmail_pub = loadGmailSigningPublicKey();
    if (!gmail_pub) {
        return false;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(gmail_pub);
        return false;
    }

    bool ok = false;
    if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, gmail_pub) > 0 &&
        EVP_DigestVerifyUpdate(md_ctx, payload.data(), payload.size()) > 0) {
        int result = EVP_DigestVerifyFinal(
            md_ctx,
            reinterpret_cast<const unsigned char*>(signature.data()),
            signature.size());
        ok = (result == 1);
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(gmail_pub);

#if TOKEN_DEBUG
    cout << "[TOKEN] Signature verification " << (ok ? "PASSED" : "FAILED") << endl;
#endif

    if (!ok) {
        cerr << "[VERIFY] Token signature INVALID for: " << expected_username << endl;
    }
    return ok;
}

// Sign data
string signData(const string& data) {
    EVP_PKEY *pkey = loadServerPrivateKey();
    if (!pkey) {
        cerr << "Error loading private key." << endl;
        return "";
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        cerr << "Error creating MD context." << endl;
        return "";
    }

    if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        PRINT_SSL_ERROR("Error initializing signing");
        return "";
    }

    if (EVP_DigestSignUpdate(md_ctx, data.c_str(), data.length()) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        PRINT_SSL_ERROR("Error updating signing");
        return "";
    }

    size_t sig_len;
    if (EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        PRINT_SSL_ERROR("Error getting signature length");
        return "";
    }

    vector<unsigned char> signature(sig_len);
    if (EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        PRINT_SSL_ERROR("Error finalizing signature");
        return "";
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    
    return base64Encode(signature.data(), sig_len);
}

// Register client key
// Wire format from client: "client_id|session_token|public_key"
void registerClientKey(SSL* client_ssl) {
    char buffer[BUFFER_SIZE] = {0};
    int bytes_received = tls_recv(client_ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        cerr << "Error receiving data from client or connection closed." << endl;
        return;
    }
    buffer[bytes_received] = '\0';

    string client_data(buffer);
    size_t delim1 = client_data.find("|");
    size_t delim2 = (delim1 == string::npos) ? string::npos : client_data.find("|", delim1 + 1);
    if (delim1 == string::npos || delim2 == string::npos) {
        cerr << "Invalid registration format. Expected 'client_id|session_token|public_key'" << endl;
        tls_send(client_ssl, "INVALID_FORMAT", 14);
        return;
    }

    string client_id = client_data.substr(0, delim1);
    string session_token = client_data.substr(delim1 + 1, delim2 - delim1 - 1);
    string public_key = client_data.substr(delim2 + 1);

    if (client_id.empty() || session_token.empty() || public_key.empty()) {
        cerr << "Empty client ID, session token, or public key" << endl;
        tls_send(client_ssl, "EMPTY_FIELDS", 12);
        return;
    }

    // Confirm with GmailServer that this client_id is genuinely the one
    // that just authenticated, and not someone registering a key under
    // a username they don't own.
    if (!verifyWithGmailServer(client_id, session_token)) {
        cerr << "Identity verification with GmailServer FAILED for: " << client_id << endl;
        tls_send(client_ssl, "IDENTITY_VERIFICATION_FAILED", 29);
        return;
    }
    cout << "Identity verified with GmailServer for: " << client_id << endl;

    lock_guard<mutex> lock(file_mutex);
    
    if (clientPublicKeys.count(client_id)) {
        cerr << "Client already registered: " << client_id << endl;
        tls_send(client_ssl, "CLIENT_EXISTS", 13);
        return;
    }

    string signature = signData(public_key);
    if (signature.empty()) {
        cerr << "Error signing data for client: " << client_id << endl;
        tls_send(client_ssl, "SIGN_ERROR", 10);
        return;
    }

    clientPublicKeys[client_id] = public_key;
    clientSignatures[client_id] = signature;

    // Store in file
    ofstream file("key_store.txt", ios::app);
    if (!file.is_open()) {
        cerr << "Error opening key store file" << endl;
        tls_send(client_ssl, "STORAGE_ERROR", 13);
        return;
    }
    
    // Base64-encode the public key so embedded newlines don't corrupt the
    // line-based file format (same pattern used for share1_store.txt).
    string pub_key_b64 = base64Encode(
        reinterpret_cast<const unsigned char*>(public_key.data()), public_key.size());
    file << client_id << "|" << pub_key_b64 << "|" << signature << "\n";
    file.close();

    tls_send(client_ssl, "KEY STORED SUCCESSFULLY", 23);
    cout << "Registered new client: " << client_id << endl;
}

// Fetch client key
void fetchClientKey(SSL* client_ssl) {
    char buffer[BUFFER_SIZE] = {0};
    int bytes_received = tls_recv(client_ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        cerr << "Error receiving request or connection closed." << endl;
        return;
    }
    buffer[bytes_received] = '\0';

    string request(buffer);
    size_t delim_pos = request.find("|");
    if (delim_pos == string::npos || request.substr(0, delim_pos) != "REQUEST_KEY") {
        cerr << "Invalid request format. Expected 'REQUEST_KEY|client_id'" << endl;
        tls_send(client_ssl, "INVALID_REQUEST", 15);
        return;
    }

    string client_id = request.substr(delim_pos + 1);
    if (client_id.empty()) {
        cerr << "Empty client ID in request" << endl;
        tls_send(client_ssl, "EMPTY_CLIENT_ID", 15);
        return;
    }

    lock_guard<mutex> lock(file_mutex);

    if (!clientPublicKeys.count(client_id)) {
        cerr << "Client not found: " << client_id << endl;
        tls_send(client_ssl, "CLIENT_NOT_FOUND", 16);
        return;
    }

    string response = clientPublicKeys[client_id] + "|" + clientSignatures[client_id];
    if (tls_send(client_ssl, response.c_str(), response.length()) <= 0) {
        cerr << "Error sending response to client" << endl;
    } else {
        cout << "Sent public key for client: " << client_id << endl;
    }
}

// ---- STORE_SHARE1 ----
// Wire format arriving after command byte '3':
//   "STORE_SHARE1|username|session_token|op_token|<share1_bytes>"
// The share data is a raw binary string (1-byte index + N data bytes from
// shamir.cpp), so we do NOT trim or modify it beyond splitting on the
// first four '|' delimiters. op_token is new in Phase 2 (One-Time
// Operation Tokens) - additive field, everything else about this wire
// format is unchanged.
void storeShare1(SSL* client_ssl) {
    // Read the payload (may be large - share is same length as PEM + 1 byte)
    // Use a larger buffer here; PEM keys are typically ~1700 bytes.
    vector<char> buf(8192, 0);
    int bytes = tls_recv(client_ssl, buf.data(), buf.size() - 1);
    if (bytes <= 0) {
        cerr << "[SHARE1] Error receiving STORE_SHARE1 payload" << endl;
        tls_send(client_ssl, "RECV_ERROR", 10);
        return;
    }
    string payload(buf.data(), bytes);

    // Expected: "STORE_SHARE1|username|session_token|op_token|<share_data>"
    size_t d1 = payload.find('|');
    size_t d2 = (d1 == string::npos) ? string::npos : payload.find('|', d1 + 1);
    size_t d3 = (d2 == string::npos) ? string::npos : payload.find('|', d2 + 1);
    size_t d4 = (d3 == string::npos) ? string::npos : payload.find('|', d3 + 1);

    if (d1 == string::npos || d2 == string::npos || d3 == string::npos || d4 == string::npos) {
        cerr << "[SHARE1] Invalid STORE_SHARE1 format" << endl;
        tls_send(client_ssl, "INVALID_FORMAT", 14);
        return;
    }

    // d1 points at the '|' after "STORE_SHARE1"
    string username     = payload.substr(d1 + 1, d2 - d1 - 1);
    string session_tok  = payload.substr(d2 + 1, d3 - d2 - 1);
    string op_token      = payload.substr(d3 + 1, d4 - d3 - 1);
    string share1       = payload.substr(d4 + 1);   // raw binary blob

    if (username.empty() || session_tok.empty() || op_token.empty() || share1.empty()) {
        cerr << "[SHARE1] Empty field in STORE_SHARE1" << endl;
        tls_send(client_ssl, "EMPTY_FIELDS", 12);
        return;
    }

    // Verify the caller is genuinely who they claim to be (unchanged)
    if (!verifyWithGmailServer(username, session_tok)) {
        cerr << "[SHARE1] Session verification failed for: " << username << endl;
        tls_send(client_ssl, "IDENTITY_VERIFICATION_FAILED", 29);
        return;
    }

    // Phase 2: additionally require a valid, unused, correctly-scoped
    // Operation Token for this exact operation. Additive gate - does not
    // replace the session-token check above.
    if (!verifyOperationToken(username, "STORE_SHARE1", op_token)) {
        cerr << "[SHARE1] Operation token verification failed for STORE: " << username << endl;
        tls_send(client_ssl, "OP_TOKEN_VERIFICATION_FAILED", 29);
        return;
    }

    lock_guard<mutex> lock(file_mutex);

    if (clientShare1.count(username)) {
        cerr << "[SHARE1] Share1 already stored for: " << username << endl;
        tls_send(client_ssl, "SHARE1_EXISTS", 13);
        return;
    }

    // Persist to share1_store.txt.
    // The share blob is binary, so we base64-encode it for safe line storage.
    // Re-use the existing base64Encode() helper from this file.
    string share1_b64 = base64Encode(
        reinterpret_cast<const unsigned char*>(share1.data()), share1.size());

    ofstream f("share1_store.txt", ios::app);
    if (!f.is_open()) {
        cerr << "[SHARE1] Failed to open share1_store.txt" << endl;
        tls_send(client_ssl, "STORAGE_ERROR", 13);
        return;
    }
    f << username << "|" << share1_b64 << "\n";
    f.close();

    clientShare1[username] = share1;   // keep raw bytes in memory

    tls_send(client_ssl, "SHARE1_STORED", 13);
    cout << "[SHARE1] Stored Share1 for: " << username << endl;
}

// ---- FETCH_SHARE1 ----
// Wire format arriving after command byte '4':
//   "FETCH_SHARE1|username|session_token|op_token"
// Returns the raw Share1 bytes on success, or an error string. op_token
// is new in Phase 2 - additive field, last in the message (this command
// has no binary blob tail, so unlike STORE/UPDATE the op_token can safely
// be the final substr() segment).
void fetchShare1(SSL* client_ssl) {
    vector<char> buf(4096, 0);
    int bytes = tls_recv(client_ssl, buf.data(), buf.size() - 1);
    if (bytes <= 0) {
        cerr << "[SHARE1] Error receiving FETCH_SHARE1 payload" << endl;
        tls_send(client_ssl, "RECV_ERROR", 10);
        return;
    }
    string payload(buf.data(), bytes);

    // Expected: "FETCH_SHARE1|username|session_token|op_token"
    size_t d1 = payload.find('|');
    size_t d2 = (d1 == string::npos) ? string::npos : payload.find('|', d1 + 1);
    size_t d3 = (d2 == string::npos) ? string::npos : payload.find('|', d2 + 1);

    if (d1 == string::npos || d2 == string::npos || d3 == string::npos) {
        cerr << "[SHARE1] Invalid FETCH_SHARE1 format" << endl;
        tls_send(client_ssl, "INVALID_FORMAT", 14);
        return;
    }

    string username    = payload.substr(d1 + 1, d2 - d1 - 1);
    string session_tok = payload.substr(d2 + 1, d3 - d2 - 1);
    string op_token     = payload.substr(d3 + 1);

    if (username.empty() || session_tok.empty() || op_token.empty()) {
        cerr << "[SHARE1] Empty fields in FETCH_SHARE1" << endl;
        tls_send(client_ssl, "EMPTY_FIELDS", 12);
        return;
    }

    // Verify session before handing out a share (unchanged)
    if (!verifyWithGmailServer(username, session_tok)) {
        cerr << "[SHARE1] Session verification failed for FETCH: " << username << endl;
        tls_send(client_ssl, "IDENTITY_VERIFICATION_FAILED", 29);
        return;
    }

    // Phase 2: additionally require a valid, unused, correctly-scoped
    // Operation Token for this exact operation before handing out share data.
    if (!verifyOperationToken(username, "FETCH_SHARE1", op_token)) {
        cerr << "[SHARE1] Operation token verification failed for FETCH: " << username << endl;
        tls_send(client_ssl, "OP_TOKEN_VERIFICATION_FAILED", 29);
        return;
    }

    lock_guard<mutex> lock(file_mutex);

    if (!clientShare1.count(username)) {
        cerr << "[SHARE1] No Share1 found for: " << username << endl;
        tls_send(client_ssl, "SHARE1_NOT_FOUND", 16);
        return;
    }

    // Send back raw bytes (not base64 - caller gets the exact binary string
    // that split_private_key() produced, ready to pass to reconstruct_private_key())
    const string& share1 = clientShare1[username];
    if (tls_send(client_ssl, share1.data(), share1.size()) <= 0) {
        cerr << "[SHARE1] Error sending Share1 to client: " << username << endl;
    } else {
        cout << "[SHARE1] Sent Share1 for: " << username << endl;
    }
}

// ---- UPDATE_SHARE1 ----
// Wire format arriving after command byte '5':
//   "UPDATE_SHARE1|username|session_token|op_token|<new_share1_bytes>"
//
// Used by recover_account_flow() after a fresh split: Share1, Share2, and
// Share3 are all regenerated together in one split_private_key() call, so
// the Share1 already on file (from registration, or from a previous
// recovery) must be REPLACED with the new one from that same call - not
// left in place. Leaving it in place is exactly the bug this command
// fixes: an old Share1 paired with a freshly-split Share3 belongs to two
// different random polynomials and does not reconstruct the original key.
//
// Same identity guarantee as storeShare1 (session token verified against
// GmailServer, plus Phase 2's op_token check), but this command REPLACES
// an existing entry instead of refusing when one is already present -
// registration's "refuse to overwrite" policy is intentionally different
// from recovery's "this is a deliberate, authenticated replacement" policy.
void updateShare1(SSL* client_ssl) {
    vector<char> buf(8192, 0);
    int bytes = tls_recv(client_ssl, buf.data(), buf.size() - 1);
    if (bytes <= 0) {
        cerr << "[SHARE1] Error receiving UPDATE_SHARE1 payload" << endl;
        tls_send(client_ssl, "RECV_ERROR", 10);
        return;
    }
    string payload(buf.data(), bytes);

    // Expected: "UPDATE_SHARE1|username|session_token|op_token|<share_data>"
    size_t d1 = payload.find('|');
    size_t d2 = (d1 == string::npos) ? string::npos : payload.find('|', d1 + 1);
    size_t d3 = (d2 == string::npos) ? string::npos : payload.find('|', d2 + 1);
    size_t d4 = (d3 == string::npos) ? string::npos : payload.find('|', d3 + 1);

    if (d1 == string::npos || d2 == string::npos || d3 == string::npos || d4 == string::npos) {
        cerr << "[SHARE1] Invalid UPDATE_SHARE1 format" << endl;
        tls_send(client_ssl, "INVALID_FORMAT", 14);
        return;
    }

    string username    = payload.substr(d1 + 1, d2 - d1 - 1);
    string session_tok = payload.substr(d2 + 1, d3 - d2 - 1);
    string op_token     = payload.substr(d3 + 1, d4 - d3 - 1);
    string new_share1  = payload.substr(d4 + 1);   // raw binary blob

    if (username.empty() || session_tok.empty() || op_token.empty() || new_share1.empty()) {
        cerr << "[SHARE1] Empty field in UPDATE_SHARE1" << endl;
        tls_send(client_ssl, "EMPTY_FIELDS", 12);
        return;
    }

    // Verify the caller is genuinely who they claim to be before letting
    // them replace a stored share - identical guarantee to storeShare1.
    if (!verifyWithGmailServer(username, session_tok)) {
        cerr << "[SHARE1] Session verification failed for UPDATE: " << username << endl;
        tls_send(client_ssl, "IDENTITY_VERIFICATION_FAILED", 29);
        return;
    }

    // Phase 2: additionally require a valid, unused, correctly-scoped
    // Operation Token for this exact operation.
    if (!verifyOperationToken(username, "UPDATE_SHARE1", op_token)) {
        cerr << "[SHARE1] Operation token verification failed for UPDATE: " << username << endl;
        tls_send(client_ssl, "OP_TOKEN_VERIFICATION_FAILED", 29);
        return;
    }

    lock_guard<mutex> lock(file_mutex);

    // Note: unlike storeShare1, we do NOT reject when an entry already
    // exists - replacing it is the whole point of this command. We also
    // do not require one to already exist: a session-verified caller is
    // entitled to (re)establish their own Share1.

    // Persist the replacement. share1_store.txt is append-only and
    // loadExistingKeys() takes the LAST line for a given username when
    // rebuilding clientShare1 on startup, so appending the new value
    // here is sufficient for the on-disk state to converge to the same
    // thing the in-memory map has after this call.
    string share1_b64 = base64Encode(
        reinterpret_cast<const unsigned char*>(new_share1.data()), new_share1.size());

    ofstream f("share1_store.txt", ios::app);
    if (!f.is_open()) {
        cerr << "[SHARE1] Failed to open share1_store.txt for update" << endl;
        tls_send(client_ssl, "STORAGE_ERROR", 13);
        return;
    }
    f << username << "|" << share1_b64 << "\n";
    f.close();

    clientShare1[username] = new_share1;   // overwrite in-memory value

    tls_send(client_ssl, "SHARE1_UPDATED", 14);
    cout << "[SHARE1] Updated Share1 for: " << username << endl;
}

void handleClient(SSL* client_ssl) {
while(true){
    char choice;
    if (tls_recv(client_ssl, &choice, 1) <= 0) {
        cerr << "Error receiving choice from client" << endl;
        tls_close(client_ssl);
        return;
    }

    switch (choice) {
        case '1':
            registerClientKey(client_ssl);
            break;
        case '2':
            fetchClientKey(client_ssl);
            break;
        case '3':
            storeShare1(client_ssl);
            break;
        case '4':
            fetchShare1(client_ssl);
            break;
        case '5':
            updateShare1(client_ssl);
            break;
        default:
            cerr << "Invalid choice received: " << choice << endl;
            tls_send(client_ssl, "INVALID_CHOICE", 14);
            break;
    }
    }

    tls_close(client_ssl);
}

void loadExistingKeys() {
    ifstream file("key_store.txt");
    if (!file.is_open()) {
        cout << "No existing key store found. Creating new one." << endl;
        return;
    }

    string line;
    while (getline(file, line)) {
        size_t delim1 = line.find("|");
        size_t delim2 = line.rfind("|");
        if (delim1 != string::npos && delim2 != string::npos && delim1 != delim2) {
            string client_id = line.substr(0, delim1);
            string public_key = line.substr(delim1 + 1, delim2 - delim1 - 1);
            string signature = line.substr(delim2 + 1);
            
            if (!client_id.empty() && !public_key.empty() && !signature.empty()) {
                // public_key is base64-encoded on disk; decode back to PEM
                clientPublicKeys[client_id] = base64Decode(public_key);
                clientSignatures[client_id] = signature;
            }
        }
    }
    file.close();
    cout << "Loaded " << clientPublicKeys.size() << " existing client keys." << endl;

    // Load Share1 data from share1_store.txt (base64-encoded blobs, one per line)
    ifstream share1_file("share1_store.txt");
    if (share1_file.is_open()) {
        string s1line;
        while (getline(share1_file, s1line)) {
            size_t sep = s1line.find('|');
            if (sep != string::npos) {
                string uname   = s1line.substr(0, sep);
                string s1_b64  = s1line.substr(sep + 1);
                if (!uname.empty() && !s1_b64.empty()) {
                    clientShare1[uname] = base64Decode(s1_b64);
                }
            }
        }
        share1_file.close();
        cout << "Loaded " << clientShare1.size() << " existing Share1 entries." << endl;
    } else {
        cout << "No existing share1_store.txt found. Starting fresh." << endl;
    }
}

int main() {
    init_openssl();
    tls_global_init();

    // Generate keys if they don't exist
    ifstream priv_key("keyserver_private.pem");
    ifstream pub_key("keyserver_public.pem");
    
    if (!priv_key.good() || !pub_key.good()) {
        cout << "Generating new server keys..." << endl;
        generateServerKeys();
    }
    priv_key.close();
    pub_key.close();

    loadExistingKeys();

    // TLS identity this server presents on PORT.
    SSL_CTX* server_ctx = tls_create_server_ctx(TLS_CERT_PATH, TLS_KEY_PATH);
    if (!server_ctx) {
        cerr << "FATAL: Could not load TLS certificate/key ("
             << TLS_CERT_PATH << " / " << TLS_KEY_PATH << "). "
             << "Run certs/gen_certs.sh first." << endl;
        cleanup_openssl();
        return -1;
    }

    // TLS trust store used when THIS server connects out to GmailServer's
    // verify port (verifyWithGmailServer).
    g_verify_client_ctx = tls_create_client_ctx(TLS_TRUSTED_BUNDLE_PATH);
    if (!g_verify_client_ctx) {
        cerr << "FATAL: Could not load trusted certificate bundle ("
             << TLS_TRUSTED_BUNDLE_PATH << "). Run certs/gen_certs.sh first." << endl;
        cleanup_openssl();
        return -1;
    }

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        cleanup_openssl();
        return -1;
    }

    // Set SO_REUSEADDR to avoid "address already in use" errors
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_socket);
        cleanup_openssl();
        return -1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Binding failed");
        close(server_socket);
        cleanup_openssl();
        return -1;
    }

    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        cleanup_openssl();
        return -1;
    }

    cout << "Key Server running on port " << PORT << " (TLS)" << endl;
    cout << "Waiting for connections..." << endl;

    while (true) {
        sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (sockaddr*)&client_addr, &addr_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

        SSL* client_ssl = tls_server_accept(client_socket, server_ctx);
        if (!client_ssl) {
            cerr << "Client TLS handshake failed; dropping connection" << endl;
            continue;
        }

        thread(handleClient, client_ssl).detach();
    }

    close(server_socket);
    cleanup_openssl();
    return 0;
}