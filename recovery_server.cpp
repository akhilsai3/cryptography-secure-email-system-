#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <mutex>
#include <ctime>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <vector>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include "tls_common.h"   // TLS transport helpers

// ---- TEMPORARY: Signed Session Token debug verification logging ----
// Set to 0 (or delete this block + the TOKEN_DEBUG-guarded lines below)
// once the Phase 1 token rollout is verified. Purely additive cout/cerr
// statements - no protocol, security, or control-flow changes.
#define TOKEN_DEBUG 1

#define PORT 6666
#define BUFFER_SIZE 4096
#define GMAIL_VERIFY_IP "127.0.0.1"   // single point of change if servers later run on separate machines
#define GMAIL_VERIFY_PORT 4446

// This server's own TLS identity (presented to clients connecting on PORT).
#define TLS_CERT_PATH "certs/recoveryserver_cert.pem"
#define TLS_KEY_PATH  "certs/recoveryserver_key.pem"

// Trust store used when Recovery Server itself acts as a TLS *client* —
// i.e. when it calls out to GmailServer's internal verify port. Contains
// (at least) GmailServer's self-signed certificate.
#define TLS_TRUSTED_BUNDLE_PATH "certs/trusted_servers.pem"

// ---- Signed Session Tokens (Phase 1) ----
// GmailServer's token-signing public key (separate from its TLS cert).
// Recovery Server only ever READS this file - it never generates it.
#define GMAIL_SIGNING_PUBLIC_KEY_PATH "gmailserver_public.pem"

using namespace std;

// Client SSL_CTX used for the outbound verify connection to GmailServer.
// Built once at startup in main() and reused for every verify call.
static SSL_CTX* g_verify_client_ctx = nullptr;

// Base64 encode (OpenSSL BIO — same pattern as keyserver.cpp)
static string base64Encode(const unsigned char* input, size_t length) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, (int)length);
    BIO_flush(b64);
    BUF_MEM* bufPtr;
    BIO_get_mem_ptr(b64, &bufPtr);
    string encoded(bufPtr->data, bufPtr->length);
    BIO_free_all(b64);
    return encoded;
}

// Base64 decode
static string base64Decode(const string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(encoded.data(), (int)encoded.size());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    vector<char> buf(encoded.size());
    int len = BIO_read(b64, buf.data(), (int)buf.size());
    BIO_free_all(b64);
    if (len <= 0) return "";
    return string(buf.data(), len);
}

// In-memory store mirrored to disk: username -> Share2.
// This plays the role of "iCloud / Google Drive" in the architecture -
// it only ever holds Share2, which is mathematically useless on its own.
mutex file_mutex;
unordered_map<string, string> shareStore;

// ---- Signed Session Tokens (Phase 1) ----
// Loads GmailServer's token-signing PUBLIC key. Recovery Server only ever
// reads this file - GmailServer is the only process that ever generates
// or writes it.
static EVP_PKEY* loadGmailSigningPublicKey() {
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
// Identical in shape to Key Server's verifyTokenSignature() so Share1 and
// Share2 access get the same token-authenticity guarantee.
static bool verifyTokenSignature(const string& expected_username, const string& token) {
    size_t dot = token.find('.');
    if (dot == string::npos || dot == 0 || dot == token.size() - 1) {
        cerr << "[VERIFY] Malformed token (missing '.' separator)" << endl;
        return false;
    }

    string payload = base64Decode(token.substr(0, dot));
    string signature = base64Decode(token.substr(dot + 1));
    if (payload.empty() || signature.empty()) {
        cerr << "[VERIFY] Malformed token (base64 decode failed)" << endl;
        return false;
    }

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

// Ask GmailServer's internal verify port whether (username, token) is a
// real, currently-active authenticated session. Returns true only on an
// explicit "VALID". Identical in shape to Key Server's verifyWithGmailServer
// so Share1 and Share2 get the same authentication guarantee. This call is
// now made over TLS: Recovery Server connects to GmailServer as a TLS
// client and verifies GmailServer's certificate against
// TLS_TRUSTED_BUNDLE_PATH before trusting anything it says.
//
// Phase 1: this function ALSO independently verifies the token's RSA
// signature before trusting it - both checks must pass. The original
// VERIFY-port call is unchanged and still required; signature
// verification is purely additive.
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

    // Short timeout: this must not hang Recovery Server if GmailServer is
    // unreachable.
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
// "RECOVERYSERVER"). ADDITIVE to verifyWithGmailServer() above - every
// share-related handler below calls BOTH; the existing session-token
// check is unchanged. Mirrors KeyServer's verifyOperationToken exactly,
// differing only in the target_service string, so Share1 and Share2 get
// identical Operation Token guarantees.
static bool verifyOperationToken(const string& username, const string& operation, const string& op_token) {
    static const char* kTargetService = "RECOVERYSERVER";

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

// ---- STORE_SHARE|username|session_token|op_token|share ----
// Stores Share2 for a username. Refuses to overwrite an existing share
// (same policy as Key Server refusing to re-register an existing client) -
// once a share is on file, replacing it requires a deliberate, authenticated
// flow, not a bare overwrite. That flow is out of scope for this phase.
//
// Requires a valid, currently-active Gmail session token (verified the
// same way Key Server verifies Share1 requests) PLUS, as of Phase 2, a
// valid single-use Operation Token scoped to this exact operation.
void storeShare(SSL* client_ssl, const string& request) {
    size_t delim1 = request.find("|");
    size_t delim2 = (delim1 == string::npos) ? string::npos : request.find("|", delim1 + 1);
    size_t delim3 = (delim2 == string::npos) ? string::npos : request.find("|", delim2 + 1);
    size_t delim4 = (delim3 == string::npos) ? string::npos : request.find("|", delim3 + 1);

    if (delim1 == string::npos || delim2 == string::npos || delim3 == string::npos || delim4 == string::npos) {
        cerr << "Invalid STORE_SHARE format. Expected 'STORE_SHARE|username|session_token|op_token|share'" << endl;
        tls_send(client_ssl, "INVALID_FORMAT", 14);
        return;
    }

    string username = request.substr(delim1 + 1, delim2 - delim1 - 1);
    string session_token = request.substr(delim2 + 1, delim3 - delim2 - 1);
    string op_token = request.substr(delim3 + 1, delim4 - delim3 - 1);
    string share = request.substr(delim4 + 1);

    if (username.empty() || session_token.empty() || op_token.empty() || share.empty()) {
        cerr << "Empty username, session token, op token, or share in STORE_SHARE request" << endl;
        tls_send(client_ssl, "EMPTY_FIELDS", 12);
        return;
    }

    // Verify the caller is genuinely who they claim to be before accepting
    // their Share2 (unchanged).
    if (!verifyWithGmailServer(username, session_token)) {
        cerr << "[SHARE2] Session verification failed for: " << username << endl;
        tls_send(client_ssl, "IDENTITY_VERIFICATION_FAILED", 29);
        return;
    }

    // Phase 2: additionally require a valid, unused, correctly-scoped
    // Operation Token for this exact operation.
    if (!verifyOperationToken(username, "STORE_SHARE2", op_token)) {
        cerr << "[SHARE2] Operation token verification failed for STORE: " << username << endl;
        tls_send(client_ssl, "OP_TOKEN_VERIFICATION_FAILED", 29);
        return;
    }

    lock_guard<mutex> lock(file_mutex);

    if (shareStore.count(username)) {
        cerr << "Share already exists for: " << username << endl;
        tls_send(client_ssl, "SHARE_EXISTS", 12);
        return;
    }

    ofstream file("recovery_store.txt", ios::app);
    if (!file.is_open()) {
        cerr << "Error opening recovery store file" << endl;
        tls_send(client_ssl, "STORAGE_ERROR", 13);
        return;
    }

    // Base64-encode the binary share before writing — it can contain embedded
    // NUL bytes, '|' delimiters, and newlines that would corrupt the file format.
    string share_b64 = base64Encode(
        reinterpret_cast<const unsigned char*>(share.data()), share.size());
    file << username << "|" << share_b64 << "\n";
    file.close();

    shareStore[username] = share;

    tls_send(client_ssl, "SHARE_STORED", 12);
    cout << "Stored Share2 for: " << username << endl;
}

// ---- GET_SHARE|username|session_token|op_token ----
// Returns the raw Share2 string for a username, or SHARE_NOT_FOUND.
// Requires a valid, currently-active Gmail session token (verified
// against GmailServer's internal VERIFY port) PLUS, as of Phase 2, a
// valid single-use Operation Token scoped to this exact operation.
void getShare(SSL* client_ssl, const string& request) {
    size_t delim1 = request.find("|");
    size_t delim2 = (delim1 == string::npos) ? string::npos : request.find("|", delim1 + 1);
    size_t delim3 = (delim2 == string::npos) ? string::npos : request.find("|", delim2 + 1);

    if (delim1 == string::npos || delim2 == string::npos || delim3 == string::npos) {
        cerr << "Invalid GET_SHARE format. Expected 'GET_SHARE|username|session_token|op_token'" << endl;
        tls_send(client_ssl, "INVALID_REQUEST", 15);
        return;
    }

    string username = request.substr(delim1 + 1, delim2 - delim1 - 1);
    string session_token = request.substr(delim2 + 1, delim3 - delim2 - 1);
    string op_token = request.substr(delim3 + 1);

    if (username.empty() || session_token.empty() || op_token.empty()) {
        cerr << "Empty username, session token, or op token in GET_SHARE request" << endl;
        tls_send(client_ssl, "EMPTY_USERNAME", 14);
        return;
    }

    // Verify session before handing out a share (unchanged).
    if (!verifyWithGmailServer(username, session_token)) {
        cerr << "[SHARE2] Session verification failed for GET: " << username << endl;
        tls_send(client_ssl, "IDENTITY_VERIFICATION_FAILED", 29);
        return;
    }

    // Phase 2: additionally require a valid, unused, correctly-scoped
    // Operation Token for this exact operation before handing out share data.
    if (!verifyOperationToken(username, "GET_SHARE", op_token)) {
        cerr << "[SHARE2] Operation token verification failed for GET: " << username << endl;
        tls_send(client_ssl, "OP_TOKEN_VERIFICATION_FAILED", 29);
        return;
    }

    lock_guard<mutex> lock(file_mutex);

    if (!shareStore.count(username)) {
        cerr << "Share not found for: " << username << endl;
        tls_send(client_ssl, "SHARE_NOT_FOUND", 15);
        return;
    }

    string response = shareStore[username];
    if (tls_send(client_ssl, response.c_str(), response.length()) <= 0) {
        cerr << "Error sending share to client" << endl;
    } else {
        cout << "Sent Share2 for: " << username << endl;
    }
}

// ---- UPDATE_SHARE|username|session_token|op_token|share ----
// Replaces an existing Share2 for a username.
//
// Used by recover_account_flow() after a fresh split: Share1, Share2, and
// Share3 are all regenerated together in one split_private_key() call, so
// the Share2 already on file (from registration, or a previous recovery)
// must be REPLACED with the new one from that same call - not left in
// place. Leaving it in place is exactly the bug this command fixes: an
// old Share2 paired with a freshly-split Share1/Share3 belongs to two
// different random polynomials and does not reconstruct the original key.
//
// Same identity guarantee as storeShare (session token verified against
// GmailServer, plus Phase 2's op_token check), but this command REPLACES
// an existing entry instead of refusing when one is already present -
// registration's "refuse to overwrite" policy is intentionally different
// from recovery's "this is a deliberate, authenticated replacement" policy.
void updateShare(SSL* client_ssl, const string& request) {
    size_t delim1 = request.find("|");
    size_t delim2 = (delim1 == string::npos) ? string::npos : request.find("|", delim1 + 1);
    size_t delim3 = (delim2 == string::npos) ? string::npos : request.find("|", delim2 + 1);
    size_t delim4 = (delim3 == string::npos) ? string::npos : request.find("|", delim3 + 1);

    if (delim1 == string::npos || delim2 == string::npos || delim3 == string::npos || delim4 == string::npos) {
        cerr << "Invalid UPDATE_SHARE format. Expected 'UPDATE_SHARE|username|session_token|op_token|share'" << endl;
        tls_send(client_ssl, "INVALID_FORMAT", 14);
        return;
    }

    string username = request.substr(delim1 + 1, delim2 - delim1 - 1);
    string session_token = request.substr(delim2 + 1, delim3 - delim2 - 1);
    string op_token = request.substr(delim3 + 1, delim4 - delim3 - 1);
    string new_share = request.substr(delim4 + 1);

    if (username.empty() || session_token.empty() || op_token.empty() || new_share.empty()) {
        cerr << "Empty username, session token, op token, or share in UPDATE_SHARE request" << endl;
        tls_send(client_ssl, "EMPTY_FIELDS", 12);
        return;
    }

    // Verify the caller is genuinely who they claim to be before letting
    // them replace a stored share - identical guarantee to storeShare.
    if (!verifyWithGmailServer(username, session_token)) {
        cerr << "[SHARE2] Session verification failed for UPDATE: " << username << endl;
        tls_send(client_ssl, "IDENTITY_VERIFICATION_FAILED", 29);
        return;
    }

    // Phase 2: additionally require a valid, unused, correctly-scoped
    // Operation Token for this exact operation.
    if (!verifyOperationToken(username, "UPDATE_SHARE2", op_token)) {
        cerr << "[SHARE2] Operation token verification failed for UPDATE: " << username << endl;
        tls_send(client_ssl, "OP_TOKEN_VERIFICATION_FAILED", 29);
        return;
    }

    lock_guard<mutex> lock(file_mutex);

    // Note: unlike storeShare, we do NOT reject when an entry already
    // exists - replacing it is the whole point of this command. We also
    // do not require one to already exist: a session-verified caller is
    // entitled to (re)establish their own Share2.

    // Persist the replacement. recovery_store.txt is append-only and
    // loadExistingShares() takes the LAST line for a given username when
    // rebuilding shareStore on startup, so appending the new value here
    // is sufficient for the on-disk state to converge to the same thing
    // the in-memory map has after this call.
    string share_b64 = base64Encode(
        reinterpret_cast<const unsigned char*>(new_share.data()), new_share.size());

    ofstream file("recovery_store.txt", ios::app);
    if (!file.is_open()) {
        cerr << "Error opening recovery store file for update" << endl;
        tls_send(client_ssl, "STORAGE_ERROR", 13);
        return;
    }
    file << username << "|" << share_b64 << "\n";
    file.close();

    shareStore[username] = new_share;   // overwrite in-memory value

    tls_send(client_ssl, "SHARE_UPDATED", 13);
    cout << "Updated Share2 for: " << username << endl;
}

// Thread-per-client, same shape as Key Server's handleClient: keep the
// connection open and dispatch one command per message until the client
// disconnects.
void handleClient(SSL* client_ssl) {
    while (true) {
        char buffer[BUFFER_SIZE] = {0};
        int bytes_received = tls_recv(client_ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            break; // client disconnected or error
        }
        // Use length-based constructor — Share2 is binary and can contain
        // embedded NUL bytes; string(buffer) would silently truncate at the
        // first NUL. This mirrors the safe pattern used in keyserver.cpp.
        string request(buffer, bytes_received);

        size_t delim = request.find("|");
        string command = (delim == string::npos) ? request : request.substr(0, delim);

        if (command == "STORE_SHARE") {
            storeShare(client_ssl, request);
        } else if (command == "GET_SHARE") {
            getShare(client_ssl, request);
        } else if (command == "UPDATE_SHARE") {
            updateShare(client_ssl, request);
        } else {
            cerr << "Invalid command received: " << command << endl;
            tls_send(client_ssl, "INVALID_COMMAND", 15);
        }
    }
    tls_close(client_ssl);
}

// Load all persisted shares from recovery_store.txt into memory at startup,
// same pattern as Key Server's loadExistingKeys.
void loadExistingShares() {
    ifstream file("recovery_store.txt");
    if (!file.is_open()) {
        cout << "No existing recovery store found. Creating new one." << endl;
        return;
    }

    string line;
    while (getline(file, line)) {
        size_t delim = line.find("|");
        if (delim != string::npos) {
            string username = line.substr(0, delim);
            string share = line.substr(delim + 1);
            if (!username.empty() && !share.empty()) {
                // Shares are base64-encoded on disk; decode back to raw binary
                shareStore[username] = base64Decode(share);
            }
        }
    }
    file.close();
    cout << "Loaded " << shareStore.size() << " existing shares." << endl;
}

int main() {
    tls_global_init();
    loadExistingShares();

    // TLS identity this server presents on PORT.
    SSL_CTX* server_ctx = tls_create_server_ctx(TLS_CERT_PATH, TLS_KEY_PATH);
    if (!server_ctx) {
        cerr << "FATAL: Could not load TLS certificate/key ("
             << TLS_CERT_PATH << " / " << TLS_KEY_PATH << "). "
             << "Run certs/gen_certs.sh first." << endl;
        return -1;
    }

    // TLS trust store used when THIS server connects out to GmailServer's
    // verify port (verifyWithGmailServer).
    g_verify_client_ctx = tls_create_client_ctx(TLS_TRUSTED_BUNDLE_PATH);
    if (!g_verify_client_ctx) {
        cerr << "FATAL: Could not load trusted certificate bundle ("
             << TLS_TRUSTED_BUNDLE_PATH << "). Run certs/gen_certs.sh first." << endl;
        return -1;
    }

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        return -1;
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_socket);
        return -1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Binding failed");
        close(server_socket);
        return -1;
    }

    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        return -1;
    }

    cout << "Recovery Server running on port " << PORT << " (TLS)" << endl;
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
    return 0;
}