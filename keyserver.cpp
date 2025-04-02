#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <mutex>
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

#define PORT 5555
#define BUFFER_SIZE 4096
#define RSA_KEY_SIZE 2048

using namespace std;

mutex file_mutex;
unordered_map<string, string> clientPublicKeys;
unordered_map<string, string> clientSignatures;

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
void registerClientKey(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        cerr << "Error receiving data from client or connection closed." << endl;
        return;
    }
    buffer[bytes_received] = '\0';

    string client_data(buffer);
    size_t delim_pos = client_data.find("|");
    if (delim_pos == string::npos) {
        cerr << "Invalid registration format. Expected 'client_id|public_key'" << endl;
        send(client_socket, "INVALID_FORMAT", 14, 0);
        return;
    }

    string client_id = client_data.substr(0, delim_pos);
    string public_key = client_data.substr(delim_pos + 1);

    if (client_id.empty() || public_key.empty()) {
        cerr << "Empty client ID or public key" << endl;
        send(client_socket, "EMPTY_FIELDS", 12, 0);
        return;
    }

    lock_guard<mutex> lock(file_mutex);
    
    if (clientPublicKeys.count(client_id)) {
        cerr << "Client already registered: " << client_id << endl;
        send(client_socket, "CLIENT_EXISTS", 13, 0);
        return;
    }

    string signature = signData(public_key);
    if (signature.empty()) {
        cerr << "Error signing data for client: " << client_id << endl;
        send(client_socket, "SIGN_ERROR", 10, 0);
        return;
    }

    clientPublicKeys[client_id] = public_key;
    clientSignatures[client_id] = signature;

    // Store in file
    ofstream file("key_store.txt", ios::app);
    if (!file.is_open()) {
        cerr << "Error opening key store file" << endl;
        send(client_socket, "STORAGE_ERROR", 13, 0);
        return;
    }
    
    file << client_id << "|" << public_key << "|" << signature << "\n";
    file.close();

    send(client_socket, "KEY STORED SUCCESSFULLY", 23, 0);
    cout << "Registered new client: " << client_id << endl;
}

// Fetch client key
void fetchClientKey(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        cerr << "Error receiving request or connection closed." << endl;
        return;
    }
    buffer[bytes_received] = '\0';

    string request(buffer);
    size_t delim_pos = request.find("|");
    if (delim_pos == string::npos || request.substr(0, delim_pos) != "REQUEST_KEY") {
        cerr << "Invalid request format. Expected 'REQUEST_KEY|client_id'" << endl;
        send(client_socket, "INVALID_REQUEST", 15, 0);
        return;
    }

    string client_id = request.substr(delim_pos + 1);
    if (client_id.empty()) {
        cerr << "Empty client ID in request" << endl;
        send(client_socket, "EMPTY_CLIENT_ID", 15, 0);
        return;
    }

    lock_guard<mutex> lock(file_mutex);

    if (!clientPublicKeys.count(client_id)) {
        cerr << "Client not found: " << client_id << endl;
        send(client_socket, "CLIENT_NOT_FOUND", 16, 0);
        return;
    }

    string response = clientPublicKeys[client_id] + "|" + clientSignatures[client_id];
    if (send(client_socket, response.c_str(), response.length(), 0) <= 0) {
        cerr << "Error sending response to client" << endl;
    } else {
        cout << "Sent public key for client: " << client_id << endl;
    }
}

void handleClient(int client_socket) {
while(true){
    char choice;
    if (recv(client_socket, &choice, 1, 0) <= 0) {
        cerr << "Error receiving choice from client" << endl;
        close(client_socket);
        return;
    }

    switch (choice) {
        case '1':
            registerClientKey(client_socket);
            break;
        case '2':
            fetchClientKey(client_socket);
            break;
        default:
            cerr << "Invalid choice received: " << choice << endl;
            send(client_socket, "INVALID_CHOICE", 14, 0);
            break;
    }
    }

    close(client_socket);
}
void process_email(const string& email, int key_sock, EVP_PKEY* pkey) {
    if (email.empty() || email.find("No emails found") != string::npos) return;
    vector<string> parts = split(email, '~');
    if (parts.size() != 7) return;
    try {
        string sender_id = trim(parts[0]);
        auto iv = base64_decode(parts[1]);
        auto enc_msg = base64_decode(parts[2]);
        auto hmac = base64_decode(parts[3]);
        auto signed_hmac = base64_decode(parts[4]);
        auto enc_key = base64_decode(parts[5]);
        auto signed_key = base64_decode(parts[6]);

        EVP_PKEY* sender_pub = get_recipient_pubkey(key_sock, sender_id);
        if (!sender_pub) return;
        if (!verify_signature(signed_key.data(), signed_key.size(), enc_key.data(), enc_key.size(), sender_pub)) {
            EVP_PKEY_free(sender_pub);
            return;
        }
        // Decrypt key and message
        auto aes_key = decrypt_key(enc_key, pkey);
        if (!verify_signature(signed_hmac.data(), signed_hmac.size(), hmac.data(), hmac.size(), sender_pub)) {
            EVP_PKEY_free(sender_pub);
            return;
        }
        auto computed_hmac = generate_HMAC(enc_msg.data(), enc_msg.size(), aes_key.data(), AES_KEY_SIZE);
        if (hmac != computed_hmac) {
            EVP_PKEY_free(sender_pub);
            return;
        }
        auto decrypted = aes_crypt(enc_msg.data(), enc_msg.size(), aes_key.data(), iv.data(), false);
        cout << "\nFrom: " << sender_id << "\n" << string(decrypted.begin(), decrypted.end()) << "\n";

        EVP_PKEY_free(sender_pub);
    } catch (...) {}
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
                clientPublicKeys[client_id] = public_key;
                clientSignatures[client_id] = signature;
            }
        }
    }
    file.close();
    cout << "Loaded " << clientPublicKeys.size() << " existing client keys." << endl;
}

int main() {
    init_openssl();
    
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

    cout << "Key Server running on port " << PORT << endl;
    cout << "Waiting for connections..." << endl;

    while (true) {
        sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (sockaddr*)&client_addr, &addr_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

      
        thread(handleClient, client_socket).detach();
    }

    close(server_socket);
    cleanup_openssl();
    return 0;
}
