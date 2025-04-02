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
#define BUFFER_SIZE 4096
#define RSA_KEY_SIZE 2048
#define AES_KEY_SIZE 32
#define HMAC_SIZE 32
#define AES_BLOCK_SIZE 16

using namespace std;
#define MAX_EMAIL_SIZE (10 * 1024 * 1024) // 10MB maximum email size
void process_email(const string& email, int key_sock, EVP_PKEY* pkey);
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

// Connect to server
int connect_to_server(const char* ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

// Register with key server
void register_with_key_server(int key_sock, const string& client_id, EVP_PKEY* pkey) {
    string pub_key = get_public_key_string(pkey);
    string msg = client_id + "|" + pub_key;
    
    send(key_sock, "1", 1, 0);
    send(key_sock, msg.c_str(), msg.size(), 0);
    
    char buffer[BUFFER_SIZE] = {0};
    recv(key_sock, buffer, BUFFER_SIZE, 0);
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


EVP_PKEY* get_recipient_pubkey(int key_sock, const string& recipient_id) {
    cout << "[DEBUG] Starting key request for " << recipient_id << endl;
    
    // Send request type
    if (send(key_sock, "2", 1, 0) <= 0) {
        cerr << "[ERROR] Failed to send request type to key server" << endl;
        return nullptr;
    }

    // Send recipient ID
    string request = "REQUEST_KEY|" + recipient_id;
    if (send(key_sock, request.c_str(), request.size(), 0) <= 0) {
        cerr << "[ERROR] Failed to send recipient ID to key server" << endl;
        return nullptr;
    }

    // Set receive timeout (5 seconds)
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(key_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Receive response
    char buffer[BUFFER_SIZE] = {0};
    int bytes = recv(key_sock, buffer, BUFFER_SIZE, 0);
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
void authenticate_with_gmail_server(int gmail_sock) {
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
        send(gmail_sock, message.c_str(), message.size(), 0);
        
        // Receive response
        char response[BUFFER_SIZE] = {0};
        int bytes = recv(gmail_sock, response, BUFFER_SIZE, 0);
        if (bytes <= 0) {
            cout << "Server disconnected\n";
            return;
        }
        
        string responseStr(response, bytes);
        responseStr = responseStr.substr(0, responseStr.find('\n'));
        
        if (responseStr == "AUTH_SUCCESS") {
            cout << "Authentication successful\n";
            break;
        } else {
            cout << "Authentication failed: " << responseStr << endl;
        }
    }
}
//send mail
void send_email(int gmail_sock, int key_sock, EVP_PKEY* pkey, const string& sender_id) {
    // Validate connections
    if (gmail_sock <= 0 || key_sock <= 0) {
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

    if (send(gmail_sock, complete_message.c_str(), complete_message.size(), 0) <= 0) {
        cerr << "ERROR: Failed to send email data" << endl;
        EVP_PKEY_free(recipient_pub);
        return;
    }

    // Wait for response
    char response[BUFFER_SIZE] = {0};
    int bytes_received = recv(gmail_sock, response, BUFFER_SIZE, 0);
    if (bytes_received <= 0) {
        cerr << "ERROR: No response from server" << endl;
    } else {
        response[bytes_received] = '\0';
        cout << "Server response: " << response << endl;
    }

    EVP_PKEY_free(recipient_pub);
}

// Receive emails
void receive_emails(int gmail_sock, int key_sock, EVP_PKEY* pkey, const string& client_id) {
    // Send retrieve command with terminator
    string command = "4\n";
    if (send(gmail_sock, command.c_str(), command.size(), 0) <= 0) {
        cerr << "ERROR: Failed to send retrieve command\n";
        return;
    }

    // Set receive timeout (5 seconds)
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(gmail_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Receive all email data
    string all_emails;
    char buffer[BUFFER_SIZE];
    while (true) {
        int bytes = recv(gmail_sock, buffer, BUFFER_SIZE, 0);
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
void process_email(const string& email, int key_sock, EVP_PKEY* pkey) {
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
}int main() {
    // Generate keys
    EVP_PKEY* pkey = generate_keys();
    if (!pkey) {
        cerr << "Failed to generate keys\n";
        return 1;
    }

    // Connect to servers
    int key_sock = connect_to_server("127.0.0.1", 5555);
    if (key_sock == -1) {
        EVP_PKEY_free(pkey);
        return 1;
    }

    int gmail_sock = connect_to_server("127.0.0.1", 4444);
    if (gmail_sock == -1) {
        close(key_sock);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // Register with key server
    string client_id;
    cout << "Enter client ID: ";
    cin >> client_id;
    register_with_key_server(key_sock, client_id, pkey);

    // Authenticate with Gmail server
    authenticate_with_gmail_server(gmail_sock);

    // Main menu
    while (true) {
        cout << "\n1. Send email\n2. Receive emails\n0. Exit\nChoice: ";
        int choice;
        cin >> choice;
        cin.ignore();

        if (choice == 1) {
            send_email(gmail_sock, key_sock, pkey, client_id);
        } else if (choice == 2) {
            receive_emails(gmail_sock, key_sock, pkey, client_id);
        } else if (choice == 0) {
            break;
        }
    }

    // Cleanup
    close(key_sock);
    close(gmail_sock);
    EVP_PKEY_free(pkey);
    return 0;
}
