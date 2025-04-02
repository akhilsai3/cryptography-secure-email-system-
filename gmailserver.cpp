#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <vector>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <algorithm> // For std::min
#include <openssl/sha.h> 
#include <iomanip>
#include <openssl/evp.h> 

#define PORT 4444
#define BUFFER_SIZE 4096

using namespace std;

mutex file_mutex;
unordered_map<string, string> userDatabase;
string read_line(int sock) {
    string line;
    char c;
    while (recv(sock, &c, 1, 0) > 0) {
        if (c == '\n') break;
        line += c;
    }
    return line;
}
#include <openssl/evp.h>  // Already included in your original code

string hashPassword(const string& password) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) {
        cerr << "Error creating hash context" << endl;
        return "";
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        cerr << "Error initializing hash" << endl;
        EVP_MD_CTX_free(context);
        return "";
    }

    if (EVP_DigestUpdate(context, password.c_str(), password.size()) != 1) {
        cerr << "Error updating hash" << endl;
        EVP_MD_CTX_free(context);
        return "";
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    if (EVP_DigestFinal_ex(context, hash, &lengthOfHash) != 1) {
        cerr << "Error finalizing hash" << endl;
        EVP_MD_CTX_free(context);
        return "";
    }

    EVP_MD_CTX_free(context);

    stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}


void loadUserDatabase() {
    ifstream file("users.txt");
    if (!file.is_open()) return;

    string line;
    while (getline(file, line)) {
        size_t space = line.find(' ');
        if (space != string::npos) {
            string username = line.substr(0, space);
            string passwordHash = line.substr(space + 1);
            // Validate it looks like a SHA256 hash (64 hex chars)
            if (passwordHash.length() == 64 && 
                passwordHash.find_first_not_of("0123456789abcdef") == string::npos) {
                userDatabase[username] = passwordHash;
            } else {
                cerr << "Invalid password hash format for user: " << username << endl;
            }
        }
    }
}

void saveUserDatabase(const string& username, const string& password) {
    lock_guard<mutex> lock(file_mutex);
    ofstream file("users.txt", ios::app);
    if (file.is_open()) {
        file << username << " " << password << "\n";
    }
}

bool authenticateUser(const string& username, const string& password) {
    if (!userDatabase.count(username)) return false;
    string hashedInput = hashPassword(password);
    return userDatabase[username] == hashedInput;
}
bool registerUser(const string& username, const string& password) {
    if (userDatabase.count(username)) return false;
    string hashedPassword = hashPassword(password);
    userDatabase[username] = hashedPassword;
    saveUserDatabase(username, hashedPassword);
    return true;
}

void storeEmail(const string& recipient, const string& email) {
    lock_guard<mutex> lock(file_mutex);
    ofstream outFile(recipient + "_emails.txt", ios::app | ios::binary);
    if (outFile.is_open()) {
        // Verify the email has 7 parts before storing
        size_t count = std::count(email.begin(), email.end(), '~');
        if (count != 6) { // 6 delimiters = 7 parts
            cerr << "ERROR: Invalid email format when storing (expected 7 parts)\n";
            return;
        }
        outFile << email << "\n---EMAIL_END---\n";
        outFile.flush();
    }
}

string retrieveEmails(const string& username) {
    lock_guard<mutex> lock(file_mutex);  // Thread safety

    // --- Phase 1: Read Emails ---
    string filename = username + "_emails.txt";
    ifstream inFile(filename, ios::binary);
    
    if (!inFile.is_open()) {
        cout << "[STATUS] No emails found for " << username << endl;
        return "No emails found\n---EMAIL_END---\n";
    }

    // Read content
    stringstream buffer;
    buffer << inFile.rdbuf();
    string content = buffer.str();
    inFile.close();

    // Ensure proper termination
    if (content.find("---EMAIL_END---") == string::npos) {
        content += "\n---EMAIL_END---\n";
    }

    // --- Phase 2: Clear File ---
    ofstream outFile(filename, ios::trunc | ios::binary);
    if (!outFile) {
        cerr << "[ERROR] Failed to clear email file for " << username << endl;
        // Still return the content we managed to read
        return content;
    }
    outFile.close();

    cout << "[STATUS] Emails retrieved and storage cleared for " << username << endl;
    return content;
}

void handleClient(int clientSocket) {
    loadUserDatabase();
    string username;
        char buffer[BUFFER_SIZE] = {0};
    bool authenticated = false;

    // Authentication
    while (!authenticated) {
        int bytes = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (bytes <= 0) break;
        
        string received(buffer, bytes);
        vector<string> parts;
        size_t pos = 0;
        
        while ((pos = received.find('\n')) != string::npos) {
            string part = received.substr(0, pos);
            if (!part.empty()) parts.push_back(part);
            received.erase(0, pos + 1);
        }

        if (parts.size() >= 3) {
            string choice = parts[0];
            username = parts[1];
            string password = parts[2];
            
            if (choice == "1") { // Login
                if (authenticateUser(username, password)) {
                    write(clientSocket, "AUTH_SUCCESS\n", 13);
                    authenticated = true;
                } else {
                    write(clientSocket, "AUTH_FAILED\n", 12);
                }
            } else if (choice == "2") { // Signup
                if (registerUser(username, password)) {
                    write(clientSocket, "AUTH_SUCCESS\n", 13);
                    authenticated = true;
                } else {
                    write(clientSocket, "USER_EXISTS\n", 12);
                }
            }
        }
    }

    // Rest of your email handling code..

    // Email operations
  while (authenticated) {
        string command = read_line(clientSocket);
        cout << "Received command: " << command << endl;

        if (command == "EMAIL_SEND") {
            // Read recipient
            string recipient = read_line(clientSocket);
            if (recipient.empty()) {
                write(clientSocket, "ERROR:NO_RECIPIENT\n", 19);
                continue;
            }

            // Read email packet
            string email_packet = read_line(clientSocket);
            if (email_packet.empty()) {
                write(clientSocket, "ERROR:NO_DATA\n", 14);
                continue;
            }

            // Verify end marker
            string end_marker = read_line(clientSocket);
            if (end_marker != "END_TRANSMISSION") {
                write(clientSocket, "ERROR:INVALID_END_MARKER\n", 24);
                continue;
            }

            // Store email
            storeEmail(recipient, email_packet);
            write(clientSocket, "OK:EMAIL_STORED\n", 16);
            cout << "Stored email for " << recipient << endl;
        }
      else if (command == "4") { // Retrieve emails
    string emails = retrieveEmails(username);
    if (emails.empty()) {
        emails = "No emails found\n---EMAIL_END---\n";
    }
    
    // Convert BUFFER_SIZE to size_t for comparison
    size_t buffer_size = static_cast<size_t>(BUFFER_SIZE);
    size_t total_sent = 0;
    
    while (total_sent < emails.size()) {
        size_t chunk_size = std::min(buffer_size, emails.size() - total_sent);
        int bytes = send(clientSocket, 
                        emails.c_str() + total_sent, 
                        chunk_size, 
                        0);
        if (bytes <= 0) {
            cerr << "Failed to send email data\n";
            break;
        }
        total_sent += bytes;
    }
}
        else if (command == "0") { // Exit
            break;
        }
    }
    close(clientSocket);
}
int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        cerr << "Socket creation failed\n";
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Bind failed\n";
        return 1;
    }

    if (listen(serverSocket, 10) < 0) {
        cerr << "Listen failed\n";
        return 1;
    }

    cout << "Gmail Server running on port " << PORT << endl;

    while (true) {
        sockaddr_in clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &addrLen);
        if (clientSocket < 0) {
            cerr << "Accept failed\n";
            continue;
        }
        thread(handleClient, clientSocket).detach();
    }

    close(serverSocket);
    return 0;
}
