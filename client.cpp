void send_email(int gmail_sock, int key_sock, EVP_PKEY* pkey, const string& sender_id) {
    if (gmail_sock <= 0 || key_sock <= 0) return;// Validate inputs and get recipient ID
    string recipient_id;
    cout << "Recipient ID: ";
    if (!(cin >> recipient_id)) return;
    cin.ignore();
    EVP_PKEY* recipient_pub = get_recipient_pubkey(key_sock, recipient_id);    // Get recipient's public key
    if (!recipient_pub) return;
    unsigned char aes_key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE]; // Generate crypto materials
    if (RAND_bytes(aes_key, AES_KEY_SIZE) != 1 || RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        EVP_PKEY_free(recipient_pub);
        return;
    }
    string message;
    cout << "Message: "; // Get message and add timestamp
    getline(cin, message);
    if (message.empty()) {
        EVP_PKEY_free(recipient_pub);
        return;
    }
    string full_msg = "Time: " + string(ctime(&time(0))) + message;
    auto encrypted_msg = aes_crypt((unsigned char*)full_msg.c_str(), full_msg.size(), aes_key, iv, true);// Encrypt and sign
    auto hmac = generate_HMAC(encrypted_msg.data(), encrypted_msg.size(), aes_key, AES_KEY_SIZE);
    auto signed_hmac = sign_data(hmac.data(), hmac.size(), pkey);
    auto encrypted_key = encrypt_key(aes_key, recipient_pub);
    auto signed_key = sign_data(encrypted_key.data(), encrypted_key.size(), pkey);
    string packet = sender_id + "~" + base64_encode(iv, AES_BLOCK_SIZE) + "~" +                      // Send packet
                   base64_encode(encrypted_msg.data(), encrypted_msg.size()) + "~" +
                   base64_encode(hmac.data(), hmac.size()) + "~" +
                   base64_encode(signed_hmac.data(), signed_hmac.size()) + "~" +
                   base64_encode(encrypted_key.data(), encrypted_key.size()) + "~" +
                   base64_encode(signed_key.data(), signed_key.size());
    send(gmail_sock, ("EMAIL_SEND\n" + recipient_id + "\n" + packet + "\nEND_TRANSMISSION\n").c_str());
    EVP_PKEY_free(recipient_pub);
}