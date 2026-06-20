// test_shamir.cpp
//
// Standalone test harness for the Shamir module. Not part of the
// project's running servers/client — just verifies:
//
//   Private Key -> split -> Share1, Share2, Share3 -> combine (any 2) -> same Private Key
//
// exactly as required before any integration with login/registration.

#include "shamir.h"
#include <iostream>
#include <fstream>
#include <sstream>

static std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static bool check(const std::string& label, bool cond) {
    std::cout << (cond ? "[PASS] " : "[FAIL] ") << label << std::endl;
    return cond;
}

int main() {
    bool all_ok = true;

    std::string pem = read_file("test_key.pem");
    all_ok &= check("loaded test PEM (non-empty)", !pem.empty());
    std::cout << "  PEM length: " << pem.size() << " bytes" << std::endl;

    // --- Split ---
    std::vector<std::string> shares = split_private_key(pem);
    all_ok &= check("split_private_key returned 3 shares", shares.size() == 3);
    if (shares.size() == 3) {
        for (size_t i = 0; i < 3; ++i) {
            std::cout << "  Share" << (i + 1) << " length: " << shares[i].size()
                       << " bytes (header byte + " << (shares[i].size() - 1)
                       << " data bytes)" << std::endl;
        }
        all_ok &= check("each share length == pem length + 1",
                         shares[0].size() == pem.size() + 1 &&
                         shares[1].size() == pem.size() + 1 &&
                         shares[2].size() == pem.size() + 1);

        // Sanity: shares must not be byte-identical to each other or to the PEM
        all_ok &= check("Share1 != Share2", shares[0] != shares[1]);
        all_ok &= check("Share2 != Share3", shares[1] != shares[2]);
        all_ok &= check("Share1 != Share3", shares[0] != shares[2]);
    }

    // --- Reconstruct from all 3 possible pairs, both orderings each ---
    struct Pair { int a, b; const char* label; };
    Pair pairs[] = {
        {0, 1, "Share1 + Share2"},
        {0, 2, "Share1 + Share3"},
        {1, 2, "Share2 + Share3"},
    };

    for (auto& p : pairs) {
        std::string rec_ab = reconstruct_private_key(shares[p.a], shares[p.b]);
        std::string rec_ba = reconstruct_private_key(shares[p.b], shares[p.a]); // order shouldn't matter
        all_ok &= check(std::string(p.label) + " reconstructs original PEM", rec_ab == pem);
        all_ok &= check(std::string(p.label) + " (reversed order) reconstructs original PEM", rec_ba == pem);
    }

    // --- Negative cases ---
    std::string same_share_twice = reconstruct_private_key(shares[0], shares[0]);
    all_ok &= check("reconstructing from Share1+Share1 fails (returns empty)",
                     same_share_twice.empty());

    std::string bad_len = reconstruct_private_key(shares[0], std::string("short"));
    all_ok &= check("mismatched-length shares fail (returns empty)", bad_len.empty());

    auto empty_split = split_private_key("");
    all_ok &= check("splitting empty string returns empty vector", empty_split.empty());

    std::cout << std::endl << (all_ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << std::endl;
    return all_ok ? 0 : 1;
}
