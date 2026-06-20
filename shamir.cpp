// shamir.cpp
//
// Implementation of the standalone 2-of-3 Shamir Secret Sharing module.
// See shamir.h for the public interface and scope notes.
//
// ---------------------------------------------------------------------
// How a share is laid out
// ---------------------------------------------------------------------
// Splitting is done one byte at a time. For each byte of the input PEM
// string we build a random degree-1 polynomial
//
//     f(x) = secret_byte XOR (coeff1 * x)      (all arithmetic in GF(2^8))
//
// and evaluate it at x = 1, 2, 3 to get the three shares' bytes for
// that position. Because the polynomial has degree (threshold - 1) = 1,
// any 2 of the 3 (x, f(x)) points are enough to recover f(0) = secret_byte
// via Lagrange interpolation; a single point reveals nothing about the
// secret byte (Shamir's information-theoretic guarantee).
//
// A returned share string is:
//     [1 byte: x-coordinate index (1, 2, or 3)] + [N bytes: y-values]
// where N = length of the original PEM string. Prefixing the index
// means reconstruct_private_key can be handed any 2 of the 3 shares,
// in either order, and still know which x-coordinate each one is.
//
// ---------------------------------------------------------------------
// Field arithmetic
// ---------------------------------------------------------------------
// We use GF(2^8) with the same reduction polynomial AES uses
// (x^8 + x^4 + x^3 + x + 1, i.e. 0x11B) purely because it's a
// well-known, well-tested choice with simple log/exp tables — there is
// no cryptographic dependency on AES itself here, just the field.

#include "shamir.h"

#include <openssl/rand.h>
#include <cstdint>
#include <array>

namespace {

// ---- GF(2^8) log / exp tables, generator g = 0x03 ----
// exp_table[i]  = g^i  for i in [0, 509] (extended range avoids extra
//                 modulo when multiplying via log addition)
// log_table[a]  = i such that g^i = a, for a in [1, 255] (log_table[0]
//                 is unused/undefined, as 0 has no logarithm)
struct GF256Tables {
    std::array<uint8_t, 510> exp_table{};
    std::array<uint8_t, 256> log_table{};

    GF256Tables() {
        // Build via repeated multiplication by the generator, using the
        // textbook carry-less multiply + reduce (only needed here, at
        // table-build time, not on the hot path).
        uint16_t x = 1;
        for (int i = 0; i < 255; ++i) {
            exp_table[i] = static_cast<uint8_t>(x);
            log_table[x] = static_cast<uint8_t>(i);

            // multiply x by generator 0x03 = 0x02 ^ 0x01, i.e. (x<<1) XOR x,
            // reduced mod the AES polynomial 0x11B if it overflows 8 bits
            uint16_t doubled = x << 1;
            if (doubled & 0x100) {
                doubled ^= 0x11B;
            }
            x = doubled ^ x;
        }
        // Extend exp_table so exp_table[i] for i in [255, 509] mirrors
        // exp_table[i - 255]; lets gf_mul skip a modulo on the index sum.
        for (int i = 255; i < 510; ++i) {
            exp_table[i] = exp_table[i - 255];
        }
    }
};

const GF256Tables& tables() {
    static const GF256Tables t;
    return t;
}

uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    const auto& t = tables();
    int sum = static_cast<int>(t.log_table[a]) + static_cast<int>(t.log_table[b]);
    return t.exp_table[sum];
}

uint8_t gf_inv(uint8_t a) {
    // a must be nonzero; caller guarantees this (x-coordinates are 1..3,
    // and differences of distinct x-coordinates are always nonzero too).
    const auto& t = tables();
    return t.exp_table[255 - t.log_table[a]];
}

uint8_t gf_div(uint8_t a, uint8_t b) {
    if (a == 0) return 0;
    return gf_mul(a, gf_inv(b));
}

// Cryptographically random nonzero-safe byte (any value 0-255 is fine
// for a polynomial coefficient — coefficients are allowed to be zero).
bool random_byte(uint8_t& out) {
    return RAND_bytes(&out, 1) == 1;
}

constexpr int THRESHOLD = 2;   // degree-1 polynomials: 2 points reconstruct
constexpr int NUM_SHARES = 3;  // x-coordinates 1, 2, 3

} // namespace

std::vector<std::string> split_private_key(const std::string& pem) {
    if (pem.empty()) {
        return {};
    }

    const size_t n = pem.size();

    // One body buffer per share (the index-byte header is prepended at
    // the end, once we know we succeeded for every byte).
    std::array<std::string, NUM_SHARES> bodies;
    for (auto& b : bodies) b.resize(n);

    for (size_t i = 0; i < n; ++i) {
        uint8_t secret_byte = static_cast<uint8_t>(pem[i]);

        // Degree-1 polynomial: f(x) = secret_byte XOR (coeff1 * x).
        // Threshold-1 = 1 random coefficient.
        uint8_t coeff1;
        if (!random_byte(coeff1)) {
            return {}; // RNG failure - caller must treat as hard failure
        }

        for (int share_idx = 0; share_idx < NUM_SHARES; ++share_idx) {
            uint8_t x = static_cast<uint8_t>(share_idx + 1); // x = 1, 2, 3
            uint8_t y = secret_byte ^ gf_mul(coeff1, x);
            bodies[share_idx][i] = static_cast<char>(y);
        }
    }

    std::vector<std::string> shares;
    shares.reserve(NUM_SHARES);
    for (int share_idx = 0; share_idx < NUM_SHARES; ++share_idx) {
        std::string share;
        share.reserve(n + 1);
        share.push_back(static_cast<char>(share_idx + 1)); // x-coordinate header
        share += bodies[share_idx];
        shares.push_back(std::move(share));
    }

    return shares;
}

std::string reconstruct_private_key(const std::string& share_a,
                                     const std::string& share_b) {
    // Minimum valid share is 1 header byte + at least 1 data byte.
    if (share_a.size() < 2 || share_b.size() < 2) {
        return "";
    }
    if (share_a.size() != share_b.size()) {
        return ""; // shares must come from the same split() call
    }

    uint8_t x_a = static_cast<uint8_t>(share_a[0]);
    uint8_t x_b = static_cast<uint8_t>(share_b[0]);

    if (x_a < 1 || x_a > NUM_SHARES || x_b < 1 || x_b > NUM_SHARES) {
        return ""; // not a header byte this module produced
    }
    if (x_a == x_b) {
        return ""; // need two *distinct* shares, e.g. not Share1 twice
    }

    const size_t n = share_a.size() - 1;
    std::string pem;
    pem.resize(n);

    for (size_t i = 0; i < n; ++i) {
        uint8_t y_a = static_cast<uint8_t>(share_a[1 + i]);
        uint8_t y_b = static_cast<uint8_t>(share_b[1 + i]);

        // Lagrange interpolation at x = 0, for 2 points (x_a, y_a), (x_b, y_b):
        //
        //   f(0) = y_a * (x_b / (x_a XOR x_b))   [since "x_a - x_b" in GF(2^n) is XOR]
        //        XOR y_b * (x_a / (x_a XOR x_b))
        //
        // (standard 2-point Lagrange basis, specialized to GF(2^8) where
        // subtraction is XOR)
        uint8_t denom = x_a ^ x_b; // always nonzero here since x_a != x_b
        uint8_t term_a = gf_mul(y_a, gf_div(x_b, denom));
        uint8_t term_b = gf_mul(y_b, gf_div(x_a, denom));
        uint8_t secret_byte = term_a ^ term_b;

        pem[i] = static_cast<char>(secret_byte);
    }

    return pem;
}