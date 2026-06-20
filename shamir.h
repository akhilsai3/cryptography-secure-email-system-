// shamir.h
//
// Standalone Shamir Secret Sharing module (2-of-3 threshold).
//
// Scope of this module (Task 2 only):
//   - split_private_key(pem)         -> {Share1, Share2, Share3}
//   - reconstruct_private_key(s1,s2) -> pem
//
// This module knows nothing about sockets, login flow, Key Server,
// Recovery Server, or client.cpp. It operates purely on strings in
// memory: give it a PEM string, get back 3 share strings; give it any
// 2 of those 3 share strings, get back the original PEM string.
//
// Math: classic Shamir Secret Sharing over GF(2^8), applied byte-by-byte
// to the PEM string. Each output share is itself a string the same
// length as the input, prefixed with a 1-byte share index (0x01/0x02/0x03)
// so reconstruct_private_key knows which x-coordinate each byte came
// from regardless of which 2 of the 3 shares are supplied, and in
// what order.
//
// Threshold = 2: the secret polynomial for each byte is degree 1
// (f(x) = secret_byte XOR coeff1*x), so any 2 distinct (x, f(x)) points
// are sufficient to recover f(0) = secret_byte via Lagrange interpolation.
// Any single share leaks no information about the byte (information-
// theoretic security property of Shamir's scheme), matching the
// "Share 1 alone is useless" / "Share 2 alone is useless" guarantees
// from the architecture doc.

#ifndef SHAMIR_H
#define SHAMIR_H

#include <string>
#include <vector>

// Splits a PEM-encoded RSA private key string into exactly 3 shares
// using a 2-of-3 threshold Shamir scheme.
//
// Returns a vector of exactly 3 strings: {Share1, Share2, Share3}.
// On any internal error (e.g. RNG failure), returns an empty vector
// — callers must check the result size before using it.
//
// Each returned share is a self-contained string (1-byte index header
// + per-byte y-values) and can be stored as-is (e.g. sent over the
// existing STORE_SHARE wire format, written to a file, etc).
std::vector<std::string> split_private_key(const std::string& pem);

// Reconstructs the original PEM string from any 2 of the 3 shares
// produced by split_private_key. Order does not matter — passing
// (Share1, Share2), (Share1, Share3), or (Share2, Share3) all work,
// and so does passing them in either order.
//
// Returns the original PEM string on success, or an empty string if
// the shares are malformed, mismatched in length, or otherwise
// cannot be combined (callers must check for an empty result).
std::string reconstruct_private_key(const std::string& share_a,
                                     const std::string& share_b);

#endif // SHAMIR_H