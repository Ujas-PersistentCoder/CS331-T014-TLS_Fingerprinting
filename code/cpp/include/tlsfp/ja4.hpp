#ifndef TLSFP_JA4_HPP
#define TLSFP_JA4_HPP

#include "tlsfp/parser.hpp"
#include <string>
#include <string_view>

namespace tlsfp {

struct JA4Fingerprint {
    std::string full_fp;   // e.g. t13d1516h2_8daaf6152771_e56270d44002
    std::string ja4_a;     // t13d1516h2
    std::string ja4_b;     // 8daaf6152771
    std::string ja4_c;     // e56270d44002
    std::string raw_ja4_b; // Raw sorted ciphers before hashing
    std::string raw_ja4_c; // Raw sorted extensions and wire-order sigalgs
};

std::string sha256_hex_12(std::string_view input);

JA4Fingerprint compute_ja4(const ClientHelloData &client);
JA4Fingerprint compute_ja4s(const ServerHelloData &server); // Added

} // namespace tlsfp

#endif // TLSFP_JA4_HPP