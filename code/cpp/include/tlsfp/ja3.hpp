#ifndef TLSFP_JA3_HPP
#define TLSFP_JA3_HPP

#include "tlsfp/parser.hpp"
#include <string>
#include <string_view>

namespace tlsfp {

struct JA3Fingerprint {
    std::string raw_string;
    std::string md5_hash;
};

// Generates JA3 client fingerprint
JA3Fingerprint compute_ja3(const ClientHelloData &client);

// Generates JA3S server fingerprint
JA3Fingerprint compute_ja3s(const ServerHelloData &server);

// Utility: Compute lowercase 32-char hex MD5 using OpenSSL EVP
std::string md5_hex(const std::string &input);

}

#endif