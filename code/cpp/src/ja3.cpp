#include "tlsfp/ja3.hpp"
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

namespace tlsfp {

template <typename T>
static void append_joined(std::string &out, const std::vector<T> &vec, char delimiter = '-') {
    for (size_t i = 0; i < vec.size(); ++i) {
        if (i > 0) out += delimiter;
        out += std::to_string(static_cast<uint32_t>(vec[i]));
    }
}

std::string md5_hex(const std::string &input) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    EVP_MD_CTX_free(ctx);

    // Convert raw 16 bytes to 32-character lowercase hex string
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digest_len; ++i) {
        oss << std::setw(2) << static_cast<int>(digest[i]);
    }
    return oss.str();
}

JA3Fingerprint compute_ja3(const ClientHelloData &client) {
    JA3Fingerprint fp;
    
    // Pre-reserve to minimize reallocations
    fp.raw_string.reserve(256);

    // 1. SSLVersion (in decimal)
    fp.raw_string += std::to_string(client.client_version);
    fp.raw_string += ',';

    // 2. Cipher Suites
    append_joined(fp.raw_string, client.cipher_suites);
    fp.raw_string += ',';

    // 3. Extensions
    append_joined(fp.raw_string, client.extensions);
    fp.raw_string += ',';

    // 4. Elliptic Curves (Supported Groups)
    append_joined(fp.raw_string, client.supported_groups);
    fp.raw_string += ',';

    // 5. Elliptic Curve Point Formats
    append_joined(fp.raw_string, client.ec_point_formats);

    // Compute MD5
    fp.md5_hash = md5_hex(fp.raw_string);
    return fp;
}

JA3Fingerprint compute_ja3s(const ServerHelloData &server) {
    JA3Fingerprint fp;
    fp.raw_string.reserve(128);

    // 1. SSLVersion
    fp.raw_string += std::to_string(server.server_version);
    fp.raw_string += ',';

    // 2. Selected Cipher Suite
    fp.raw_string += std::to_string(server.selected_cipher);
    fp.raw_string += ',';

    // 3. Extensions
    append_joined(fp.raw_string, server.extensions);

    // Compute MD5
    fp.md5_hash = md5_hex(fp.raw_string);
    return fp;
}

} // namespace tlsfp