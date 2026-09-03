#include "tlsfp/ja3.hpp"
#include <openssl/evp.h>
#include <charconv>

namespace tlsfp {

// Ground 3: Zero-allocation integer formatting via C++17 std::to_chars
template <typename T>
static inline void append_joined(std::string &out, const std::vector<T> &vec, char delimiter = '-') {
    char num_buf[16];
    for (size_t i = 0; i < vec.size(); ++i) {
        if (i > 0) {
            out += delimiter;
        }
        auto [ptr, ec] = std::to_chars(num_buf, num_buf + sizeof(num_buf), static_cast<uint32_t>(vec[i]));
        out.append(num_buf, static_cast<size_t>(ptr - num_buf));
    }
}

std::string md5_hex(const std::string &input) {
    // Ground 3: Reusable thread-local context avoids heap allocation per packet
    static thread_local EVP_MD_CTX *t_md5_ctx = nullptr;
    if (!t_md5_ctx) {
        t_md5_ctx = EVP_MD_CTX_new();
        if (!t_md5_ctx) return "";
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (EVP_DigestInit_ex(t_md5_ctx, EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(t_md5_ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(t_md5_ctx, digest, &digest_len) != 1) {
        return "";
    }

    // Ground 3: Direct 16-byte nibble LUT conversion (Replaces std::ostringstream)
    static constexpr char HEX_LUT[] = "0123456789abcdef";
    std::string hex_str;
    hex_str.resize(32);

    for (size_t i = 0; i < 16; ++i) {
        hex_str[i * 2]     = HEX_LUT[(digest[i] >> 4) & 0x0F];
        hex_str[i * 2 + 1] = HEX_LUT[digest[i] & 0x0F];
    }

    return hex_str;
}

JA3Fingerprint compute_ja3(const ClientHelloData &client) {
    JA3Fingerprint fp;
    
    // Ground 2: Pre-allocate 512 bytes to cover modern post-quantum ClientHellos
    fp.raw_string.reserve(512);

    // 1. SSLVersion (using stack buffer)
    char ver_buf[16];
    auto [ptr, ec] = std::to_chars(ver_buf, ver_buf + sizeof(ver_buf), client.client_version);
    fp.raw_string.append(ver_buf, static_cast<size_t>(ptr - ver_buf));
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
    char ver_buf[16];
    auto [ptr, ec] = std::to_chars(ver_buf, ver_buf + sizeof(ver_buf), server.server_version);
    fp.raw_string.append(ver_buf, static_cast<size_t>(ptr - ver_buf));
    fp.raw_string += ',';

    // 2. Selected Cipher Suite
    auto [c_ptr, c_ec] = std::to_chars(ver_buf, ver_buf + sizeof(ver_buf), server.selected_cipher);
    fp.raw_string.append(ver_buf, static_cast<size_t>(c_ptr - ver_buf));
    fp.raw_string += ',';

    // 3. Extensions
    append_joined(fp.raw_string, server.extensions);

    // Compute MD5
    fp.md5_hash = md5_hex(fp.raw_string);
    return fp;
}

} // namespace tlsfp