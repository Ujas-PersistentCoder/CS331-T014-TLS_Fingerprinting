#include "tlsfp/ja4.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <vector>
#include <cctype>

namespace tlsfp {

static constexpr char HEX_LUT[] = "0123456789abcdef";

static inline void append_hex4(std::string &out, uint16_t val) noexcept {
    out.push_back(HEX_LUT[(val >> 12) & 0x0F]);
    out.push_back(HEX_LUT[(val >> 8)  & 0x0F]);
    out.push_back(HEX_LUT[(val >> 4)  & 0x0F]);
    out.push_back(HEX_LUT[val & 0x0F]);
}

static inline void append_hex4_joined(std::string &out, const std::vector<uint16_t> &vec, char delim = ',') {
    for (size_t i = 0; i < vec.size(); ++i) {
        if (i > 0) out.push_back(delim);
        append_hex4(out, vec[i]);
    }
}

std::string sha256_hex_12(std::string_view input) {
    static thread_local EVP_MD_CTX *t_sha256_ctx = nullptr;
    if (!t_sha256_ctx) {
        t_sha256_ctx = EVP_MD_CTX_new();
        if (!t_sha256_ctx) return "000000000000";
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (EVP_DigestInit_ex(t_sha256_ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(t_sha256_ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(t_sha256_ctx, digest, &digest_len) != 1) {
        return "000000000000";
    }

    // Convert first 6 bytes of digest to 12 hex characters
    std::string hex_str;
    hex_str.resize(12);
    for (size_t i = 0; i < 6; ++i) {
        hex_str[i * 2]     = HEX_LUT[(digest[i] >> 4) & 0x0F];
        hex_str[i * 2 + 1] = HEX_LUT[digest[i] & 0x0F];
    }
    return hex_str;
}

static inline const char* resolve_ja4_version(const ClientHelloData &client) noexcept {
    uint16_t highest_ver = 0;
    if (!client.supported_versions.empty()) {
        for (uint16_t v : client.supported_versions) {
            if (v > highest_ver) highest_ver = v;
        }
    } else {
        highest_ver = client.client_version;
    }

    switch (highest_ver) {
        case 0x0304: return "13"; // TLS 1.3
        case 0x0303: return "12"; // TLS 1.2
        case 0x0302: return "11"; // TLS 1.1
        case 0x0301: return "10"; // TLS 1.0
        case 0x0300: return "s3"; // SSL 3.0
        case 0x0200: return "s2"; // SSL 2.0
        case 0x0100: return "s1"; // SSL 1.0
        default:     return "00";
    }
}

static inline void resolve_ja4_alpn(std::string_view alpn, char &first, char &last) noexcept {
    if (alpn.empty()) {
        first = '0';
        last  = '0';
        return;
    }
    char f = alpn.front();
    char l = alpn.back();
    first = std::isalnum(static_cast<unsigned char>(f)) ? f : '0';
    last  = std::isalnum(static_cast<unsigned char>(l)) ? l : '0';
}

JA4Fingerprint compute_ja4(const ClientHelloData &client) {
    JA4Fingerprint fp;

    // 1. Compute JA4_a (10 Characters)
    fp.ja4_a.reserve(10);
    fp.ja4_a.push_back('t'); // Protocol: TCP
    fp.ja4_a.append(resolve_ja4_version(client)); // TLS Version
    fp.ja4_a.push_back(client.has_sni ? 'd' : 'i'); // SNI status

    // Number of Ciphers (excluding GREASE, saturated at 99)
    size_t ciphers_count = std::min<size_t>(client.cipher_suites.size(), 99);
    fp.ja4_a.push_back(static_cast<char>('0' + (ciphers_count / 10)));
    fp.ja4_a.push_back(static_cast<char>('0' + (ciphers_count % 10)));

    // Filter Extensions: Exclude SNI (0x0000) and ALPN (0x0010)
    std::vector<uint16_t> filtered_exts;
    filtered_exts.reserve(client.extensions.size());
    for (uint16_t ext : client.extensions) {
        if (ext != 0x0000 && ext != 0x0010) {
            filtered_exts.push_back(ext);
        }
    }

    // Number of Extensions (excluding GREASE, SNI, ALPN, saturated at 99)
    size_t exts_count = std::min<size_t>(filtered_exts.size(), 99);
    fp.ja4_a.push_back(static_cast<char>('0' + (exts_count / 10)));
    fp.ja4_a.push_back(static_cast<char>('0' + (exts_count % 10)));

    // ALPN (2 chars)
    char alpn_first, alpn_last;
    resolve_ja4_alpn(client.first_alpn, alpn_first, alpn_last);
    fp.ja4_a.push_back(alpn_first);
    fp.ja4_a.push_back(alpn_last);

    // 2. Compute JA4_b (Sorted Ciphers, 12 hex chars)
    if (client.cipher_suites.empty()) {
        fp.ja4_b = "000000000000";
    } else {
        std::vector<uint16_t> sorted_ciphers = client.cipher_suites;
        std::sort(sorted_ciphers.begin(), sorted_ciphers.end());

        fp.raw_ja4_b.reserve(sorted_ciphers.size() * 5);
        append_hex4_joined(fp.raw_ja4_b, sorted_ciphers, ',');
        fp.ja4_b = sha256_hex_12(fp.raw_ja4_b);
    }

    // 3. Compute JA4_c (Sorted Extensions + Wire-Order SigAlgs, 12 hex chars)
    if (filtered_exts.empty() && client.signature_algorithms.empty()) {
        fp.ja4_c = "000000000000";
    } else {
        std::sort(filtered_exts.begin(), filtered_exts.end());

        fp.raw_ja4_c.reserve(filtered_exts.size() * 5 + client.signature_algorithms.size() * 5 + 2);
        append_hex4_joined(fp.raw_ja4_c, filtered_exts, ',');

        if (!client.signature_algorithms.empty()) {
            fp.raw_ja4_c.push_back('_');
            // Signature algorithms MUST maintain original wire order per JA4 spec
            append_hex4_joined(fp.raw_ja4_c, client.signature_algorithms, ',');
        }

        fp.ja4_c = sha256_hex_12(fp.raw_ja4_c);
    }

    // Assemble Full JA4 String
    fp.full_fp.reserve(36);
    fp.full_fp.append(fp.ja4_a).push_back('_');
    fp.full_fp.append(fp.ja4_b).push_back('_');
    fp.full_fp.append(fp.ja4_c);

    return fp;
}

JA4Fingerprint compute_ja4s(const ServerHelloData &server) {
    JA4Fingerprint fp;

    // 1. JA4S_a (7 characters: t + 2 version + 2 ext count + 2 alpn)
    fp.ja4_a.reserve(7);
    fp.ja4_a.push_back('t');

    // Version
    uint16_t ver = (server.selected_version != 0) ? server.selected_version : server.server_version;
    switch (ver) {
        case 0x0304: fp.ja4_a.append("13"); break;
        case 0x0303: fp.ja4_a.append("12"); break;
        case 0x0302: fp.ja4_a.append("11"); break;
        case 0x0301: fp.ja4_a.append("10"); break;
        default:     fp.ja4_a.append("00"); break;
    }

    // Filter Extensions (exclude ALPN 0x0010 and GREASE)
    std::vector<uint16_t> filtered_exts;
    filtered_exts.reserve(server.extensions.size());
    for (uint16_t ext : server.extensions) {
        if (ext != 0x0010) {
            filtered_exts.push_back(ext);
        }
    }

    // Extension Count (2 digits, saturated at 99)
    size_t exts_count = std::min<size_t>(filtered_exts.size(), 99);
    fp.ja4_a.push_back(static_cast<char>('0' + (exts_count / 10)));
    fp.ja4_a.push_back(static_cast<char>('0' + (exts_count % 10)));

    // Negotiated ALPN
    char alpn_first, alpn_last;
    resolve_ja4_alpn(server.first_alpn, alpn_first, alpn_last);
    fp.ja4_a.push_back(alpn_first);
    fp.ja4_a.push_back(alpn_last);

    // 2. JA4S_b (Selected Cipher in 4 hex digits)
    fp.ja4_b.reserve(4);
    append_hex4(fp.ja4_b, server.selected_cipher);

    // 3. JA4S_c (Sorted Extensions Hash)
    if (filtered_exts.empty()) {
        fp.ja4_c = "000000000000";
    } else {
        std::sort(filtered_exts.begin(), filtered_exts.end());
        fp.raw_ja4_c.reserve(filtered_exts.size() * 5);
        append_hex4_joined(fp.raw_ja4_c, filtered_exts, ',');
        fp.ja4_c = sha256_hex_12(fp.raw_ja4_c);
    }

    // Assemble Full JA4S
    fp.full_fp.reserve(26);
    fp.full_fp.append(fp.ja4_a).push_back('_');
    fp.full_fp.append(fp.ja4_b).push_back('_');
    fp.full_fp.append(fp.ja4_c);

    return fp;
}

} // namespace tlsfp