#include "tlsfp/ja4.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <vector>

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

// RAII Wrapper for thread-local OpenSSL SHA256 context
struct ThreadLocalSha256Context {
    EVP_MD_CTX *ctx{nullptr};
    ThreadLocalSha256Context() : ctx(EVP_MD_CTX_new()) {}
    ~ThreadLocalSha256Context() {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
            ctx = nullptr;
        }
    }
    ThreadLocalSha256Context(const ThreadLocalSha256Context&) = delete;
    ThreadLocalSha256Context& operator=(const ThreadLocalSha256Context&) = delete;
};

std::string sha256_hex_12(std::string_view input) {
    static thread_local ThreadLocalSha256Context tls_ctx;
    if (!tls_ctx.ctx) return "000000000000";

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (EVP_DigestInit_ex(tls_ctx.ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(tls_ctx.ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(tls_ctx.ctx, digest, &digest_len) != 1) {
        return "000000000000";
    }

    // Convert first 6 bytes of digest to 12 hex characters
    std::string hex_str;
    hex_str.resize(12);
    for (size_t i = 0; i < 6; ++i) {
        hex_str[i * 2] = HEX_LUT[(digest[i] >> 4) & 0x0F];
        hex_str[i * 2 + 1] = HEX_LUT[digest[i] & 0x0F];
    }
    return hex_str;
}

// JA4 spec version table (technical_details/JA4.md, "TLS and DTLS Version")
static inline const char* ja4_version_code(uint16_t version) noexcept {
    switch (version) {
        case 0x0304: return "13"; // TLS 1.3
        case 0x0303: return "12"; // TLS 1.2
        case 0x0302: return "11"; // TLS 1.1
        case 0x0301: return "10"; // TLS 1.0
        case 0x0300: return "s3"; // SSL 3.0
        case 0x0002: return "s2"; // SSL 2.0
        case 0xfeff: return "d1"; // DTLS 1.0
        case 0xfefd: return "d2"; // DTLS 1.2
        case 0xfefc: return "d3"; // DTLS 1.3
        default:     return "00";
    }
}

// Highest non-GREASE supported_versions value (parser already drops GREASE), else the
// ClientHello's legacy_version. An unknown highest value maps to "00", as in FoxIO's reference.
static inline const char* resolve_ja4_version(const ClientHelloData &client) noexcept {
    if (!client.supported_versions.empty()) {
        return ja4_version_code(*std::max_element(client.supported_versions.begin(),
                                                  client.supported_versions.end()));
    }
    return ja4_version_code(client.client_version);
}

static inline bool is_ascii_alnum(unsigned char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

// First and last character of the first ALPN value, unchanged. If either end byte is not
// ASCII alphanumeric, the first and last characters of the value's hex encoding instead
// (spec examples: 0xAB -> "ab", 0x30 0xAB -> "3b", 0x61 0x20 -> "60").
static inline void resolve_ja4_alpn(std::string_view alpn, char &first, char &last) noexcept {
    if (alpn.empty()) {
        first = '0';
        last  = '0';
        return;
    }
    const auto f = static_cast<unsigned char>(alpn.front());
    const auto l = static_cast<unsigned char>(alpn.back());
    if (is_ascii_alnum(f) && is_ascii_alnum(l)) {
        first = static_cast<char>(f);
        last  = static_cast<char>(l);
    } else {
        first = HEX_LUT[f >> 4];
        last  = HEX_LUT[l & 0x0F];
    }
}

JA4Fingerprint compute_ja4(const ClientHelloData &client) {
    JA4Fingerprint fp;

    // 1. Compute JA4_a (10 Characters)
    fp.ja4_a.reserve(10);
    fp.ja4_a.push_back('t'); // Protocol: TCP
    fp.ja4_a.append(resolve_ja4_version(client)); // TLS Version
    // 'd' whenever the SNI extension is present, whatever it contains (spec: "If the SNI
    // extension (0x0000) exists, then the destination of the connection is a domain")
    const bool has_sni_ext =
        std::find(client.extensions.begin(), client.extensions.end(), uint16_t{0x0000}) != client.extensions.end();
    fp.ja4_a.push_back(has_sni_ext ? 'd' : 'i');
    // Number of Ciphers (excluding GREASE, saturated at 99)
    size_t ciphers_count = std::min<size_t>(client.cipher_suites.size(), 99);
    fp.ja4_a.push_back(static_cast<char>('0' + (ciphers_count / 10)));
    fp.ja4_a.push_back(static_cast<char>('0' + (ciphers_count % 10)));

    // Number of Extensions in JA4_a: All non-GREASE extensions (including SNI and ALPN)
    size_t exts_count = std::min<size_t>(client.extensions.size(), 99);
    fp.ja4_a.push_back(static_cast<char>('0' + (exts_count / 10)));
    fp.ja4_a.push_back(static_cast<char>('0' + (exts_count % 10)));

    // Filter Extensions for JA4_c: Exclude SNI (0x0000) and ALPN (0x0010)
    std::vector<uint16_t> filtered_exts;
    filtered_exts.reserve(client.extensions.size());
    for (uint16_t ext : client.extensions) {
        if (ext != 0x0000 && ext != 0x0010) {
            filtered_exts.push_back(ext);
        }
    }

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
    const uint16_t ver = (server.selected_version != 0) ? server.selected_version : server.server_version;
    fp.ja4_a.append(ja4_version_code(ver));

    // Extension count: every extension the server sent, ALPN and GREASE included
    // (FoxIO reference to_ja4s: "extensions ... in the order they are present (include grease values)")
    size_t exts_count = std::min<size_t>(server.extensions.size(), 99);
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

    // 3. JA4S_c: hash of the extensions in WIRE order. Unlike JA4, nothing is sorted or
    // removed: the server's extension order is part of its fingerprint.
    if (server.extensions.empty()) {
        fp.ja4_c = "000000000000";
    } else {
        fp.raw_ja4_c.reserve(server.extensions.size() * 5);
        append_hex4_joined(fp.raw_ja4_c, server.extensions, ',');
        fp.ja4_c = sha256_hex_12(fp.raw_ja4_c);
    }

    // Assemble Full JA4S
    fp.full_fp.reserve(26);
    fp.full_fp.append(fp.ja4_a).push_back('_');
    fp.full_fp.append(fp.ja4_b).push_back('_');
    fp.full_fp.append(fp.ja4_c);

    return fp;
}

}