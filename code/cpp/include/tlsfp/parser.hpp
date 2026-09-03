#ifndef TLSFP_PARSER_HPP
#define TLSFP_PARSER_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace tlsfp {

// Bitwise check for all 16 RFC 8701 GREASE values (0x0a0a, 0x1a1a, ..., 0xfafa)
inline bool is_grease(uint16_t val) noexcept {
    return ((val & 0x0f0f) == 0x0a0a) && ((val >> 8) == (val & 0x00ff));
}

struct ClientHelloData {
    uint16_t client_version{0};
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> supported_groups;
    std::vector<uint8_t>  ec_point_formats;
    std::vector<uint16_t> supported_versions;
    std::vector<uint16_t> signature_algorithms; // Required for JA4_c

    bool has_sni{false};
    std::string_view sni;                       // Zero-allocation string_view
    std::string_view first_alpn;                // Required for JA4_a

    void clear() noexcept {
        client_version = 0;
        cipher_suites.clear();
        extensions.clear();
        supported_groups.clear();
        ec_point_formats.clear();
        supported_versions.clear();
        signature_algorithms.clear();
        has_sni = false;
        sni = {};
        first_alpn = {};
    }
};

struct ServerHelloData {
    uint16_t server_version{0};
    uint16_t selected_version{0};
    uint16_t selected_cipher{0};
    std::vector<uint16_t> extensions;
    std::string_view first_alpn; // Added: Server-negotiated ALPN protocol

    void clear() noexcept {
        server_version = 0;
        selected_version = 0;
        selected_cipher = 0;
        extensions.clear();
        first_alpn = {};
    }
};

// Zero-copy parser functions
bool parse_client_hello(const uint8_t *payload, size_t len, ClientHelloData &out);
bool parse_server_hello(const uint8_t *payload, size_t len, ServerHelloData &out);

} // namespace tlsfp

#endif // TLSFP_PARSER_HPP