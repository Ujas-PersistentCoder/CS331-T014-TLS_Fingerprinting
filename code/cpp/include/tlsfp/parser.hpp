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
    std::vector<uint16_t> supported_groups;   // Elliptic curves (Ext 0x000a)
    std::vector<uint8_t>  ec_point_formats;   // Point formats (Ext 0x000b)
    std::vector<std::string> alpn_protocols;  // Ext 0x0010
    std::vector<uint16_t> supported_versions; // Ext 0x002b (TLS 1.3 indicators)
    std::string sni;                          // Ext 0x0000
    bool has_sni{false};

    void clear() {
        client_version = 0;
        cipher_suites.clear();
        extensions.clear();
        supported_groups.clear();
        ec_point_formats.clear();
        supported_versions.clear();
        alpn_protocols.clear();
        sni.clear();
        has_sni = false;
    }
};

struct ServerHelloData {
    uint16_t server_version{0};
    uint16_t selected_cipher{0};
    std::vector<uint16_t> extensions;
    uint16_t selected_version{0};             // Ext 0x002b
    std::string negotiated_alpn;              // Ext 0x0010

    void clear() {
        server_version = 0;
        selected_cipher = 0;
        extensions.clear();
        selected_version = 0;
        negotiated_alpn.clear();
    }
};

// Zero-copy parser functions
bool parse_client_hello(const uint8_t *payload, size_t len, ClientHelloData &out);
bool parse_server_hello(const uint8_t *payload, size_t len, ServerHelloData &out);

} // namespace tlsfp

#endif // TLSFP_PARSER_HPP