#include "tlsfp/parser.hpp"
#include <cstring>
#include <algorithm>
#include <string_view>

namespace tlsfp {

// Lightweight byte reader with bounds checking
struct ByteReader {
    const uint8_t *data;
    size_t len;
    size_t offset{0};

    inline bool has_bytes(size_t n) const noexcept {
        return (n <= len && offset <= len - n);
    }

    inline uint8_t read_u8() noexcept {
        return data[offset++];
    }

    inline uint16_t read_u16() noexcept {
        uint16_t val = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
        return val;
    }

    inline uint32_t read_u24() noexcept {
        uint32_t val = (static_cast<uint32_t>(data[offset]) << 16) |
                       (static_cast<uint32_t>(data[offset + 1]) << 8)  |
                       data[offset + 2];
        offset += 3;
        return val;
    }

    inline bool skip(size_t n) noexcept {
        if (!has_bytes(n)) return false;
        offset += n;
        return true;
    }
};

// Evaluates if a 2-byte ALPN string is an RFC 8701 GREASE value
inline bool is_alpn_grease(std::string_view alpn) noexcept {
    if (alpn.size() != 2) return false;
    uint8_t b1 = static_cast<uint8_t>(alpn[0]);
    uint8_t b2 = static_cast<uint8_t>(alpn[1]);
    return (b1 == b2) && ((b1 & 0x0F) == 0x0A);
}

// Parse the extensions vector from a ClientHello message
static void parse_extensions(ByteReader &reader, size_t exts_len, ClientHelloData &out) {
    const size_t end_offset = reader.offset + exts_len;

    while (reader.offset + 4 <= end_offset) {
        uint16_t ext_type = reader.read_u16();
        uint16_t ext_len = reader.read_u16();

        // Prevent extension length from overrunning the extension block
        if (reader.offset + ext_len > end_offset) {
            break;
        }

        // Filter GREASE extension types (RFC 8701)
        if (!is_grease(ext_type)) {
            out.extensions.push_back(ext_type);
        }

        const size_t ext_start = reader.offset;

        switch (ext_type) {
            // Extension 0x0000: Server Name Indication (SNI)
            case 0x0000: {
                if (ext_len >= 5) {
                    ByteReader sni_reader{reader.data, ext_start + ext_len, ext_start};
                    uint16_t list_len = sni_reader.read_u16();
                    if (list_len + 2 <= ext_len && sni_reader.has_bytes(3)) {
                        uint8_t name_type = sni_reader.read_u8();
                        uint16_t name_len = sni_reader.read_u16();
                        // 0 = host_name per RFC 6066
                        if (name_type == 0 && name_len <= list_len - 3 && sni_reader.has_bytes(name_len)) {
                            out.has_sni = true;
                            // Zerocopy std::string_view eliminates heap allocation
                            out.sni = std::string_view(reinterpret_cast<const char*>(sni_reader.data + sni_reader.offset), name_len);
                        }
                    }
                }
                break;
            }

            // Extension 0x000a: Supported Groups / Elliptic Curves
            case 0x000a: {
                if (ext_len >= 2) {
                    ByteReader ec_reader{reader.data, ext_start + ext_len, ext_start};
                    uint16_t curves_len = ec_reader.read_u16();
                    // Enforce even-byte alignment and bounds check
                    size_t valid_curves_len = std::min<size_t>(curves_len, ext_len - 2);
                    size_t ec_end = ec_reader.offset + (valid_curves_len & ~1ULL);

                    while (ec_reader.offset + 2 <= ec_end) {
                        uint16_t group = ec_reader.read_u16();
                        if (!is_grease(group)) {
                            out.supported_groups.push_back(group);
                        }
                    }
                }
                break;
            }

            // Extension 0x000b: EC Point Formats
            case 0x000b: {
                if (ext_len >= 1) {
                    ByteReader pt_reader{reader.data, ext_start + ext_len, ext_start};
                    uint8_t formats_len = pt_reader.read_u8();
                    size_t pt_end = pt_reader.offset + std::min<size_t>(formats_len, ext_len - 1);
                    while (pt_reader.offset < pt_end) {
                        out.ec_point_formats.push_back(pt_reader.read_u8());
                    }
                }
                break;
            }

            // Extension 0x000d: Signature Algorithms (Required for JA4_c)
            case 0x000d: {
                if (ext_len >= 2) {
                    ByteReader sig_reader{reader.data, ext_start + ext_len, ext_start};
                    uint16_t sig_len = sig_reader.read_u16();
                    size_t valid_sig_len = std::min<size_t>(sig_len, ext_len - 2);
                    size_t sig_end = sig_reader.offset + (valid_sig_len & ~1ULL);

                    while (sig_reader.offset + 2 <= sig_end) {
                        uint16_t sig_algo = sig_reader.read_u16();
                        if (!is_grease(sig_algo)) {
                            out.signature_algorithms.push_back(sig_algo);
                        }
                    }
                }
                break;
            }

            // Extension 0x0010: ALPN (Required for JA4_a)
            case 0x0010: {
                if (ext_len >= 2) {
                    ByteReader alpn_reader{reader.data, ext_start + ext_len, ext_start};
                    uint16_t list_len = alpn_reader.read_u16();
                    if (list_len + 2 <= ext_len) {
                        const size_t list_end = alpn_reader.offset + list_len;
                        while (alpn_reader.offset < list_end && alpn_reader.has_bytes(1)) {
                            uint8_t proto_len = alpn_reader.read_u8();
                            if (proto_len == 0 || !alpn_reader.has_bytes(proto_len)) break;

                            std::string_view cand(
                                reinterpret_cast<const char*>(alpn_reader.data + alpn_reader.offset), 
                                proto_len
                            );
                            alpn_reader.skip(proto_len);

                            // Skip GREASE ALPN values to prevent JA4 fingerprint drift
                            if (!is_alpn_grease(cand)) {
                                out.first_alpn = cand;
                                break;
                            }
                        }
                    }
                }
                break;
            }

            // Extension 0x002b: Supported Versions (TLS 1.3)
            case 0x002b: {
                if (ext_len >= 1) {
                    ByteReader ver_reader{reader.data, ext_start + ext_len, ext_start};
                    uint8_t versions_len = ver_reader.read_u8();
                    size_t valid_ver_len = std::min<size_t>(versions_len, ext_len - 1);
                    size_t ver_end = ver_reader.offset + (valid_ver_len & ~1ULL);

                    while (ver_reader.offset + 2 <= ver_end) {
                        uint16_t ver = ver_reader.read_u16();
                        if (!is_grease(ver)) {
                            out.supported_versions.push_back(ver);
                        }
                    }
                }
                break;
            }

            default:
                break;
        }

        reader.offset = ext_start + ext_len; // Deterministically advance to next block
    }
}

bool parse_client_hello(const uint8_t *payload, size_t len, ClientHelloData &out) {
    ByteReader reader{payload, len, 0};

    // Record Header (5 bytes)
    if (!reader.has_bytes(5)) return false;
    if (reader.read_u8() != 0x16) return false; // Handshake record type

    reader.skip(2); // Skip legacy record version (0x0301 / 0x0303)
    uint16_t record_len = reader.read_u16();
    if (!reader.has_bytes(record_len)) return false;

    // Handshake Header (4 bytes)
    if (!reader.has_bytes(4)) return false;
    if (reader.read_u8() != 0x01) return false; // ClientHello handshake type

    uint32_t handshake_len = reader.read_u24();
    // Validate handshake framing against record boundary
    if (handshake_len + 4 > record_len || !reader.has_bytes(handshake_len)) {
        return false;
    }
    reader.len = reader.offset + handshake_len;
    // Client Version
    if (!reader.has_bytes(2)) return false;
    out.client_version = reader.read_u16();

    // Skip Client Random (32 bytes)
    if (!reader.skip(32)) return false;

    // Skip Session ID
    if (!reader.has_bytes(1)) return false;
    uint8_t session_id_len = reader.read_u8();
    if (!reader.skip(session_id_len)) return false;

    // Cipher Suites (with GREASE filtering)
    if (!reader.has_bytes(2)) return false;
    uint16_t cipher_suites_len = reader.read_u16();
    if (!reader.has_bytes(cipher_suites_len) || (cipher_suites_len % 2 != 0)) return false;

    const size_t cipher_end = reader.offset + cipher_suites_len;
    while (reader.offset < cipher_end) {
        uint16_t cs = reader.read_u16();
        if (!is_grease(cs)) {
            out.cipher_suites.push_back(cs);
        }
    }

    // Compression Methods
    if (!reader.has_bytes(1)) return false;
    uint8_t compression_len = reader.read_u8();
    if (!reader.skip(compression_len)) return false;

    // Extensions Vector
    if (reader.has_bytes(2)) {
        uint16_t extensions_len = reader.read_u16();
        if (!reader.has_bytes(extensions_len)) {
            return false; // Truncated extensions must fail parsing
        }
        parse_extensions(reader, extensions_len, out);
    }

    return true;
}

bool parse_server_hello(const uint8_t *payload, size_t len, ServerHelloData &out) {
    ByteReader reader{payload, len, 0};

    // Record Header
    if (!reader.has_bytes(5)) return false;
    if (reader.read_u8() != 0x16) return false;

    reader.skip(2); // Skip record version
    uint16_t record_len = reader.read_u16();
    if (!reader.has_bytes(record_len)) return false;

    // Handshake Header
    if (!reader.has_bytes(4)) return false;
    if (reader.read_u8() != 0x02) return false; // ServerHello handshake type

    uint32_t handshake_len = reader.read_u24();
    if (handshake_len + 4 > record_len || !reader.has_bytes(handshake_len)) {
        return false;
    }
    reader.len = reader.offset + handshake_len;
    // Server Version (Default for TLS 1.2 and earlier)
    if (!reader.has_bytes(2)) return false;
    out.server_version = reader.read_u16();
    out.selected_version = out.server_version; // Ground 1: Safe fallback initialization

    // Skip Server Random (32 bytes)
    if (!reader.skip(32)) return false;

    // Skip Session ID
    if (!reader.has_bytes(1)) return false;
    uint8_t session_id_len = reader.read_u8();
    if (!reader.skip(session_id_len)) return false;

    // Selected Cipher Suite
    if (!reader.has_bytes(2)) return false;
    out.selected_cipher = reader.read_u16();

    // Skip Compression Method (1 byte)
    if (!reader.skip(1)) return false;

    // Extensions Vector
    if (reader.has_bytes(2)) {
        uint16_t exts_len = reader.read_u16();
        if (!reader.has_bytes(exts_len)) {
            return false; // Bound validation against buffer over-read
        }
        const size_t end_offset = reader.offset + exts_len;

        while (reader.offset + 4 <= end_offset && reader.has_bytes(4)) {
            uint16_t ext_type = reader.read_u16();
            uint16_t ext_len = reader.read_u16();
            
            if (reader.offset + ext_len > end_offset) {
                break;
            }

            if (!is_grease(ext_type)) {
                out.extensions.push_back(ext_type);
            }

            const size_t ext_start = reader.offset;

            // Extension 0x002b: Supported Versions (TLS 1.3 negotiated version)
            if (ext_type == 0x002b && ext_len == 2 && reader.has_bytes(2)) {
                uint16_t ver = (static_cast<uint16_t>(reader.data[reader.offset]) << 8) |
                                reader.data[reader.offset + 1];
                if (!is_grease(ver)) {
                    out.selected_version = ver;
                }
            }

            if (ext_type == 0x0010 && ext_len >= 2) {
                ByteReader alpn_reader{reader.data, ext_start + ext_len, ext_start};
                uint16_t list_len = alpn_reader.read_u16();
                if (list_len + 2 <= ext_len && alpn_reader.has_bytes(1)) {
                    uint8_t proto_len = alpn_reader.read_u8();
                    if (proto_len > 0 && alpn_reader.has_bytes(proto_len)) {
                        out.first_alpn = std::string_view(
                            reinterpret_cast<const char*>(alpn_reader.data + alpn_reader.offset), 
                            proto_len
                        );
                    }
                }
            }

            reader.offset = ext_start + ext_len;
        }
    }

    return true;
}

} // namespace tlsfp