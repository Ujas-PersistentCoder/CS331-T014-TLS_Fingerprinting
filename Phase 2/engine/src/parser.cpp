#include "tlsfp/parser.hpp"
#include <algorithm>

namespace tlsfp {

namespace {

void parse_client_extensions(ByteReader &ext_reader, ClientHelloData &out) {
    while (ext_reader.has_bytes(4)) {
        uint16_t ext_type = 0;
        uint16_t ext_len = 0;
        if (!ext_reader.read_u16_be(ext_type) || !ext_reader.read_u16_be(ext_len)) {
            break;
        }

        auto sub_opt = ext_reader.spawn_sub_reader(ext_len);
        if (!sub_opt) {
            break; // Truncated extension payload
        }
        ByteReader &reader = *sub_opt;

        // Prune GREASE extension types (RFC 8701)
        if (!is_grease(ext_type)) {
            out.extensions.push_back(ext_type);
        }

        switch (ext_type) {
            // Extension 0x0000: Server Name Indication (SNI)
            case 0x0000: {
                uint16_t list_len = 0;
                if (reader.read_u16_be(list_len) && reader.has_bytes(3)) {
                    uint8_t name_type = 0;
                    uint16_t name_len = 0;
                    if (reader.read_u8(name_type) && reader.read_u16_be(name_len)) {
                        // 0 = host_name per RFC 6066
                        if (name_type == 0 && reader.has_bytes(name_len)) {
                            out.has_sni = true;
                            reader.read_string_view(name_len, out.sni);
                        }
                    }
                }
                break;
            }

            // Extension 0x000a: Supported Groups / Elliptic Curves
            case 0x000a: {
                uint16_t groups_len = 0;
                if (reader.read_u16_be(groups_len)) {
                    size_t count = std::min<size_t>(groups_len, reader.remaining()) / 2;
                    for (size_t i = 0; i < count; ++i) {
                        uint16_t group = 0;
                        if (reader.read_u16_be(group) && !is_grease(group)) {
                            out.supported_groups.push_back(group);
                        }
                    }
                }
                break;
            }

            // Extension 0x000b: EC Point Formats
            case 0x000b: {
                uint8_t formats_len = 0;
                if (reader.read_u8(formats_len)) {
                    size_t count = std::min<size_t>(formats_len, reader.remaining());
                    for (size_t i = 0; i < count; ++i) {
                        uint8_t pt = 0;
                        if (reader.read_u8(pt)) {
                            out.ec_point_formats.push_back(pt);
                        }
                    }
                }
                break;
            }

            // Extension 0x000d: Signature Algorithms (Required for JA4_c)
            case 0x000d: {
                uint16_t sig_len = 0;
                if (reader.read_u16_be(sig_len)) {
                    size_t count = std::min<size_t>(sig_len, reader.remaining()) / 2;
                    for (size_t i = 0; i < count; ++i) {
                        uint16_t sig_algo = 0;
                        if (reader.read_u16_be(sig_algo) && !is_grease(sig_algo)) {
                            out.signature_algorithms.push_back(sig_algo);
                        }
                    }
                }
                break;
            }

            // Extension 0x0010: ALPN (Required for JA4_a)
            case 0x0010: {
                uint16_t list_len = 0;
                if (reader.read_u16_be(list_len)) {
                    while (reader.has_bytes(1)) {
                        uint8_t proto_len = 0;
                        if (!reader.read_u8(proto_len) || proto_len == 0 || !reader.has_bytes(proto_len)) {
                            break;
                        }
                        std::string_view cand;
                        reader.read_string_view(proto_len, cand);

                        // Prune GREASE ALPN values to prevent JA4 drift
                        if (!is_alpn_grease(cand)) {
                            out.first_alpn = cand;
                            break; // Spec: only capture first negotiated/offered protocol
                        }
                    }
                }
                break;
            }

            // Extension 0x002b: Supported Versions (TLS 1.3)
            case 0x002b: {
                uint8_t versions_len = 0;
                if (reader.read_u8(versions_len)) {
                    size_t count = std::min<size_t>(versions_len, reader.remaining()) / 2;
                    for (size_t i = 0; i < count; ++i) {
                        uint16_t ver = 0;
                        if (reader.read_u16_be(ver) && !is_grease(ver)) {
                            out.supported_versions.push_back(ver);
                        }
                    }
                }
                break;
            }

            default:
                break;
        }
    }
}

void parse_server_extensions(ByteReader &ext_reader, ServerHelloData &out) {
    while (ext_reader.has_bytes(4)) {
        uint16_t ext_type = 0;
        uint16_t ext_len = 0;
        if (!ext_reader.read_u16_be(ext_type) || !ext_reader.read_u16_be(ext_len)) {
            break;
        }

        auto sub_opt = ext_reader.spawn_sub_reader(ext_len);
        if (!sub_opt) {
            break;
        }
        ByteReader &reader = *sub_opt;

        if (!is_grease(ext_type)) {
            out.extensions.push_back(ext_type);
        }

        switch (ext_type) {
            // Extension 0x002b: Supported Versions in ServerHello is exactly 2 bytes
            case 0x002b: {
                if (ext_len >= 2) {
                    reader.read_u16_be(out.selected_version);
                }
                break;
            }

            // Extension 0x0010: Negotiated ALPN
            case 0x0010: {
                uint16_t list_len = 0;
                if (reader.read_u16_be(list_len) && reader.has_bytes(1)) {
                    uint8_t proto_len = 0;
                    if (reader.read_u8(proto_len) && reader.has_bytes(proto_len)) {
                        reader.read_string_view(proto_len, out.first_alpn);
                    }
                }
                break;
            }

            default:
                break;
        }
    }
}

} // anonymous namespace

bool parse_client_hello(const uint8_t *record, size_t record_len, ClientHelloData &out) {
    out.clear();
    ByteReader reader{record, record_len};

    // 1. Record Header (5 bytes)
    uint8_t rec_type = 0;
    uint16_t rec_ver = 0;
    uint16_t rec_len = 0;
    if (!reader.read_u8(rec_type) || rec_type != TLS_RECORD_HANDSHAKE ||
        !reader.read_u16_be(rec_ver) || !reader.read_u16_be(rec_len) ||
        !reader.has_bytes(rec_len)) {
        return false;
    }

    // 2. Handshake Header (4 bytes)
    uint8_t hs_type = 0;
    uint32_t hs_len = 0;
    if (!reader.read_u8(hs_type) || hs_type != TLS_HANDSHAKE_CLIENT_HELLO ||
        !reader.read_u24_be(hs_len) || !reader.has_bytes(hs_len)) {
        return false;
    }

    auto hs_sub_opt = reader.spawn_sub_reader(hs_len);
    if (!hs_sub_opt) return false;
    ByteReader &hs_reader = *hs_sub_opt;

    // 3. Client Version (2 bytes)
    if (!hs_reader.read_u16_be(out.client_version)) return false;

    // 4. Random (32 bytes)
    if (!hs_reader.skip(32)) return false;

    // 5. Session ID
    uint8_t session_id_len = 0;
    if (!hs_reader.read_u8(session_id_len) || !hs_reader.skip(session_id_len)) {
        return false;
    }

    // 6. Cipher Suites (array of 2-byte values with GREASE filtering)
    uint16_t ciphers_len = 0;
    if (!hs_reader.read_u16_be(ciphers_len) || (ciphers_len % 2 != 0) || !hs_reader.has_bytes(ciphers_len)) {
        return false;
    }

    size_t cipher_count = ciphers_len / 2;
    out.cipher_suites.reserve(cipher_count);
    for (size_t i = 0; i < cipher_count; ++i) {
        uint16_t cs = 0;
        hs_reader.read_u16_be(cs);
        if (!is_grease(cs)) {
            out.cipher_suites.push_back(cs);
        }
    }

    // 7. Compression Methods
    uint8_t comp_len = 0;
    if (!hs_reader.read_u8(comp_len) || !hs_reader.skip(comp_len)) {
        return false;
    }

    // 8. Extensions Vector (optional in legacy SSL, standard in modern TLS)
    if (hs_reader.has_bytes(2)) {
        uint16_t exts_len = 0;
        if (!hs_reader.read_u16_be(exts_len) || !hs_reader.has_bytes(exts_len)) {
            return false;
        }

        auto ext_sub_opt = hs_reader.spawn_sub_reader(exts_len);
        if (ext_sub_opt) {
            parse_client_extensions(*ext_sub_opt, out);
        }
    }

    return true;
}

bool parse_server_hello(const uint8_t *record, size_t record_len, ServerHelloData &out) {
    out.clear();
    ByteReader reader{record, record_len};

    // 1. Record Header (5 bytes)
    uint8_t rec_type = 0;
    uint16_t rec_ver = 0;
    uint16_t rec_len = 0;
    if (!reader.read_u8(rec_type) || rec_type != TLS_RECORD_HANDSHAKE ||
        !reader.read_u16_be(rec_ver) || !reader.read_u16_be(rec_len) ||
        !reader.has_bytes(rec_len)) {
        return false;
    }

    // 2. Handshake Header (4 bytes)
    uint8_t hs_type = 0;
    uint32_t hs_len = 0;
    if (!reader.read_u8(hs_type) || hs_type != TLS_HANDSHAKE_SERVER_HELLO ||
        !reader.read_u24_be(hs_len) || !reader.has_bytes(hs_len)) {
        return false;
    }

    auto hs_sub_opt = reader.spawn_sub_reader(hs_len);
    if (!hs_sub_opt) return false;
    ByteReader &hs_reader = *hs_sub_opt;

    // 3. Server Version (2 bytes)
    if (!hs_reader.read_u16_be(out.server_version)) return false;

    // 4. Random (32 bytes)
    if (!hs_reader.skip(32)) return false;

    // 5. Session ID
    uint8_t session_id_len = 0;
    if (!hs_reader.read_u8(session_id_len) || !hs_reader.skip(session_id_len)) {
        return false;
    }

    // 6. Selected Cipher Suite (single 2-byte value)
    if (!hs_reader.read_u16_be(out.selected_cipher)) return false;

    // 7. Compression Method
    uint8_t comp_method = 0;
    if (!hs_reader.read_u8(comp_method)) return false;

    // 8. Extensions Vector
    if (hs_reader.has_bytes(2)) {
        uint16_t exts_len = 0;
        if (!hs_reader.read_u16_be(exts_len) || !hs_reader.has_bytes(exts_len)) {
            return false;
        }

        auto ext_sub_opt = hs_reader.spawn_sub_reader(exts_len);
        if (ext_sub_opt) {
            parse_server_extensions(*ext_sub_opt, out);
        }
    }

    if (out.selected_version == 0) {
        out.selected_version = out.server_version;
    }

    return true;
}

} // namespace tlsfp
