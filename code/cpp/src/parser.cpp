#include "tlsfp/parser.hpp"
#include <cstring>
#include <arpa/inet.h>

namespace tlsfp {

struct ByteReader {
    const uint8_t *data;
    size_t len;
    size_t offset{0};

    bool has_bytes(size_t n) const {
        return (offset + n <= len);
    }

    uint8_t read_u8() {
        return data[offset++];
    }

    uint16_t read_u16() {
        uint16_t val = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
        return val;
    }

    uint32_t read_u24() {
        uint32_t val = (static_cast<uint32_t>(data[offset]) << 16) |
                       (static_cast<uint32_t>(data[offset + 1]) << 8) |
                       data[offset + 2];
        offset += 3;
        return val;
    }

    bool skip(size_t n) {
        if (!has_bytes(n)) return false;
        offset += n;
        return true;
    }
};

static void parse_extensions(ByteReader &reader, size_t exts_len, ClientHelloData &out) {
    size_t end_offset = reader.offset + exts_len;

    while (reader.offset + 4 <= end_offset) {
        uint16_t ext_type = reader.read_u16();
        uint16_t ext_len = reader.read_u16();

        if (reader.offset + ext_len > end_offset) {
            break; // Truncated extension block
        }

        // 1. Filter GREASE extension types
        if (!is_grease(ext_type)) {
            out.extensions.push_back(ext_type);
        }

        size_t ext_start = reader.offset;

        // Extension 0x0000: Server Name Indication (SNI)
        if (ext_type == 0x0000 && ext_len >= 5) {
            ByteReader sni_reader{reader.data, ext_start + ext_len, ext_start};
            uint16_t list_len = sni_reader.read_u16();
            if (sni_reader.has_bytes(3)) {
                uint8_t name_type = sni_reader.read_u8();
                uint16_t name_len = sni_reader.read_u16();
                if (name_type == 0 && sni_reader.has_bytes(name_len)) {
                    out.has_sni = true;
                    out.sni.assign(reinterpret_cast<const char*>(sni_reader.data + sni_reader.offset), name_len);
                }
            }
        }
        // Extension 0x000a: Supported Groups (Elliptic Curves)
        else if (ext_type == 0x000a && ext_len >= 2) {
            ByteReader ec_reader{reader.data, ext_start + ext_len, ext_start};
            uint16_t curves_len = ec_reader.read_u16();
            while (ec_reader.has_bytes(2) && ec_reader.offset < ext_start + 2 + curves_len) {
                uint16_t group = ec_reader.read_u16();
                // 2. Filter GREASE curves/groups
                if (!is_grease(group)) {
                    out.supported_groups.push_back(group);
                }
            }
        }
        // Extension 0x000b: EC Point Formats
        else if (ext_type == 0x000b && ext_len >= 1) {
            ByteReader pt_reader{reader.data, ext_start + ext_len, ext_start};
            uint8_t formats_len = pt_reader.read_u8();
            while (pt_reader.has_bytes(1) && pt_reader.offset < ext_start + 1 + formats_len) {
                out.ec_point_formats.push_back(pt_reader.read_u8());
            }
        }
        // Extension 0x002b: Supported Versions (TLS 1.3)
        else if (ext_type == 0x002b && ext_len >= 1) {
            ByteReader ver_reader{reader.data, ext_start + ext_len, ext_start};
            uint8_t versions_len = ver_reader.read_u8();
            while (ver_reader.has_bytes(2) && ver_reader.offset < ext_start + 1 + versions_len) {
                uint16_t ver = ver_reader.read_u16();
                // 3. Filter GREASE versions
                if (!is_grease(ver)) {
                    out.supported_versions.push_back(ver);
                }
            }
        }

        reader.offset = ext_start + ext_len; // Advance to next extension block
    }
}

bool parse_client_hello(const uint8_t *payload, size_t len, ClientHelloData &out) {
    ByteReader reader{payload, len, 0};

    // 1. Record Header (5 bytes)
    if (!reader.has_bytes(5)) return false;
    if (reader.read_u8() != 0x16) return false;

    reader.skip(2); // Skip record version
    uint16_t record_len = reader.read_u16();
    if (!reader.has_bytes(record_len)) return false;

    // 2. Handshake Header (4 bytes)
    if (!reader.has_bytes(4)) return false;
    if (reader.read_u8() != 0x01) return false;

    uint32_t handshake_len = reader.read_u24();
    if (!reader.has_bytes(handshake_len)) return false;

    // 3. Client Version
    if (!reader.has_bytes(2)) return false;
    out.client_version = reader.read_u16();

    // 4. Skip Client Random (32 bytes)
    if (!reader.skip(32)) return false;

    // 5. Skip Session ID
    if (!reader.has_bytes(1)) return false;
    uint8_t session_id_len = reader.read_u8();
    if (!reader.skip(session_id_len)) return false;

    // 6. Cipher Suites (with GREASE filtering)
    if (!reader.has_bytes(2)) return false;
    uint16_t cipher_suites_len = reader.read_u16();
    if (!reader.has_bytes(cipher_suites_len) || (cipher_suites_len % 2 != 0)) return false;

    size_t cipher_end = reader.offset + cipher_suites_len;
    while (reader.offset < cipher_end) {
        uint16_t cs = reader.read_u16();
        // 4. Filter GREASE cipher suites
        if (!is_grease(cs)) {
            out.cipher_suites.push_back(cs);
        }
    }

    // 7. Compression Methods
    if (!reader.has_bytes(1)) return false;
    uint8_t compression_len = reader.read_u8();
    if (!reader.skip(compression_len)) return false;

    // 8. Extensions
    if (reader.has_bytes(2)) {
        uint16_t extensions_len = reader.read_u16();
        if (reader.has_bytes(extensions_len)) {
            parse_extensions(reader, extensions_len, out);
        }
    }

    return true;
}

bool parse_server_hello(const uint8_t *payload, size_t len, ServerHelloData &out) {
    ByteReader reader{payload, len, 0};

    // 1. Record Header
    if (!reader.has_bytes(5)) return false;
    if (reader.read_u8() != 0x16) return false;

    reader.skip(2); // Skip record version
    uint16_t record_len = reader.read_u16();
    if (!reader.has_bytes(record_len)) return false;

    // 2. Handshake Header
    if (!reader.has_bytes(4)) return false;
    if (reader.read_u8() != 0x02) return false;

    uint32_t handshake_len = reader.read_u24();
    if (!reader.has_bytes(handshake_len)) return false;

    // 3. Server Version
    if (!reader.has_bytes(2)) return false;
    out.server_version = reader.read_u16();

    // 4. Skip Server Random (32 bytes)
    if (!reader.skip(32)) return false;

    // 5. Skip Session ID
    if (!reader.has_bytes(1)) return false;
    uint8_t session_id_len = reader.read_u8();
    if (!reader.skip(session_id_len)) return false;

    // 6. Selected Cipher Suite
    if (!reader.has_bytes(2)) return false;
    out.selected_cipher = reader.read_u16();

    // 7. Skip Compression Method (1 byte)
    if (!reader.skip(1)) return false;

    // 8. Extensions
    if (reader.has_bytes(2)) {
        uint16_t exts_len = reader.read_u16();
        size_t end_offset = reader.offset + exts_len;
        while (reader.offset + 4 <= end_offset && reader.has_bytes(4)) {
            uint16_t ext_type = reader.read_u16();
            uint16_t ext_len = reader.read_u16();
            if (!reader.has_bytes(ext_len)) break;

            if (!is_grease(ext_type)) {
                out.extensions.push_back(ext_type);
            }

            if (ext_type == 0x002b && ext_len == 2) {
                uint16_t ver = (static_cast<uint16_t>(reader.data[reader.offset]) << 8) |
                               reader.data[reader.offset + 1];
                if (!is_grease(ver)) {
                    out.selected_version = ver;
                }
            }
            reader.skip(ext_len);
        }
    }

    return true;
}

} // namespace tlsfp