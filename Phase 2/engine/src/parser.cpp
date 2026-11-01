#include "tlsfp/parser.hpp"
#include "tlsfp/ech_analysis.hpp"
#include <algorithm>

namespace tlsfp {

namespace {

bool parse_client_extensions(ByteReader &ext_reader, ClientHelloData &out) {
    while (ext_reader.remaining() != 0) {
        uint16_t ext_type = 0;
        uint16_t ext_len = 0;
        if (!ext_reader.read_u16_be(ext_type) || !ext_reader.read_u16_be(ext_len)) {
            return false;
        }

        // A complete type/length header proves presence even if its body is bad.
        if (ext_type == ECH_EXTENSION) out.ech.present = true;
        if (ext_type == ECH_OUTER_EXTENSIONS) out.ech.has_outer_extensions = true;
        auto sub_opt = ext_reader.spawn_sub_reader(ext_len);
        if (!sub_opt) {
            if (ext_type == ECH_EXTENSION) {
                EchExtension extension;
                extension.status = ParseStatus::Malformed;
                extension.detail = "extension length exceeds complete ClientHello";
                out.ech.occurrences.push_back(extension);
            }
            return false;
        }
        ByteReader &reader = *sub_opt;

        // Filter reserved GREASE types, but preserve the remaining wire order:
        // browser permutation is observable JA3 variation, not parser noise.
        if (!is_grease(ext_type)) {
            out.extensions.push_back(ext_type);
        }

        switch (ext_type) {
            case ECH_EXTENSION:
                // ECH uses ordinary ClientHello framing. A malformed local body
                // stays an ECH observation without redefining the outer fingerprint.
                out.ech.occurrences.push_back(parse_ech_extension(reader));
                break;
            // Extension 0x0000: visible SNI. With real ECH this is the outer cover
            // name, not evidence of the intended inner destination.
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
                    auto alpn_sub = reader.spawn_sub_reader(list_len);
                    if (alpn_sub) {
                        while (alpn_sub->has_bytes(1)) {
                            uint8_t proto_len = 0;
                            if (!alpn_sub->read_u8(proto_len) || proto_len == 0 || !alpn_sub->has_bytes(proto_len)) {
                                break;
                            }
                            std::string_view cand;
                            alpn_sub->read_string_view(proto_len, cand);

                            if (!is_alpn_grease(cand)) {
                                out.first_alpn = cand;
                                break; // Spec: only capture first non-GREASE protocol
                            }
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
    return true;
}

bool parse_server_extensions(ByteReader &ext_reader, ServerHelloData &out) {
    bool version_seen = false;
    while (ext_reader.remaining() != 0) {
        uint16_t ext_type = 0;
        uint16_t ext_len = 0;
        if (!ext_reader.read_u16_be(ext_type) || !ext_reader.read_u16_be(ext_len)) {
            return false;
        }

        auto sub_opt = ext_reader.spawn_sub_reader(ext_len);
        if (!sub_opt) {
            return false;
        }
        ByteReader &reader = *sub_opt;

        if (!is_grease(ext_type)) {
            out.extensions.push_back(ext_type);
        }

        switch (ext_type) {
            // Extension 0x002b: Supported Versions in ServerHello is exactly 2 bytes
            case 0x002b: {
                if (ext_len != 2 || version_seen) return false;
                reader.read_u16_be(out.selected_version);
                version_seen = true;
                break;
            }

            // Extension 0x0010: negotiated ALPN in older TLS ServerHello messages.
            // TLS 1.3 puts this in encrypted EncryptedExtensions, outside this parser.
            case 0x0010: {
                uint16_t list_len = 0;
                if (reader.read_u16_be(list_len)) {
                    auto alpn_sub = reader.spawn_sub_reader(list_len);
                    if (alpn_sub && alpn_sub->has_bytes(1)) {
                        uint8_t proto_len = 0;
                        if (alpn_sub->read_u8(proto_len) && alpn_sub->has_bytes(proto_len)) {
                            alpn_sub->read_string_view(proto_len, out.first_alpn);
                        }
                    }
                }
                break;
            }

            default:
                break;
        }
    }
    return true;
}

} // anonymous namespace

bool parse_client_hello(const uint8_t *record, size_t record_len, ClientHelloData &out) {
    out.clear();
    const auto fail = [&out](ParseStatus status, const char *detail) {
        out.parse_status = status;
        out.parse_detail = detail;
        analyze_ech(out.ech);
        return false;
    };
    if (record == nullptr || record_len < 5) {
        return fail(ParseStatus::Incomplete, "missing TLS record header");
    }
    ByteReader root_reader{record, record_len};

    // 1. Record Header (5 bytes)
    uint8_t rec_type = 0;
    uint16_t rec_ver = 0;
    uint16_t rec_len = 0;
    if (!root_reader.read_u8(rec_type) || rec_type != TLS_RECORD_HANDSHAKE ||
        !root_reader.read_u16_be(rec_ver) || !root_reader.read_u16_be(rec_len) ||
        (rec_ver >> 8) != 3 || (rec_ver & 0xff) > 4) {
        return fail(ParseStatus::Malformed, "invalid handshake record header");
    }
    // Bound the declared record, not a coalesced caller buffer containing other records.
    if (size_t{5} + rec_len > ACCUMULATOR_BUFFER_SIZE) {
        return fail(ParseStatus::Unsupported, "TLS record exceeds 8192-byte supported limit");
    }
    if (!root_reader.has_bytes(rec_len)) {
        return fail(ParseStatus::Incomplete, "missing TLS record bytes");
    }

    // Isolate reader strictly to declared record length to enforce boundary
    auto rec_sub_opt = root_reader.spawn_sub_reader(rec_len);
    ByteReader &reader = *rec_sub_opt;

    // 2. Handshake Header (4 bytes)
    uint8_t hs_type = 0;
    uint32_t hs_len = 0;
    if (!reader.read_u8(hs_type)) {
        return fail(ParseStatus::Malformed, "empty handshake record");
    }
    if (hs_type != TLS_HANDSHAKE_CLIENT_HELLO) {
        return fail(ParseStatus::Malformed, "expected ClientHello handshake type");
    }
    if (!reader.read_u24_be(hs_len) || !reader.has_bytes(hs_len)) {
        return fail(ParseStatus::Unsupported, "ClientHello spans TLS records");
    }

    auto hs_sub_opt = reader.spawn_sub_reader(hs_len);
    ByteReader &hs_reader = *hs_sub_opt;

    // JA3 uses this wire version. TLS 1.3 retains legacy_version = 0x0303;
    // supported_versions, rather than this field, advertises newer versions.
    if (!hs_reader.read_u16_be(out.client_version)) {
        return fail(ParseStatus::Malformed, "missing ClientHello version");
    }

    // 4. Random (32 bytes)
    const uint8_t *random = nullptr;
    if (!hs_reader.read_bytes(32, random)) {
        return fail(ParseStatus::Malformed, "missing ClientHello random");
    }
    out.outer_random.emplace();
    // Own the outer random for later connection/keylog joins. It does not reveal
    // the inner random needed to verify ordinary ECH acceptance confirmation.
    std::copy_n(random, 32, out.outer_random->begin());

    // 5. Session ID
    uint8_t session_id_len = 0;
    if (!hs_reader.read_u8(session_id_len) || session_id_len > 32 || !hs_reader.skip(session_id_len)) {
        return fail(ParseStatus::Malformed, "invalid session ID vector");
    }

    // 6. Cipher Suites (array of 2-byte values with GREASE filtering)
    uint16_t ciphers_len = 0;
    if (!hs_reader.read_u16_be(ciphers_len) || ciphers_len == 0 ||
        (ciphers_len % 2 != 0) || !hs_reader.has_bytes(ciphers_len)) {
        return fail(ParseStatus::Malformed, "invalid cipher suites vector");
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
    if (!hs_reader.read_u8(comp_len) || comp_len == 0 || !hs_reader.skip(comp_len)) {
        return fail(ParseStatus::Malformed, "invalid compression methods vector");
    }

    // 8. Extensions Vector
    // TLS <=1.2 permits an omitted extension vector. A partial length or a
    // contradictory vector inside a complete hello is malformed, not capture loss.
    if (hs_reader.remaining() != 0) {
        uint16_t exts_len = 0;
        if (!hs_reader.read_u16_be(exts_len) || hs_reader.remaining() != exts_len) {
            return fail(ParseStatus::Malformed, "extension vector does not consume ClientHello");
        }

        auto ext_sub_opt = hs_reader.spawn_sub_reader(exts_len);
        if (!parse_client_extensions(*ext_sub_opt, out)) {
            return fail(ParseStatus::Malformed, "invalid extension header or body length");
        }
    }

    out.parse_status = ParseStatus::Complete;
    out.parse_detail = "complete ClientHello framing";
    // Only a complete extension traversal proves absence. Failure paths retain
    // unknown presence unless an ECH type/length header was actually observed.
    if (!out.ech.present.has_value()) out.ech.present = false;
    analyze_ech(out.ech);
    return true;
}

bool parse_server_hello(const uint8_t *record, size_t record_len, ServerHelloData &out) {
    out.clear();
    const auto fail = [&out](ParseStatus status, const char *detail) {
        out.parse_status = status;
        out.parse_detail = detail;
        return false;
    };
    if (!record || record_len < 5) return fail(ParseStatus::Incomplete, "missing TLS record header");
    ByteReader root{record, record_len};
    uint8_t type = 0;
    uint16_t version = 0, length = 0;
    root.read_u8(type); root.read_u16_be(version); root.read_u16_be(length);
    if (type != TLS_RECORD_HANDSHAKE || (version >> 8) != 3 || (version & 255) > 4)
        return fail(ParseStatus::Malformed, "invalid handshake record header");
    if (size_t{5} + length > ACCUMULATOR_BUFFER_SIZE)
        return fail(ParseStatus::Unsupported, "TLS record exceeds 8192-byte supported limit");
    if (!root.has_bytes(length)) return fail(ParseStatus::Incomplete, "missing TLS record bytes");
    auto body = *root.spawn_sub_reader(length);
    uint8_t hello_type = 0;
    uint32_t hello_length = 0;
    if (!body.read_u8(hello_type) || hello_type != TLS_HANDSHAKE_SERVER_HELLO)
        return fail(ParseStatus::Malformed, "expected ServerHello handshake type");
    if (!body.read_u24_be(hello_length) || !body.has_bytes(hello_length))
        return fail(ParseStatus::Unsupported, "ServerHello spans TLS records");
    auto hello = *body.spawn_sub_reader(hello_length);
    const uint8_t *random = nullptr;
    if (!hello.read_u16_be(out.server_version) || !hello.read_bytes(32, random))
        return fail(ParseStatus::Malformed, "missing ServerHello version or random");
    out.random.emplace();
    std::copy_n(random, 32, out.random->begin());
    // HRR uses ServerHello framing with SHA-256("HelloRetryRequest") as its
    // fixed random. Recognizing it prevents final-server fingerprints on a retry.
    constexpr std::array<uint8_t, 32> hrr{{
        0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c}};
    out.is_hrr = *out.random == hrr;
    uint8_t session_length = 0, compression = 0;
    if (!hello.read_u8(session_length) || session_length > 32 || !hello.skip(session_length) ||
        !hello.read_u16_be(out.selected_cipher) || !hello.read_u8(compression))
        return fail(ParseStatus::Malformed, "invalid ServerHello fixed fields");
    if (hello.remaining()) {
        uint16_t extensions_length = 0;
        if (!hello.read_u16_be(extensions_length) || hello.remaining() != extensions_length)
            return fail(ParseStatus::Malformed, "extension vector does not consume ServerHello");
        auto extensions = *hello.spawn_sub_reader(extensions_length);
        if (!parse_server_extensions(extensions, out))
            return fail(ParseStatus::Malformed, "invalid server extension framing or supported_versions");
    }
    // TLS 1.3 also sends legacy_version 0x0303. Prefer supported_versions so I3
    // cannot mistake a TLS 1.3 response for observed ECH non-acceptance.
    const bool has_version = std::find(out.extensions.begin(), out.extensions.end(), 43) != out.extensions.end();
    if (!has_version) out.selected_version = out.server_version;
    out.parse_status = ParseStatus::Complete;
    out.parse_detail = "complete ServerHello framing";
    return true;
}

} // namespace tlsfp
