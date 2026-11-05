#ifndef TLSFP_TEST_PQTLS_FIXTURES_HPP
#define TLSFP_TEST_PQTLS_FIXTURES_HPP

// Byte-level ClientHello / ServerHello builders for PQ-TLS unit tests

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pqtls_fixture {

using Bytes = std::vector<uint8_t>;

// HRR random: SHA-256("HelloRetryRequest") (RFC 8446 Sec. 4.1.3)
inline const Bytes HRR_RANDOM = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

// Append uint16 in network byte order
inline void add16(Bytes &b, size_t value) {
    b.push_back(static_cast<uint8_t>(value >> 8));
    b.push_back(static_cast<uint8_t>(value & 0xff));
}

// Extension: type (2) | length (2) | body
inline Bytes make_extension(uint16_t type, const Bytes &body) {
    Bytes e;
    add16(e, type);
    add16(e, body.size());
    e.insert(e.end(), body.begin(), body.end());
    return e;
}

// supported_groups body: list_len (2) | groups
inline Bytes make_groups_body(const std::vector<uint16_t> &groups) {
    Bytes b;
    add16(b, groups.size() * 2);
    for (uint16_t g : groups) {
        add16(b, g);
    }
    return b;
}

// Single key_share entry spec
struct Share {
    uint16_t group;
    uint16_t key_len;
};

// ClientHello key_share body: list_len (2) | { group (2) | key_len (2) | key (0xAA) } ...
inline Bytes make_key_share_body(const std::vector<Share> &shares) {
    Bytes list;
    for (const Share &s : shares) {
        add16(list, s.group);
        add16(list, s.key_len);
        list.insert(list.end(), s.key_len, 0xAA);
    }
    Bytes b;
    add16(b, list.size());
    b.insert(b.end(), list.begin(), list.end());
    return b;
}

// Wrap body in Handshake header (4) + TLS Record header (5)
inline Bytes wrap_in_record(uint8_t handshake_type, const Bytes &body) {
    Bytes handshake;
    handshake.push_back(handshake_type);
    handshake.push_back(0);                                  // Handshake length (24-bit)
    handshake.push_back(static_cast<uint8_t>(body.size() >> 8));
    handshake.push_back(static_cast<uint8_t>(body.size() & 0xff));
    handshake.insert(handshake.end(), body.begin(), body.end());

    Bytes record = {0x16, 0x03, 0x01};                       // Handshake record, TLS 1.0 legacy version
    add16(record, handshake.size());
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

// Minimal ClientHello record
inline Bytes make_client_hello(const Bytes &extensions) {
    Bytes hello;
    add16(hello, 0x0303);                // Client Version: TLS 1.2 (0x0303)
    hello.insert(hello.end(), 32, 0);    // random
    hello.push_back(0);                  // Session ID length: 0
    add16(hello, 2);                     // Cipher Suites: TLS_AES_128_GCM_SHA256
    add16(hello, 0x1301);
    hello.push_back(1);                  // Compression Methods: 1 method
    hello.push_back(0);                  // null
    add16(hello, extensions.size());
    hello.insert(hello.end(), extensions.begin(), extensions.end());
    return wrap_in_record(1, hello);     // Handshake type 0x01
}

// Minimal ServerHello record (hrr = true uses the HRR random)
inline Bytes make_server_hello(const Bytes &extensions, bool hrr = false) {
    Bytes hello;
    add16(hello, 0x0303);                // Server Version: TLS 1.2 (0x0303)
    if (hrr) {
        hello.insert(hello.end(), HRR_RANDOM.begin(), HRR_RANDOM.end());
    } else {
        hello.insert(hello.end(), 32, 0);  // random
    }
    hello.push_back(0);                  // Session ID length: 0
    add16(hello, 0x1301);                // Selected Cipher Suite
    hello.push_back(0);                  // Compression Method: null
    add16(hello, extensions.size());
    hello.insert(hello.end(), extensions.begin(), extensions.end());
    return wrap_in_record(2, hello);     // Handshake type 0x02
}

// Concatenate byte vectors
inline Bytes join(const Bytes &a, const Bytes &b) {
    Bytes out = a;
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

} // namespace pqtls_fixture

#endif // TLSFP_TEST_PQTLS_FIXTURES_HPP
