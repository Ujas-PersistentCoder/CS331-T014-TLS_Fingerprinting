#ifndef TLSFP_TEST_PQTLS_FIXTURES_HPP
#define TLSFP_TEST_PQTLS_FIXTURES_HPP

// Helpers that build small fake TLS hellos byte by byte, for the PQ-TLS tests.
// A hello is just a row of bytes in a fixed order, so we can write one by hand
// and know exactly what the parser should find in it.

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pqtls_fixture {

using Bytes = std::vector<uint8_t>;

// The fixed random value that marks a HelloRetryRequest: SHA-256("HelloRetryRequest").
inline const Bytes HRR_RANDOM = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

// add a 2 byte number (big endian, like in TLS)
inline void add16(Bytes &b, size_t value) {
    b.push_back(static_cast<uint8_t>(value >> 8));
    b.push_back(static_cast<uint8_t>(value & 0xff));
}

// one extension = type (2 bytes) + length (2 bytes) + body
inline Bytes make_extension(uint16_t type, const Bytes &body) {
    Bytes e;
    add16(e, type);
    add16(e, body.size());
    e.insert(e.end(), body.begin(), body.end());
    return e;
}

// supported_groups body: list length (2) + the groups (2 bytes each)
inline Bytes make_groups_body(const std::vector<uint16_t> &groups) {
    Bytes b;
    add16(b, groups.size() * 2);
    for (uint16_t g : groups) {
        add16(b, g);
    }
    return b;
}

// One key share entry: the group and how many key bytes to put in.
struct Share {
    uint16_t group;
    uint16_t key_len;
};

// key_share body in a ClientHello: list length (2) + entries.
// Each entry is group (2) + key length (2) + key bytes (filled with 0xAA).
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

// Puts a handshake body behind a handshake header and a record header.
inline Bytes wrap_in_record(uint8_t handshake_type, const Bytes &body) {
    Bytes handshake;
    handshake.push_back(handshake_type);
    handshake.push_back(0);                                  // 3 byte length (first byte)
    handshake.push_back(static_cast<uint8_t>(body.size() >> 8));
    handshake.push_back(static_cast<uint8_t>(body.size() & 0xff));
    handshake.insert(handshake.end(), body.begin(), body.end());

    Bytes record = {0x16, 0x03, 0x01};                       // type 0x16 (handshake), version
    add16(record, handshake.size());
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

// A small but valid ClientHello record with the given extensions.
inline Bytes make_client_hello(const Bytes &extensions) {
    Bytes hello;
    add16(hello, 0x0303);                // client version
    hello.insert(hello.end(), 32, 0);    // random
    hello.push_back(0);                  // session id length = 0
    add16(hello, 2);                     // cipher suites: one suite
    add16(hello, 0x1301);
    hello.push_back(1);                  // compression methods: 1 byte
    hello.push_back(0);                  // null compression
    add16(hello, extensions.size());
    hello.insert(hello.end(), extensions.begin(), extensions.end());
    return wrap_in_record(1, hello);     // 1 = ClientHello
}

// A small but valid ServerHello record with the given extensions.
// If hrr is true, the random is the HelloRetryRequest value instead of zeros.
inline Bytes make_server_hello(const Bytes &extensions, bool hrr = false) {
    Bytes hello;
    add16(hello, 0x0303);                // server version
    if (hrr) {
        hello.insert(hello.end(), HRR_RANDOM.begin(), HRR_RANDOM.end());
    } else {
        hello.insert(hello.end(), 32, 0);  // random
    }
    hello.push_back(0);                  // session id length = 0
    add16(hello, 0x1301);                // chosen cipher
    hello.push_back(0);                  // compression
    add16(hello, extensions.size());
    hello.insert(hello.end(), extensions.begin(), extensions.end());
    return wrap_in_record(2, hello);     // 2 = ServerHello
}

// Adds two byte lists together.
inline Bytes join(const Bytes &a, const Bytes &b) {
    Bytes out = a;
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

} // namespace pqtls_fixture

#endif // TLSFP_TEST_PQTLS_FIXTURES_HPP
