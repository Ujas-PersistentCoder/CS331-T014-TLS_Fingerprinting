#ifndef TLSFP_TEST_ECH_FIXTURES_HPP
#define TLSFP_TEST_ECH_FIXTURES_HPP

#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <vector>

namespace ech_fixture {
using Bytes = std::vector<uint8_t>;

inline void u16(Bytes &bytes, size_t value) {
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value));
}

inline Bytes outer(size_t enc_length = 32, size_t payload_length = 208,
                   uint16_t kdf = 1, uint16_t aead = 1, uint8_t config = 139) {
    // Fixed bytes exercise envelope lengths, not HPKE encryption. A successful
    // parse of this fixture establishes neither a real offer nor ECH acceptance.
    Bytes body{0};
    u16(body, kdf);
    u16(body, aead);
    body.push_back(config);
    u16(body, enc_length);
    body.insert(body.end(), enc_length, 0xab);
    u16(body, payload_length);
    body.insert(body.end(), payload_length, 0xcd);
    return body;
}

inline void extension(Bytes &extensions, uint16_t type, const Bytes &body) {
    u16(extensions, type);
    u16(extensions, body.size());
    extensions.insert(extensions.end(), body.begin(), body.end());
}

// Total extension size includes its 4-byte type/length header.
inline Bytes padding(size_t total_size) {
    Bytes extensions;
    extension(extensions, 21, Bytes(total_size - 4, 0));
    return extensions;
}

inline void record_length(Bytes &record) {
    const size_t size = record.size() - 5;
    record[3] = static_cast<uint8_t>(size >> 8);
    record[4] = static_cast<uint8_t>(size);
}

inline void handshake_length(Bytes &record) {
    // The handshake's uint24 length excludes its own 4-byte header; the record's
    // uint16 length includes that handshake header but excludes the 5-byte record header.
    const size_t size = record.size() - 9;
    record[6] = static_cast<uint8_t>(size >> 16);
    record[7] = static_cast<uint8_t>(size >> 8);
    record[8] = static_cast<uint8_t>(size);
    record_length(record);
}

inline Bytes hello(const Bytes &extensions = {}) {
    Bytes record{22, 3, 1, 0, 0, 1, 0, 0, 0, 3, 3};
    for (uint8_t i = 0; i < 32; ++i) record.push_back(i);
    record.insert(record.end(), {0, 0, 2, 0x13, 1, 1, 0});
    u16(record, extensions.size());
    record.insert(record.end(), extensions.begin(), extensions.end());
    handshake_length(record);
    return record;
}

inline Bytes with_ech(const Bytes &body = outer()) {
    Bytes extensions;
    extension(extensions, 0xfe0d, body);
    return hello(extensions);
}

inline Bytes client(bool ech = true, const Bytes &extra = {}) {
    Bytes extensions;
    extension(extensions, 43, {4, 3, 4, 3, 3}); // Offer TLS 1.3 and TLS 1.2.
    if (ech) extension(extensions, 0xfe0d, outer());
    extensions.insert(extensions.end(), extra.begin(), extra.end());
    return hello(extensions);
}

inline Bytes server(uint16_t version = 0x0304, bool hrr = false, const Bytes &extra = {}) {
    Bytes extensions;
    if (version >= 0x0304) extension(extensions, 43, {static_cast<uint8_t>(version >> 8), static_cast<uint8_t>(version)});
    extensions.insert(extensions.end(), extra.begin(), extra.end());
    Bytes record{22, 3, 3, 0, 0, 2, 0, 0, 0, 3, 3};
    record.insert(record.end(), 32, 0x42);
    if (hrr) {
        const Bytes random{0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
                           0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
        std::copy(random.begin(), random.end(), record.begin() + 11);
    }
    record.insert(record.end(), {0, 0x13, 1, 0}); // Empty session ID; selected cipher; null compression.
    u16(record, extensions.size());
    record.insert(record.end(), extensions.begin(), extensions.end());
    handshake_length(record);
    return record;
}
} // namespace ech_fixture
#endif
