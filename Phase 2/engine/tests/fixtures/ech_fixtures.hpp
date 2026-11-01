#ifndef TLSFP_TEST_ECH_FIXTURES_HPP
#define TLSFP_TEST_ECH_FIXTURES_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

namespace ech_fixture {
using Bytes = std::vector<uint8_t>;

inline void u16(Bytes &bytes, size_t value) {
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value));
}

inline Bytes outer(size_t enc_length = 32, size_t payload_length = 208,
                   uint16_t kdf = 1, uint16_t aead = 1, uint8_t config = 139) {
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
} // namespace ech_fixture
#endif
