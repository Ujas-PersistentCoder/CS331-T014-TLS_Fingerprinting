#include "tlsfp/pqtls_parser.hpp"
#include "tlsfp/parser.hpp"   // for is_grease()

#include <cstring>

namespace tlsfp {

// key_share in a ClientHello. Layout:
//   total length of the list (2 bytes)
//   then, again and again: group (2) | key length (2) | key bytes
// We only read the group and the key length. The key bytes are skipped.
void parse_pqtls_client_key_share(ByteReader &reader, PqtlsClientObservation &out) {
    out.has_key_share = true;  // we saw the extension

    uint16_t list_len = 0;
    if (!reader.read_u16_be(list_len)) return;

    auto list_opt = reader.spawn_sub_reader(list_len);
    if (!list_opt) return;  // the list length is bigger than the extension
    ByteReader &list = *list_opt;

    bool all_ok = true;
    while (list.remaining() > 0) {
        uint16_t group = 0;
        uint16_t key_len = 0;
        if (!list.read_u16_be(group)) { all_ok = false; break; }
        if (!list.read_u16_be(key_len)) { all_ok = false; break; }
        if (!list.skip(key_len)) { all_ok = false; break; }

        if (is_grease(group)) continue;  // GREASE entries are junk on purpose

        out.key_share_groups.push_back(group);
        out.key_share_lens.push_back(key_len);
    }

    // Trust it only if every entry fit and nothing is left after the list.
    if (all_ok && reader.remaining() == 0) {
        out.key_share_parsed = true;
    }
}

// key_share in a ServerHello. The server sends only one entry:
//   group (2) | key length (2) | key bytes
// In a HelloRetryRequest there is only the group (no length, no key).
void parse_pqtls_server_key_share(ByteReader &reader, PqtlsServerObservation &out) {
    uint16_t group = 0;
    uint16_t key_len = 0;
    if (!reader.read_u16_be(group)) return;
    out.selected_group = group;
    if (!reader.read_u16_be(key_len)) return;
    out.server_share_len = key_len;
}

// Runs after ALL extensions are read, because some clients shuffle the
// extension order. GREASE is already removed from supported_groups, so
// position 0 really is the client's first choice.
void find_pqtls_group(const std::vector<uint16_t> &supported_groups, PqtlsClientObservation &out) {
    for (size_t i = 0; i < supported_groups.size(); ++i) {
        uint16_t group = supported_groups[i];
        if (is_pqtls_group(group)) {
            out.pq_group = group;
            out.pq_first_choice = (i == 0);
            return;
        }
    }
}

// A HelloRetryRequest always uses this exact random value,
// which is SHA-256("HelloRetryRequest") (RFC 8446 section 4.1.3).
bool is_hrr_random(const uint8_t *random) {
    static const uint8_t HRR_RANDOM[32] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
    };
    return std::memcmp(random, HRR_RANDOM, 32) == 0;
}

} // namespace tlsfp
