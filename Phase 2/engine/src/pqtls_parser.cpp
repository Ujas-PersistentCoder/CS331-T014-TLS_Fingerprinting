#include "tlsfp/pqtls_parser.hpp"
#include "tlsfp/parser.hpp"   // is_grease()

#include <cstring>

namespace tlsfp {

// ClientHello key_share: list_len (2) | { group (2) | key_len (2) | key } ...
// Key bytes are skipped, only group and length are retained.
void parse_pqtls_client_key_share(ByteReader &reader, PqtlsClientObservation &out) {
    // Duplicate 0x0033: keep first occurrence
    if (out.has_key_share) {
        out.duplicate_key_share = true;
        return;
    }
    out.has_key_share = true;

    uint16_t list_len = 0;
    if (!reader.read_u16_be(list_len)) return;

    auto list_opt = reader.spawn_sub_reader(list_len);
    if (!list_opt) return;  // List length exceeds extension body
    ByteReader &list = *list_opt;

    bool all_ok = true;
    while (list.remaining() > 0) {
        uint16_t group = 0;
        uint16_t key_len = 0;
        if (!list.read_u16_be(group)) { all_ok = false; break; }
        if (!list.read_u16_be(key_len)) { all_ok = false; break; }
        if (!list.skip(key_len)) { all_ok = false; break; }

        if (is_grease(group)) continue;  // Prune GREASE entries (RFC 8701)

        out.key_share_groups.push_back(group);
        out.key_share_lens.push_back(key_len);
    }

    // Valid only if every entry fit and nothing trails the list
    if (all_ok && reader.remaining() == 0) {
        out.key_share_parsed = true;
    }
}

// ServerHello key_share: group (2) | key_len (2) | key
// HelloRetryRequest key_share: group (2) only
void parse_pqtls_server_key_share(ByteReader &reader, PqtlsServerObservation &out) {
    // Duplicate 0x0033: keep first occurrence
    if (out.has_key_share) {
        out.duplicate_key_share = true;
        return;
    }
    out.has_key_share = true;

    uint16_t group = 0;
    if (!reader.read_u16_be(group)) return;
    out.selected_group = group;

    // HRR: group must be the entire extension body
    if (out.is_hrr) {
        if (reader.remaining() != 0) return;
        out.key_share_parsed = true;
        return;
    }

    // ServerHello: declared key bytes must be present, no trailing bytes
    uint16_t key_len = 0;
    if (!reader.read_u16_be(key_len)) return;
    out.server_share_len = key_len;
    if (!reader.skip(key_len)) return;        // Truncated key
    if (reader.remaining() != 0) return;      // Trailing bytes
    out.key_share_parsed = true;
}

// Runs after the extension loop (extension order may be randomized).
// supported_groups is already GREASE-free, so index 0 is the true first preference.
void find_pqtls_group(const std::vector<uint16_t> &extensions,
                      const std::vector<uint16_t> &supported_groups,
                      PqtlsClientObservation &out) {
    // Duplicate supported_groups (0x000a) check
    int groups_ext_count = 0;
    for (uint16_t ext : extensions) {
        if (ext == 0x000a) groups_ext_count++;
    }
    if (groups_ext_count > 1) {
        out.duplicate_supported_groups = true;
    }

    for (size_t i = 0; i < supported_groups.size(); ++i) {
        uint16_t group = supported_groups[i];
        if (is_pqtls_group(group)) {
            out.pq_group = group;
            out.pq_first_choice = (i == 0);
            return;
        }
    }
}

// HRR random = SHA-256("HelloRetryRequest") (RFC 8446 Sec. 4.1.3)
bool is_hrr_random(const uint8_t *random) {
    static const uint8_t HRR_RANDOM[32] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
    };
    return std::memcmp(random, HRR_RANDOM, 32) == 0;
}

} // namespace tlsfp
