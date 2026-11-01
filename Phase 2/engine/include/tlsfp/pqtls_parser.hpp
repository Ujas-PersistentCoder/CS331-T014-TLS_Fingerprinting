#ifndef TLSFP_PQTLS_PARSER_HPP
#define TLSFP_PQTLS_PARSER_HPP

// PQ-TLS (post-quantum TLS), part 1: OBSERVE.
//
// These functions only read bytes from the hello and store what is on the wire.
// They keep no memory between packets and make no decisions.
// The decisions (labels) are in pqtls_analysis.hpp.
//
// What we observe:
//   ClientHello  supported_groups (0x000a): is a PQ hybrid group offered? first choice?
//   ClientHello  key_share (0x0033):        which keys were sent, and how big?
//   ServerHello  key_share (0x0033):        which group did the server pick?
//   ServerHello  random:                    is it really a HelloRetryRequest?

#include "tlsfp/byte_reader.hpp"
#include <cstdint>
#include <vector>

namespace tlsfp {

// PQ-TLS hybrid key exchange groups.
// Each one glues a classical key (X25519 or a P-curve) to an ML-KEM / Kyber key.
//   0x11ec  X25519MLKEM768            (the standard one, RFC 10024; Chrome 131+)
//   0x11eb  SecP256r1MLKEM768         (RFC 10024)
//   0x11ed  SecP384r1MLKEM1024        (RFC 10024)
//   0x6399  X25519Kyber768Draft00     (older draft version, before ML-KEM)
//   0x639a  SecP256r1Kyber768Draft00  (older draft version, before ML-KEM)
[[nodiscard]] inline constexpr bool is_pqtls_group(uint16_t group) noexcept {
    if (group == 0x11ec) return true;
    if (group == 0x11eb) return true;
    if (group == 0x11ed) return true;
    if (group == 0x6399) return true;
    if (group == 0x639a) return true;
    return false;
}

// What we observed about PQ-TLS in one ClientHello.
// Lives inside ClientHelloData as `pqtls`.
struct PqtlsClientObservation {
    // From supported_groups (0x000a)
    uint16_t pq_group{0};            // first PQ group in the list (0 = no PQ group offered)
    bool     pq_first_choice{false}; // true if that PQ group is the client's first choice

    // From key_share (0x0033)
    bool has_key_share{false};       // the extension was in the hello
    bool key_share_parsed{false};    // we read all of it and the lengths matched
    std::vector<uint16_t> key_share_groups; // groups the client sent a key for (no GREASE)
    std::vector<uint16_t> key_share_lens;   // key size in bytes, same order as key_share_groups

    void clear() noexcept {
        pq_group = 0;
        pq_first_choice = false;
        has_key_share = false;
        key_share_parsed = false;
        key_share_groups.clear();
        key_share_lens.clear();
    }
};

// What we observed about PQ-TLS in one ServerHello.
// Lives inside ServerHelloData as `pqtls`.
struct PqtlsServerObservation {
    uint16_t selected_group{0};   // group the server picked (0 = no key_share, e.g. TLS 1.2)
    uint16_t server_share_len{0}; // size of the server's key in bytes (0 in a HelloRetryRequest)
    bool     is_hrr{false};       // this "ServerHello" is really a HelloRetryRequest

    void clear() noexcept {
        selected_group = 0;
        server_share_len = 0;
        is_hrr = false;
    }
};

// Reads the key_share extension (0x0033) of a ClientHello.
// `reader` must cover exactly the extension body (after the 4 byte type + length).
void parse_pqtls_client_key_share(ByteReader &reader, PqtlsClientObservation &out);

// Reads the key_share extension (0x0033) of a ServerHello or HelloRetryRequest.
void parse_pqtls_server_key_share(ByteReader &reader, PqtlsServerObservation &out);

// After ALL extensions are read: finds the first PQ group in supported_groups.
// `supported_groups` must already have GREASE removed (the parser does this).
void find_pqtls_group(const std::vector<uint16_t> &supported_groups, PqtlsClientObservation &out);

// True if the 32 byte ServerHello random is the special HelloRetryRequest value.
bool is_hrr_random(const uint8_t *random);

} // namespace tlsfp

#endif // TLSFP_PQTLS_PARSER_HPP
