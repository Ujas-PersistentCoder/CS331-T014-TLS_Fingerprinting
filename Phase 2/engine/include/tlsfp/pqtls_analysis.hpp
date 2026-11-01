#ifndef TLSFP_PQTLS_ANALYSIS_HPP
#define TLSFP_PQTLS_ANALYSIS_HPP

// PQ-TLS (post-quantum TLS), part 2: INTERPRET.
//
// These functions take what pqtls_parser.cpp observed and decide what it means.
// Every label comes from a named rule, and the label is UNKNOWN when the
// evidence is missing (for example, no ClientHello was seen).

#include "tlsfp/pqtls_parser.hpp"
#include <cstdint>
#include <string>

namespace tlsfp {

// What we remember about a client's PQ-TLS offer until the server answers.
struct PqtlsOffer {
    bool     seen{false};          // we saw a ClientHello on this connection
    uint16_t pq_group{0};          // first PQ group in supported_groups (0 = none)
    bool     pq_key_sent{false};   // the client sent a key for a PQ group in key_share
    bool     hrr_seen{false};      // the server answered this hello with a HelloRetryRequest
};

// Copies the PQ-TLS facts out of a ClientHello observation.
PqtlsOffer make_pqtls_offer(const PqtlsClientObservation &client);

// The result of the key exchange, judged from the client's offer and the server's answer.
enum class PqtlsPosture : uint8_t {
    UNKNOWN_NO_CLIENT_HELLO,                // we never saw the ClientHello for this connection
    HRR_REQUESTED_RETRY,                    // server sent a HelloRetryRequest
    HYBRID_SELECTED_OBSERVED,               // server picked a PQ hybrid group
    CLASSICAL_SELECTED_AFTER_HYBRID_OFFER,  // client offered PQ, server picked classical (or TLS 1.2)
    CLASSICAL_NO_PQ_OFFERED                 // client never offered PQ, so classical was the only option
};

PqtlsPosture pqtls_posture(const PqtlsOffer &offer, const PqtlsServerObservation &server);
const char *pqtls_posture_name(PqtlsPosture posture);

// Did the client send its big PQ key right away, or only list PQ as supported?
// (PQ-TLS doc section 5.3: proactive vs reactive.) Judged from one ClientHello.
enum class PqtlsShareMode : uint8_t {
    NO_PQ_OFFERED,          // no PQ group in supported_groups
    PROACTIVE_SHARE_VALID,  // a PQ key of at least 1200 bytes was sent right away
    SUPPORTED_ONLY,         // PQ group listed, but no PQ key sent
    RETRY_AFTER_HRR,        // second hello after a HelloRetryRequest: its keys follow the server's request
    UNKNOWN_SHARE           // key_share unreadable, or the PQ key is too small to be a real one
};

// The smallest real PQ hybrid key: X25519MLKEM768 is 1216 bytes, the others are bigger.
// 1200 is the threshold used in the PQ-TLS doc (section 5.3).
constexpr uint16_t PQTLS_MIN_PQ_KEY_LEN = 1200;

PqtlsShareMode pqtls_share_mode(const PqtlsClientObservation &client, bool after_hrr);
const char *pqtls_share_mode_name(PqtlsShareMode mode);

// Text for the verbose output lines.
std::string pqtls_group_name(uint16_t group);                           // e.g. "X25519MLKEM768"
std::string pqtls_offer_text(const PqtlsClientObservation &client);     // [V-PQTLS-Offer]
std::string pqtls_keys_text(const PqtlsClientObservation &client);      // [V-PQTLS-Keys]
std::string pqtls_server_text(const PqtlsServerObservation &server);    // [V-PQTLS-Group]
// [V-PQTLS-Share] uses pqtls_share_mode_name(), [V-PQTLS-Result] uses pqtls_posture_name()

} // namespace tlsfp

#endif // TLSFP_PQTLS_ANALYSIS_HPP
