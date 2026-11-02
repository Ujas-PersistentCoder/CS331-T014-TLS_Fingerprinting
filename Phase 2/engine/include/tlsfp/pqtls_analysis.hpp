#ifndef TLSFP_PQTLS_ANALYSIS_HPP
#define TLSFP_PQTLS_ANALYSIS_HPP

// PQ-TLS interpretation layer: labels derived from pqtls_parser.hpp observations.
// Labels fall back to UNKNOWN when the wire evidence is insufficient.

#include "tlsfp/pqtls_parser.hpp"
#include <cstdint>
#include <string>

namespace tlsfp {

/**
 * @brief Per-flow client offer, held until the ServerHello arrives.
 */
struct PqtlsOffer {
    bool     seen{false};          // ClientHello observed on this flow
    uint16_t pq_group{0};          // First PQ group offered (0 = none)
    bool     pq_key_sent{false};   // PQ key present in key_share
    bool     hrr_seen{false};      // Previous ServerHello on this flow was an HRR
};

// Snapshot of the client observation for flow correlation
PqtlsOffer make_pqtls_offer(const PqtlsClientObservation &client);

// Key exchange outcome per flow (PQ-TLS doc Sec. 5.2)
enum class PqtlsPosture : uint8_t {
    UNKNOWN_NO_CLIENT_HELLO,                // ClientHello not observed
    UNKNOWN_SERVER_SELECTION,               // Unreadable key_share, wrong PQ size, unknown group,
                                            // or TLS 1.3 without key_share
    HRR_REQUESTED_RETRY,                    // HelloRetryRequest
    HYBRID_SELECTED_OBSERVED,               // PQ hybrid group with exact RFC 10024 key size
    CLASSICAL_SELECTED_AFTER_HYBRID_OFFER,  // PQ offered, known classical group (or TLS 1.2) selected
    CLASSICAL_NO_PQ_OFFERED                 // No PQ offered, classical selected
};

/**
 * @brief Classifies the server's key exchange choice against the client offer.
 * @param negotiated_version ServerHelloData::selected_version (separates TLS 1.2 from
 *        TLS 1.3 without key_share)
 */
PqtlsPosture pqtls_posture(const PqtlsOffer &offer, const PqtlsServerObservation &server,
                           uint16_t negotiated_version);

// Known classical groups (RFC 8446, RFC 7919, RFC 8734)
bool is_known_classical_group(uint16_t group);
const char *pqtls_posture_name(PqtlsPosture posture);

// Proactive vs reactive PQ key share, per ClientHello (PQ-TLS doc Sec. 5.3)
enum class PqtlsShareMode : uint8_t {
    NO_PQ_OFFERED,          // No PQ group in supported_groups
    PROACTIVE_SHARE_VALID,  // PQ key sent with exact RFC 10024 size
    SUPPORTED_ONLY,         // PQ group listed, no PQ key sent
    RETRY_AFTER_HRR,        // Second ClientHello after HRR (keys follow server request)
    UNKNOWN_SHARE           // key_share unreadable or PQ key size mismatch
};

PqtlsShareMode pqtls_share_mode(const PqtlsClientObservation &client, bool after_hrr);
const char *pqtls_share_mode_name(PqtlsShareMode mode);

// --- Wire Checks (PQ-TLS doc Sec. 5.6) ---

// Exact key_share sizes per direction (RFC 10024 Sec. 3), 0 for non-PQ groups
//   Client = ML-KEM encapsulation key + EC share, Server = ML-KEM ciphertext + EC share
//   0x11ec X25519MLKEM768:     client 1184+32 = 1216   server 1088+32 = 1120
//   0x11eb SecP256r1MLKEM768:  client 1184+65 = 1249   server 1088+65 = 1153
//   0x11ed SecP384r1MLKEM1024: client 1568+97 = 1665   server 1568+97 = 1665
//   0x6399 / 0x639a Kyber-768 drafts: same sizes as their ML-KEM-768 counterparts
uint16_t pqtls_expected_client_len(uint16_t group);
uint16_t pqtls_expected_server_len(uint16_t group);

// Wire anomaly flags (bitmask, can combine)
enum PqtlsFinding : uint32_t {
    PQTLS_FINDING_NONE              = 0,
    PQTLS_MALFORMED_SHARE_LENGTH    = 1u << 0,  // PQ key length != RFC 10024 size
    PQTLS_DUPLICATE_EXTENSION       = 1u << 1,  // Repeated key_share / supported_groups
    PQTLS_MALFORMED_KEY_SHARE       = 1u << 2,  // key_share framing unreadable
};

uint32_t pqtls_client_findings(const PqtlsClientObservation &client);
uint32_t pqtls_server_findings(const PqtlsServerObservation &server);

// Verbose output text
std::string pqtls_group_name(uint16_t group);                           // e.g. "X25519MLKEM768"
std::string pqtls_offer_text(const PqtlsClientObservation &client);     // [V-PQTLS-Offer]
std::string pqtls_keys_text(const PqtlsClientObservation &client);      // [V-PQTLS-Keys]
std::string pqtls_server_text(const PqtlsServerObservation &server);    // [V-PQTLS-Group]
std::string pqtls_client_check_text(const PqtlsClientObservation &client); // [V-PQTLS-Check] (client)
std::string pqtls_server_check_text(const PqtlsServerObservation &server); // [V-PQTLS-Check] (server)
// [V-PQTLS-Share] uses pqtls_share_mode_name(), [V-PQTLS-Result] uses pqtls_posture_name()

} // namespace tlsfp

#endif // TLSFP_PQTLS_ANALYSIS_HPP
