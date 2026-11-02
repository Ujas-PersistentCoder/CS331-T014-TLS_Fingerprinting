#include "tlsfp/pqtls_analysis.hpp"

#include <cstdio>

namespace tlsfp {

namespace {

// "0x%04x" formatting, consistent with capture.cpp to_hex()
std::string hex16(uint16_t value) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%04x", value);
    return std::string(buf);
}

} // anonymous namespace

// --- Flow Correlation & Posture ---

PqtlsOffer make_pqtls_offer(const PqtlsClientObservation &client) {
    PqtlsOffer offer;
    offer.seen = true;
    offer.pq_group = client.pq_group;
    for (uint16_t group : client.key_share_groups) {
        if (is_pqtls_group(group)) {
            offer.pq_key_sent = true;
        }
    }
    return offer;
}

// Classical groups (RFC 8446 Sec. 4.2.7, RFC 7919, RFC 8734)
bool is_known_classical_group(uint16_t group) {
    if (group == 0x0017) return true;                    // secp256r1
    if (group == 0x0018) return true;                    // secp384r1
    if (group == 0x0019) return true;                    // secp521r1
    if (group == 0x001d) return true;                    // x25519
    if (group == 0x001e) return true;                    // x448
    if (group >= 0x001f && group <= 0x0021) return true; // brainpool (TLS 1.3)
    if (group >= 0x0100 && group <= 0x0104) return true; // ffdhe2048 .. ffdhe8192
    return false;
}

namespace {
// Classical outcome, split by whether PQ was offered
PqtlsPosture classical_label(const PqtlsOffer &offer) {
    if (offer.pq_group != 0) return PqtlsPosture::CLASSICAL_SELECTED_AFTER_HYBRID_OFFER;
    return PqtlsPosture::CLASSICAL_NO_PQ_OFFERED;
}
} // anonymous namespace

// Rule order matters; anything not supported by observed bytes stays UNKNOWN
PqtlsPosture pqtls_posture(const PqtlsOffer &offer, const PqtlsServerObservation &server,
                           uint16_t negotiated_version) {
    // 1. No ClientHello on this flow
    if (!offer.seen) return PqtlsPosture::UNKNOWN_NO_CLIENT_HELLO;

    // 2. No server key_share: TLS 1.2 is classical, TLS 1.3 (e.g. PSK-only) is unknown
    if (!server.has_key_share) {
        if (negotiated_version != 0 && negotiated_version <= 0x0303) return classical_label(offer);
        return PqtlsPosture::UNKNOWN_SERVER_SELECTION;
    }

    // 3. Malformed server key_share framing
    if (!server.key_share_parsed) return PqtlsPosture::UNKNOWN_SERVER_SELECTION;

    // 4. HRR: final selection comes with the second ServerHello
    if (server.is_hrr) return PqtlsPosture::HRR_REQUESTED_RETRY;

    // 5. PQ hybrid group, only confirmed with exact RFC 10024 server key size
    if (is_pqtls_group(server.selected_group)) {
        if (server.server_share_len == pqtls_expected_server_len(server.selected_group)) {
            return PqtlsPosture::HYBRID_SELECTED_OBSERVED;
        }
        return PqtlsPosture::UNKNOWN_SERVER_SELECTION;
    }

    // 6. Known classical group
    if (is_known_classical_group(server.selected_group)) return classical_label(offer);

    // 7. Unrecognized group
    return PqtlsPosture::UNKNOWN_SERVER_SELECTION;
}

const char *pqtls_posture_name(PqtlsPosture posture) {
    switch (posture) {
        case PqtlsPosture::UNKNOWN_NO_CLIENT_HELLO:               return "UNKNOWN (ClientHello not seen)";
        case PqtlsPosture::UNKNOWN_SERVER_SELECTION:              return "UNKNOWN (server selection not established)";
        case PqtlsPosture::HRR_REQUESTED_RETRY:                   return "HRR_REQUESTED_RETRY";
        case PqtlsPosture::HYBRID_SELECTED_OBSERVED:              return "HYBRID_SELECTED_OBSERVED";
        case PqtlsPosture::CLASSICAL_SELECTED_AFTER_HYBRID_OFFER: return "CLASSICAL_SELECTED_AFTER_HYBRID_OFFER";
        case PqtlsPosture::CLASSICAL_NO_PQ_OFFERED:               return "CLASSICAL_NO_PQ_OFFERED";
    }
    return "?";
}

// --- Proactive vs Reactive Share (PQ-TLS doc Sec. 5.3) ---

// Rule order matters
PqtlsShareMode pqtls_share_mode(const PqtlsClientObservation &client, bool after_hrr) {
    // 1. No PQ group in supported_groups
    if (client.pq_group == 0) return PqtlsShareMode::NO_PQ_OFFERED;

    // 2. Post-HRR ClientHello: key_share reflects the server's request, not client preference
    if (after_hrr) return PqtlsShareMode::RETRY_AFTER_HRR;

    // 3. No key_share extension: PQ listed only
    if (!client.has_key_share) return PqtlsShareMode::SUPPORTED_ONLY;

    // 4. Malformed key_share framing
    if (!client.key_share_parsed) return PqtlsShareMode::UNKNOWN_SHARE;

    // 5. Every PQ key must match the exact size table (same table as the wire check,
    //    so this label cannot contradict PQTLS_MALFORMED_SHARE_LENGTH)
    bool pq_key_seen = false;
    for (size_t i = 0; i < client.key_share_groups.size(); ++i) {
        uint16_t expected = pqtls_expected_client_len(client.key_share_groups[i]);
        if (expected == 0) continue;            // Non-PQ group
        pq_key_seen = true;
        if (client.key_share_lens[i] != expected) {
            return PqtlsShareMode::UNKNOWN_SHARE;
        }
    }
    if (pq_key_seen) return PqtlsShareMode::PROACTIVE_SHARE_VALID;

    // 6. PQ listed, only classical keys sent
    return PqtlsShareMode::SUPPORTED_ONLY;
}

const char *pqtls_share_mode_name(PqtlsShareMode mode) {
    switch (mode) {
        case PqtlsShareMode::NO_PQ_OFFERED:         return "NO_PQ_OFFERED";
        case PqtlsShareMode::PROACTIVE_SHARE_VALID: return "PROACTIVE_SHARE_VALID";
        case PqtlsShareMode::SUPPORTED_ONLY:        return "SUPPORTED_ONLY";
        case PqtlsShareMode::RETRY_AFTER_HRR:       return "RETRY_AFTER_HRR";
        case PqtlsShareMode::UNKNOWN_SHARE:         return "UNKNOWN (key share unreadable or PQ key size invalid)";
    }
    return "?";
}

// --- Wire Checks (PQ-TLS doc Sec. 5.6) ---

uint16_t pqtls_expected_client_len(uint16_t group) {
    if (group == 0x11ec) return 1216;
    if (group == 0x11eb) return 1249;
    if (group == 0x11ed) return 1665;
    if (group == 0x6399) return 1216;
    if (group == 0x639a) return 1249;
    return 0;
}

uint16_t pqtls_expected_server_len(uint16_t group) {
    if (group == 0x11ec) return 1120;
    if (group == 0x11eb) return 1153;
    if (group == 0x11ed) return 1665;
    if (group == 0x6399) return 1120;
    if (group == 0x639a) return 1153;
    return 0;
}

uint32_t pqtls_client_findings(const PqtlsClientObservation &client) {
    uint32_t findings = PQTLS_FINDING_NONE;

    if (client.has_key_share && !client.key_share_parsed) findings |= PQTLS_MALFORMED_KEY_SHARE;

    if (client.duplicate_key_share) findings |= PQTLS_DUPLICATE_EXTENSION;
    if (client.duplicate_supported_groups) findings |= PQTLS_DUPLICATE_EXTENSION;

    // Exact RFC 10024 size per PQ key
    for (size_t i = 0; i < client.key_share_groups.size(); ++i) {
        uint16_t expected = pqtls_expected_client_len(client.key_share_groups[i]);
        if (expected == 0) continue;  // Non-PQ group
        if (client.key_share_lens[i] != expected) findings |= PQTLS_MALFORMED_SHARE_LENGTH;
    }
    return findings;
}

uint32_t pqtls_server_findings(const PqtlsServerObservation &server) {
    uint32_t findings = PQTLS_FINDING_NONE;

    if (server.duplicate_key_share) findings |= PQTLS_DUPLICATE_EXTENSION;

    // Truncated key, trailing bytes, or HRR carrying more than the group;
    // declared length is untrusted, so skip the size check
    if (server.has_key_share && !server.key_share_parsed) {
        findings |= PQTLS_MALFORMED_KEY_SHARE;
        return findings;
    }

    // HRR carries no key
    if (server.is_hrr) return findings;

    uint16_t expected = pqtls_expected_server_len(server.selected_group);
    if (expected != 0 && server.server_share_len != expected) {
        findings |= PQTLS_MALFORMED_SHARE_LENGTH;
    }
    return findings;
}

// --- Verbose Output Text ---

// Display names for common groups
std::string pqtls_group_name(uint16_t group) {
    if (group == 0x001d) return "x25519";
    if (group == 0x0017) return "secp256r1";
    if (group == 0x0018) return "secp384r1";
    if (group == 0x11ec) return "X25519MLKEM768";
    if (group == 0x11eb) return "SecP256r1MLKEM768";
    if (group == 0x11ed) return "SecP384r1MLKEM1024";
    if (group == 0x6399) return "X25519Kyber768Draft00";
    if (group == 0x639a) return "SecP256r1Kyber768Draft00";
    return "other";
}

// [V-PQTLS-Offer]
std::string pqtls_offer_text(const PqtlsClientObservation &client) {
    if (client.pq_group == 0) return "no PQ group offered";

    std::string text = "offered " + hex16(client.pq_group) + " (" + pqtls_group_name(client.pq_group) + ")";
    if (client.pq_first_choice) {
        text += ", first choice";
    } else {
        text += ", not first choice";
    }
    return text;
}

// [V-PQTLS-Keys]
std::string pqtls_keys_text(const PqtlsClientObservation &client) {
    if (!client.has_key_share) return "<none>";
    if (!client.key_share_parsed) return "present, but could not be read (bad lengths)";
    if (client.key_share_groups.empty()) return "empty";

    std::string text;
    for (size_t i = 0; i < client.key_share_groups.size(); ++i) {
        if (i > 0) text += ", ";
        text += hex16(client.key_share_groups[i]) + " (" + pqtls_group_name(client.key_share_groups[i]) + ") ";
        text += std::to_string(client.key_share_lens[i]) + "B";
    }
    return text;
}

// [V-PQTLS-Group]
std::string pqtls_server_text(const PqtlsServerObservation &server) {
    if (!server.has_key_share) return "<none>";
    if (!server.key_share_parsed) return "present, but could not be read (bad lengths)";

    // HRR: group requested from the client, no key
    if (server.is_hrr) {
        return "HelloRetryRequest: asks for " + hex16(server.selected_group) +
               " (" + pqtls_group_name(server.selected_group) + ")";
    }

    std::string text = hex16(server.selected_group) + " (" + pqtls_group_name(server.selected_group) + ")";
    if (is_pqtls_group(server.selected_group)) {
        text += ", post-quantum hybrid";
    } else {
        text += ", classical";
    }
    text += ", key " + std::to_string(server.server_share_len) + "B";
    return text;
}

// Findings bitmask to text ("ok" = no wire anomaly)
namespace {
std::string findings_text(uint32_t findings, const std::string &details) {
    if (findings == PQTLS_FINDING_NONE) return "ok";

    std::string text;
    if (findings & PQTLS_MALFORMED_SHARE_LENGTH) text += "PQC_MALFORMED_SHARE_LENGTH ";
    if (findings & PQTLS_DUPLICATE_EXTENSION) text += "PQC_DUPLICATE_EXTENSION ";
    if (findings & PQTLS_MALFORMED_KEY_SHARE) text += "PQC_MALFORMED_KEY_SHARE ";
    return text + details;
}
} // anonymous namespace

// [V-PQTLS-Check] (client)
std::string pqtls_client_check_text(const PqtlsClientObservation &client) {
    std::string details;
    if (client.has_key_share && !client.key_share_parsed) details += "(key_share could not be read) ";
    for (size_t i = 0; i < client.key_share_groups.size(); ++i) {
        uint16_t expected = pqtls_expected_client_len(client.key_share_groups[i]);
        if (expected == 0) continue;
        if (client.key_share_lens[i] == expected) continue;
        details += "(" + hex16(client.key_share_groups[i]) + " sent " +
                   std::to_string(client.key_share_lens[i]) + "B, expected " +
                   std::to_string(expected) + "B) ";
    }
    if (client.duplicate_key_share) details += "(key_share twice) ";
    if (client.duplicate_supported_groups) details += "(supported_groups twice) ";
    return findings_text(pqtls_client_findings(client), details);
}

// [V-PQTLS-Check] (server)
std::string pqtls_server_check_text(const PqtlsServerObservation &server) {
    std::string details;
    bool unreadable = server.has_key_share && !server.key_share_parsed;
    if (unreadable) details += "(key_share framing invalid) ";
    uint16_t expected = pqtls_expected_server_len(server.selected_group);
    if (!unreadable && !server.is_hrr && expected != 0 && server.server_share_len != expected) {
        details += "(" + hex16(server.selected_group) + " sent " +
                   std::to_string(server.server_share_len) + "B, expected " +
                   std::to_string(expected) + "B) ";
    }
    if (server.duplicate_key_share) details += "(key_share twice) ";
    return findings_text(pqtls_server_findings(server), details);
}

} // namespace tlsfp
