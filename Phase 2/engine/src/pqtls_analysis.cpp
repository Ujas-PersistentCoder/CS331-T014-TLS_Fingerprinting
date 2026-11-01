#include "tlsfp/pqtls_analysis.hpp"

#include <cstdio>

namespace tlsfp {

namespace {

// 0x11ec style text for a 2 byte number (same format as the rest of the output).
std::string hex16(uint16_t value) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%04x", value);
    return std::string(buf);
}

} // anonymous namespace

// ===================== Client offer vs server answer =====================

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

// Decides the label, one rule at a time. The order of the checks matters.
PqtlsPosture pqtls_posture(const PqtlsOffer &offer, const PqtlsServerObservation &server) {
    // 1. Without the ClientHello we cannot compare anything.
    if (!offer.seen) return PqtlsPosture::UNKNOWN_NO_CLIENT_HELLO;

    // 2. An HRR is not the final answer yet: the client will send a second hello.
    if (server.is_hrr) return PqtlsPosture::HRR_REQUESTED_RETRY;

    // 3. The server picked a PQ hybrid group.
    if (is_pqtls_group(server.selected_group)) return PqtlsPosture::HYBRID_SELECTED_OBSERVED;

    // 4. The server picked something classical (or TLS 1.2, where selected_group is 0).
    if (offer.pq_group != 0) return PqtlsPosture::CLASSICAL_SELECTED_AFTER_HYBRID_OFFER;
    return PqtlsPosture::CLASSICAL_NO_PQ_OFFERED;
}

const char *pqtls_posture_name(PqtlsPosture posture) {
    switch (posture) {
        case PqtlsPosture::UNKNOWN_NO_CLIENT_HELLO:               return "UNKNOWN (ClientHello not seen)";
        case PqtlsPosture::HRR_REQUESTED_RETRY:                   return "HRR_REQUESTED_RETRY";
        case PqtlsPosture::HYBRID_SELECTED_OBSERVED:              return "HYBRID_SELECTED_OBSERVED";
        case PqtlsPosture::CLASSICAL_SELECTED_AFTER_HYBRID_OFFER: return "CLASSICAL_SELECTED_AFTER_HYBRID_OFFER";
        case PqtlsPosture::CLASSICAL_NO_PQ_OFFERED:               return "CLASSICAL_NO_PQ_OFFERED";
    }
    return "?";
}

// ===================== Proactive vs reactive (doc section 5.3) =====================

// Decides the share mode, one rule at a time. The order of the checks matters.
PqtlsShareMode pqtls_share_mode(const PqtlsClientObservation &client, bool after_hrr) {
    // 1. No PQ group on the menu at all.
    if (client.pq_group == 0) return PqtlsShareMode::NO_PQ_OFFERED;

    // 2. A second hello after an HRR sends the key the server asked for,
    //    so it says nothing about the client's own choice.
    if (after_hrr) return PqtlsShareMode::RETRY_AFTER_HRR;

    // 3. If we could not read key_share, we cannot say.
    if (!client.key_share_parsed) return PqtlsShareMode::UNKNOWN_SHARE;

    // 4. Look for a key for a PQ group in key_share.
    for (size_t i = 0; i < client.key_share_groups.size(); ++i) {
        if (!is_pqtls_group(client.key_share_groups[i])) continue;

        if (client.key_share_lens[i] >= PQTLS_MIN_PQ_KEY_LEN) {
            return PqtlsShareMode::PROACTIVE_SHARE_VALID;
        }
        return PqtlsShareMode::UNKNOWN_SHARE;  // too small to be a real PQ key
    }

    // 5. PQ group listed, but no PQ key sent.
    return PqtlsShareMode::SUPPORTED_ONLY;
}

const char *pqtls_share_mode_name(PqtlsShareMode mode) {
    switch (mode) {
        case PqtlsShareMode::NO_PQ_OFFERED:         return "NO_PQ_OFFERED";
        case PqtlsShareMode::PROACTIVE_SHARE_VALID: return "PROACTIVE_SHARE_VALID";
        case PqtlsShareMode::SUPPORTED_ONLY:        return "SUPPORTED_ONLY";
        case PqtlsShareMode::RETRY_AFTER_HRR:       return "RETRY_AFTER_HRR";
        case PqtlsShareMode::UNKNOWN_SHARE:         return "UNKNOWN (key share unreadable or PQ key too small)";
    }
    return "?";
}

// ===================== Text for the output =====================

// Human readable name for a key exchange group (only the common ones).
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

// [V-PQTLS-Offer]: did the client offer a post-quantum group?
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

// [V-PQTLS-Keys]: which keys did the client actually send, and how big?
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

// [V-PQTLS-Group]: which key exchange did the server pick?
std::string pqtls_server_text(const PqtlsServerObservation &server) {
    if (server.selected_group == 0) return "<none>";

    // An HRR has no key, only the group the server wants the client to use instead.
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

} // namespace tlsfp
