#include "tlsfp/ech_analysis.hpp"

namespace tlsfp {

bool ech_non_acceptance_observed(const EchObservation &offer, ParseStatus client_status,
                                 ParseStatus server_status, std::optional<uint16_t> version) noexcept {
    // I3: ECH needs TLS 1.3, so a known older negotiation rules out acceptance.
    // This does not identify a real offer: GREASE can produce the same evidence.
    // Conversely, TLS 1.3 negotiation alone never establishes acceptance.
    return client_status == ParseStatus::Complete && server_status == ParseStatus::Complete &&
        offer.present == true && version && (*version == 0x0301 || *version == 0x0302 || *version == 0x0303);
}

void analyze_ech(EchObservation &observation, HelloRole role) noexcept {
    // Recompute independent findings after extension traversal so randomized
    // extension order cannot hide an anomaly or overwrite another finding.
    observation.findings = 0;
    if (observation.occurrences.size() > 1) observation.findings |= DuplicateEch;
    // 0xfd00 is an EncodedClientHelloInner compression reference, not an outer
    // extension. Keep the ECH envelope even when this separate violation exists.
    if (observation.has_outer_extensions) observation.findings |= ForbiddenOuterExtensions;
    for (const auto &extension : observation.occurrences) {
        if (extension.variant == 1) observation.findings |= ExternalInnerMarker;
        // HPKE's export-only AEAD cannot encrypt ECH, even if framing is valid.
        if (extension.aead_id == 0xffff) observation.findings |= ExportOnlyAead;
        if (extension.status == ParseStatus::Complete && extension.enc_length == 0) {
            // An initial offer needs encapsulation; after HRR it may be empty.
            // Missing history stays unknown rather than being guessed as CH1.
            if (role == HelloRole::Unknown) observation.findings |= EmptyEncContextUnknown;
            if (role == HelloRole::Initial) observation.findings |= EmptyEncInInitialHello;
        }
    }
}

} // namespace tlsfp
