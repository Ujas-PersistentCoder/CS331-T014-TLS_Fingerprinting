#include "tlsfp/ech_analysis.hpp"

namespace tlsfp {

void analyze_ech(EchObservation &observation, HelloRole role) noexcept {
    observation.findings = 0;
    if (observation.occurrences.size() > 1) observation.findings |= DuplicateEch;
    if (observation.has_outer_extensions) observation.findings |= ForbiddenOuterExtensions;
    for (const auto &extension : observation.occurrences) {
        if (extension.variant == 1) observation.findings |= ExternalInnerMarker;
        if (extension.aead_id == 0xffff) observation.findings |= ExportOnlyAead;
        if (extension.status == ParseStatus::Complete && extension.enc_length == 0) {
            if (role == HelloRole::Unknown) observation.findings |= EmptyEncContextUnknown;
            if (role == HelloRole::Initial) observation.findings |= EmptyEncInInitialHello;
        }
    }
}

} // namespace tlsfp
