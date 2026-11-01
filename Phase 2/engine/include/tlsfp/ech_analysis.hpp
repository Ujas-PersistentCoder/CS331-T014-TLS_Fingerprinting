#ifndef TLSFP_ECH_ANALYSIS_HPP
#define TLSFP_ECH_ANALYSIS_HPP

#include "tlsfp/ech_parser.hpp"

namespace tlsfp {

enum EchFinding : uint32_t {
    DuplicateEch = 1u << 0,
    ForbiddenOuterExtensions = 1u << 1,
    ExternalInnerMarker = 1u << 2,
    ExportOnlyAead = 1u << 3,
    EmptyEncContextUnknown = 1u << 4,
    EmptyEncInInitialHello = 1u << 5,
};

enum class HelloRole { Unknown, Initial, AfterHrr };

// Our capture point is the external client-facing link. No role is guessed from
// arrival order: checkpoint 1 has no bidirectional connection history.
void analyze_ech(EchObservation &observation, HelloRole role = HelloRole::Unknown) noexcept;

} // namespace tlsfp
#endif
