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

// Findings assume an external client-facing tap, where an inner marker is anomalous.
// The caller supplies a role from connection history; a standalone parse has none.
void analyze_ech(EchObservation &observation, HelloRole role = HelloRole::Unknown) noexcept;

// I3 is negative evidence only. Callers must establish a consistent connection
// and omit retry sequences whose analysis is outside this checkpoint.
bool ech_non_acceptance_observed(const EchObservation &, ParseStatus client_status,
                                 ParseStatus server_status, std::optional<uint16_t> version) noexcept;

} // namespace tlsfp
#endif
