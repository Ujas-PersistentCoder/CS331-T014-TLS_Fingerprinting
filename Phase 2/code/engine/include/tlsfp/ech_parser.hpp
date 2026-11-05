#ifndef TLSFP_ECH_PARSER_HPP
#define TLSFP_ECH_PARSER_HPP

#include "tlsfp/byte_reader.hpp"
#include <optional>
#include <vector>

namespace tlsfp {

constexpr uint16_t ECH_EXTENSION = 0xfe0d;
constexpr uint16_t ECH_OUTER_EXTENSIONS = 0xfd00;

// Completeness is independent of presence and protocol findings.
enum class ParseStatus { NotExamined, Complete, Incomplete, Unsupported, Malformed };
const char *parse_status_name(ParseStatus status) noexcept;

struct EchExtension {
    ParseStatus status{ParseStatus::NotExamined};
    const char *detail{"not examined"}; // Static diagnostic, never a packet-buffer view.
    // Optional fields distinguish unavailable bytes from observed numeric zero.
    // Retain only identifiers/lengths, never encapsulation or ciphertext bytes.
    std::optional<uint8_t> variant;
    std::optional<uint16_t> kdf_id;
    std::optional<uint16_t> aead_id;
    std::optional<uint8_t> config_id;
    std::optional<uint16_t> enc_length;
    std::optional<uint16_t> payload_length;
};

struct EchObservation {
    std::optional<bool> present; // nullopt until presence or complete absence is known.
    std::vector<EchExtension> occurrences; // No authoritative selection on duplicates.
    bool has_outer_extensions{false};
    uint32_t findings{0};

    void clear() noexcept {
        present.reset();
        occurrences.clear();
        has_outer_extensions = false;
        findings = 0;
    }
};

// The caller supplies the COMPLETE extension body, excluding its 4-byte TLS header.
// Insufficient internal lengths therefore mean malformed, not capture loss.
// The result owns all retained fields; enc/ciphertext bytes are deliberately not retained.
EchExtension parse_ech_extension(ByteReader body);

} // namespace tlsfp
#endif
