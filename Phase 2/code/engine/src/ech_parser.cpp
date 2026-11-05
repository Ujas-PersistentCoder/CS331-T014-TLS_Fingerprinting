#include "tlsfp/ech_parser.hpp"

namespace tlsfp {

const char *parse_status_name(ParseStatus status) noexcept {
    switch (status) {
        case ParseStatus::NotExamined: return "not_examined";
        case ParseStatus::Complete: return "complete";
        case ParseStatus::Incomplete: return "incomplete";
        case ParseStatus::Unsupported: return "unsupported";
        case ParseStatus::Malformed: return "malformed";
    }
    return "not_examined";
}

EchExtension parse_ech_extension(ByteReader body) {
    // Decode wire facts only; connection context and protocol findings belong to
    // ech_analysis. See docs/ECH_DeepDive_and_Integration_Strategy.md, §§2–3.
    EchExtension out;
    out.status = ParseStatus::Malformed;
    out.detail = "missing ECH variant";
    uint8_t variant = 0;
    if (!body.read_u8(variant)) return out;
    out.variant = variant;
    if (variant == 1) {
        // The inner variant is just a marker. It is structurally valid here;
        // observing it on the external client-facing link is a separate finding.
        out.detail = "trailing bytes after inner marker";
        if (body.remaining() != 0) return out;
    } else if (variant == 0) {
        // Outer layout: KDF(2), AEAD(2), config_id(1), enc<2>, payload<2>.
        // Unknown suite IDs remain numeric observations; no kem_id is sent here.
        uint16_t value = 0;
        uint8_t config = 0;
        out.detail = "truncated KDF identifier";
        if (!body.read_u16_be(value)) return out;
        out.kdf_id = value;
        out.detail = "truncated AEAD identifier";
        if (!body.read_u16_be(value)) return out;
        out.aead_id = value;
        out.detail = "missing configuration identifier";
        if (!body.read_u8(config)) return out;
        out.config_id = config;
        // config_id selects a configuration; it is not a globally unique identity.
        out.detail = "missing enc length";
        if (!body.read_u16_be(value)) return out;
        out.enc_length = value;
        // Zero-length enc is decodable: an accepted-ECH retry reuses its HPKE
        // context. Only analysis with the hello's role can judge that context.
        out.detail = "enc length exceeds extension body";
        if (!body.skip(value)) return out;
        out.detail = "missing ciphertext length";
        if (!body.read_u16_be(value)) return out;
        out.payload_length = value;
        // This is ciphertext size, including padding and AEAD expansion, not
        // hostname length. Padding buckets cannot distinguish real ECH from GREASE.
        out.detail = "ciphertext must not be empty";
        if (value == 0) return out;
        out.detail = "ciphertext length exceeds extension body";
        if (!body.skip(value)) return out;
        out.detail = "trailing bytes after ciphertext";
        // A nested length cannot leave unaccounted bytes in a complete ECH body.
        if (body.remaining() != 0) return out;
    } else {
        out.detail = "invalid ECH variant (expected 0 or 1)";
        return out;
    }
    out.status = ParseStatus::Complete;
    out.detail = "decoded";
    return out;
}

} // namespace tlsfp
