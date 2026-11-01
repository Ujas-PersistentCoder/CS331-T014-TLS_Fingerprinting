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
    EchExtension out;
    out.status = ParseStatus::Malformed;
    out.detail = "missing ECH variant";
    uint8_t variant = 0;
    if (!body.read_u8(variant)) return out;
    out.variant = variant;
    if (variant == 1) {
        out.detail = "trailing bytes after inner marker";
        if (body.remaining() != 0) return out;
    } else if (variant == 0) {
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
        out.detail = "missing enc length";
        if (!body.read_u16_be(value)) return out;
        out.enc_length = value;
        out.detail = "enc length exceeds extension body";
        if (!body.skip(value)) return out;
        out.detail = "missing ciphertext length";
        if (!body.read_u16_be(value)) return out;
        out.payload_length = value;
        out.detail = "ciphertext must not be empty";
        if (value == 0) return out;
        out.detail = "ciphertext length exceeds extension body";
        if (!body.skip(value)) return out;
        out.detail = "trailing bytes after ciphertext";
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
