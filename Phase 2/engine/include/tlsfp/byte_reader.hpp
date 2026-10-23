#ifndef TLSFP_BYTE_READER_HPP
#define TLSFP_BYTE_READER_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string_view>
#include <optional>

namespace tlsfp {

/**
 * @brief Zero-copy, bounds-checked Big-Endian binary parser.
 * Operates purely on non-owning memory slices without heap allocation.
 */
class ByteReader {
public:
    constexpr ByteReader() noexcept : data_(nullptr), size_(0), offset_(0) {}
    constexpr ByteReader(const uint8_t *data, size_t size) noexcept 
        : data_(data), size_(size), offset_(0) {}

    [[nodiscard]] constexpr size_t remaining() const noexcept {
        return (offset_ <= size_) ? (size_ - offset_) : 0;
    }

    [[nodiscard]] constexpr size_t offset() const noexcept {
        return offset_;
    }

    [[nodiscard]] constexpr size_t size() const noexcept {
        return size_;
    }

    [[nodiscard]] constexpr const uint8_t* current_ptr() const noexcept {
        return data_ + offset_;
    }

    [[nodiscard]] constexpr bool has_bytes(size_t n) const noexcept {
        return remaining() >= n;
    }

    constexpr bool skip(size_t n) noexcept {
        if (!has_bytes(n)) return false;
        offset_ += n;
        return true;
    }

    // --- Primitive Big-Endian Readers ---

    bool read_u8(uint8_t &val) noexcept {
        if (!has_bytes(1)) return false;
        val = data_[offset_++];
        return true;
    }

    bool read_u16_be(uint16_t &val) noexcept {
        if (!has_bytes(2)) return false;
        val = static_cast<uint16_t>(data_[offset_] << 8) | 
              static_cast<uint16_t>(data_[offset_ + 1]);
        offset_ += 2;
        return true;
    }

    bool read_u24_be(uint32_t &val) noexcept {
        if (!has_bytes(3)) return false;
        val = (static_cast<uint32_t>(data_[offset_]) << 16) |
              (static_cast<uint32_t>(data_[offset_ + 1]) << 8) |
              (static_cast<uint32_t>(data_[offset_ + 2]));
        offset_ += 3;
        return true;
    }

    bool read_u32_be(uint32_t &val) noexcept {
        if (!has_bytes(4)) return false;
        val = (static_cast<uint32_t>(data_[offset_]) << 24) |
              (static_cast<uint32_t>(data_[offset_ + 1]) << 16) |
              (static_cast<uint32_t>(data_[offset_ + 2]) << 8) |
              (static_cast<uint32_t>(data_[offset_ + 3]));
        offset_ += 4;
        return true;
    }

    // --- Slices and Sub-readers ---

    bool read_bytes(size_t n, const uint8_t *&ptr) noexcept {
        if (!has_bytes(n)) return false;
        ptr = data_ + offset_;
        offset_ += n;
        return true;
    }

    bool read_string_view(size_t n, std::string_view &sv) noexcept {
        if (!has_bytes(n)) return false;
        sv = std::string_view(reinterpret_cast<const char*>(data_ + offset_), n);
        offset_ += n;
        return true;
    }

    std::optional<ByteReader> spawn_sub_reader(size_t len) noexcept {
        if (!has_bytes(len)) return std::nullopt;
        ByteReader sub(data_ + offset_, len);
        offset_ += len;
        return sub;
    }

private:
    const uint8_t *data_;
    size_t size_;
    size_t offset_;
};

} // namespace tlsfp

#endif // TLSFP_BYTE_READER_HPP
