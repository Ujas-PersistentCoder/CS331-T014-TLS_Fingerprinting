#ifndef TLSFP_JA4_HPP
#define TLSFP_JA4_HPP

#include "tlsfp/types.hpp"
#include "tlsfp/parser.hpp"
#include <string>
#include <string_view>

namespace tlsfp {

/**
 * @brief Computes truncated 12-hex-character SHA-256 digest using thread-local OpenSSL context.
 */
std::string sha256_hex_12(std::string_view input);

/**
 * @brief Computes FoxIO JA4 fingerprint from parsed ClientHello data.
 */
JA4Fingerprint compute_ja4(const ClientHelloData &client);

/**
 * @brief Computes FoxIO JA4S fingerprint from parsed ServerHello data.
 */
JA4Fingerprint compute_ja4s(const ServerHelloData &server);

} // namespace tlsfp

#endif // TLSFP_JA4_HPP
