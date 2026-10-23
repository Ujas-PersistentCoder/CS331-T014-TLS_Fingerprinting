#ifndef TLSFP_JA3_HPP
#define TLSFP_JA3_HPP

#include "tlsfp/types.hpp"
#include "tlsfp/parser.hpp"
#include <string>

namespace tlsfp {

/**
 * @brief Computes MD5 hex digest string from an input string using thread-local OpenSSL context.
 */
std::string md5_hex(const std::string &input);

/**
 * @brief Computes Salesforce JA3 fingerprint from parsed ClientHello data.
 */
JA3Fingerprint compute_ja3(const ClientHelloData &client);

/**
 * @brief Computes Salesforce JA3S fingerprint from parsed ServerHello data.
 */
JA3Fingerprint compute_ja3s(const ServerHelloData &server);

} // namespace tlsfp

#endif // TLSFP_JA3_HPP
