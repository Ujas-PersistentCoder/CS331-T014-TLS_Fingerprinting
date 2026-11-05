// A real TLS endpoint for experiments. All packet parsing/fingerprinting remains
// in the passive engine. Endpoint evidence supplies independent ECH labels.
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/hpke.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
constexpr char kPublicName[] = "public.ech.test";
constexpr char kInnerName[] = "inner.ech.test";

void require(bool condition, const std::string &message) {
    if (!condition) throw std::runtime_error(message);
}

std::string quote(const std::string &value) {
    std::string out = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') { out += '\\'; out += ch; }
        else if (ch < 32) {
            out += "\\u00"; out += hex[ch >> 4]; out += hex[ch & 15];
        } else out += ch;
    }
    return out + '"';
}

std::string hex(const uint8_t *bytes, size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < size; ++i) {
        out += digits[bytes[i] >> 4]; out += digits[bytes[i] & 15];
    }
    return out;
}

uint64_t now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::vector<uint8_t> read_bytes(const fs::path &path) {
    std::ifstream input(path, std::ios::binary);
    require(bool(input), "cannot read " + path.string());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_bytes(const fs::path &path, const uint8_t *bytes, size_t size) {
    require(!fs::exists(path), "refusing to replace " + path.string());
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char *>(bytes), size);
    output.close();
    require(bool(output), "cannot write " + path.string());
}

using File = std::unique_ptr<FILE, decltype(&fclose)>;
File file(const fs::path &path, const char *mode) {
    File result(fopen(path.c_str(), mode), fclose);
    require(bool(result), "cannot open " + path.string());
    return result;
}

class Socket {
public:
    explicit Socket(int fd) : fd_(fd) { require(fd >= 0, "socket operation failed"); }
    ~Socket() { close(fd_); }
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;
    int get() const { return fd_; }
private:
    int fd_;
};

sockaddr_in address(int port) {
    sockaddr_in out{};
    out.sin_family = AF_INET;
    out.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    out.sin_port = htons(port);
    return out;
}

int socket_port(int fd, bool peer) {
    sockaddr_in addr{};
    socklen_t size = sizeof(addr);
    int rc = peer ? getpeername(fd, reinterpret_cast<sockaddr *>(&addr), &size)
                  : getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &size);
    require(rc == 0, "cannot obtain socket tuple");
    return ntohs(addr.sin_port);
}

void socket_timeout(int fd) {
    timeval timeout{5, 0};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
            "cannot set socket timeout");
}

// SSL_get_client_random may refer to the inner hello under ECH. The message
// callback explicitly distinguishes the transmitted outer message from inner.
struct HelloEvidence {
    std::string outer_random;
    std::string config_sha256;
    unsigned outer_count{0};
    unsigned inner_count{0};
};

HelloEvidence hello_evidence(const fs::path &dir) {
    const auto config = read_bytes(dir / "ech-config.bin");
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(config.data(), config.size(), hash);
    HelloEvidence evidence;
    evidence.config_sha256 = hex(hash, sizeof(hash));
    return evidence;
}

void message_callback(int is_write, int, int type, const void *data, size_t length,
                      SSL *ssl, void *arg) {
    auto &evidence = *static_cast<HelloEvidence *>(arg);
    if (is_write == SSL_is_server(ssl)) return;
    const auto *bytes = static_cast<const uint8_t *>(data);
    if (type == SSL3_RT_CLIENT_HELLO_INNER) {
        ++evidence.inner_count;
    } else if (type == SSL3_RT_HANDSHAKE && length >= 38 && bytes[0] == 1) {
        ++evidence.outer_count;
        evidence.outer_random = hex(bytes + 6, 32);
    }
}

std::vector<uint8_t> single_suite_config(const EVP_HPKE_KEY *key) {
    uint8_t public_key[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
    size_t public_length = 0;
    require(EVP_HPKE_KEY_public_key(key, public_key, &public_length, sizeof(public_key)),
            "cannot export HPKE public key");
    // RFC 9849 ECHConfig, encoded with BoringSSL's public length-vector API.
    // SSL_marshal_ech_config advertises two suites at the pinned revision.
    bssl::ScopedCBB builder;
    CBB contents, child;
    uint8_t *encoded = nullptr;
    size_t size = 0;
    require(CBB_init(builder.get(), 128) && CBB_add_u16(builder.get(), 0xfe0d) &&
            CBB_add_u16_length_prefixed(builder.get(), &contents) &&
            CBB_add_u8(&contents, 42) && CBB_add_u16(&contents, EVP_HPKE_DHKEM_X25519_HKDF_SHA256) &&
            CBB_add_u16_length_prefixed(&contents, &child) &&
            CBB_add_bytes(&child, public_key, public_length) &&
            CBB_add_u16_length_prefixed(&contents, &child) &&
            CBB_add_u16(&child, EVP_HPKE_HKDF_SHA256) && CBB_add_u16(&child, EVP_HPKE_AES_128_GCM) &&
            CBB_add_u8(&contents, 64) && CBB_add_u8_length_prefixed(&contents, &child) &&
            CBB_add_bytes(&child, reinterpret_cast<const uint8_t *>(kPublicName), sizeof(kPublicName)-1) &&
            CBB_add_u16(&contents, 0) && CBB_finish(builder.get(), &encoded, &size),
            "cannot encode ECH configuration");
    std::vector<uint8_t> result(encoded, encoded + size);
    OPENSSL_free(encoded);
    return result;
}

void prepare(const fs::path &dir) {
    require(fs::create_directory(dir), "configuration directory already exists");
    fs::permissions(dir, fs::perms::owner_all);
    bssl::UniquePtr<EVP_PKEY_CTX> generator(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    require(generator && EVP_PKEY_keygen_init(generator.get()) &&
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(generator.get(), NID_X9_62_prime256v1),
            "cannot initialize certificate key generation");
    EVP_PKEY *raw_key = nullptr;
    require(EVP_PKEY_keygen(generator.get(), &raw_key), "cannot generate certificate key");
    bssl::UniquePtr<EVP_PKEY> key(raw_key);
    bssl::UniquePtr<X509> cert(X509_new());
    require(cert && X509_set_version(cert.get(), 2) &&
            ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) &&
            X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60) &&
            X509_gmtime_adj(X509_getm_notAfter(cert.get()), 86400 * 365) &&
            X509_set_pubkey(cert.get(), key.get()), "cannot initialize certificate");
    X509_NAME *name = X509_get_subject_name(cert.get());
    require(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const uint8_t *>(kPublicName), -1, -1, 0) &&
            X509_set_issuer_name(cert.get(), name), "cannot set certificate name");
    bssl::UniquePtr<X509_EXTENSION> san(X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name,
            "DNS:public.ech.test,DNS:inner.ech.test"));
    require(san && X509_add_ext(cert.get(), san.get(), -1) &&
            X509_sign(cert.get(), key.get(), EVP_sha256()), "cannot sign certificate");
    auto pem_key = file(dir / "tls-key.pem", "wx");
    auto pem_cert = file(dir / "cert.pem", "wx");
    require(PEM_write_PrivateKey(pem_key.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) &&
            PEM_write_X509(pem_cert.get(), cert.get()), "cannot write certificate");
    bssl::UniquePtr<EVP_HPKE_KEY> hpke(EVP_HPKE_KEY_new());
    require(hpke && EVP_HPKE_KEY_generate(hpke.get(), EVP_hpke_x25519_hkdf_sha256()),
            "cannot generate ECH key");
    uint8_t private_key[EVP_HPKE_MAX_PRIVATE_KEY_LENGTH];
    size_t private_length = 0;
    require(EVP_HPKE_KEY_private_key(hpke.get(), private_key, &private_length, sizeof(private_key)),
            "cannot export ECH key");
    write_bytes(dir / "ech-key.bin", private_key, private_length);
    const auto config = single_suite_config(hpke.get());
    write_bytes(dir / "ech-config.bin", config.data(), config.size());
    std::vector<uint8_t> list{static_cast<uint8_t>(config.size() >> 8), static_cast<uint8_t>(config.size())};
    list.insert(list.end(), config.begin(), config.end());
    write_bytes(dir / "ech-config-list.bin", list.data(), list.size());
}

bssl::UniquePtr<SSL_CTX> context(const fs::path &dir, bool server) {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    require(ctx && SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) &&
            SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION), "cannot set TLS version");
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_TICKET);
    SSL_CTX_set_grease_enabled(ctx.get(), 1);
    SSL_CTX_set_permute_extensions(ctx.get(), 1);
    if (server) {
        require(SSL_CTX_use_certificate_file(ctx.get(), (dir / "cert.pem").c_str(), SSL_FILETYPE_PEM) &&
                SSL_CTX_use_PrivateKey_file(ctx.get(), (dir / "tls-key.pem").c_str(), SSL_FILETYPE_PEM) &&
                SSL_CTX_check_private_key(ctx.get()) &&
                SSL_CTX_set1_groups_list(ctx.get(), "X25519:P-256"), "cannot configure TLS server");
        auto private_key = read_bytes(dir / "ech-key.bin");
        auto config = read_bytes(dir / "ech-config.bin");
        bssl::UniquePtr<EVP_HPKE_KEY> hpke(EVP_HPKE_KEY_new());
        bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
        require(hpke && keys && EVP_HPKE_KEY_init(hpke.get(), EVP_hpke_x25519_hkdf_sha256(),
                private_key.data(), private_key.size()) &&
                SSL_ECH_KEYS_add(keys.get(), 1, config.data(), config.size(), hpke.get()) &&
                SSL_CTX_set1_ech_keys(ctx.get(), keys.get()), "cannot install server ECH key");
        SSL_CTX_set_alpn_select_cb(ctx.get(), [](SSL *, const uint8_t **out, uint8_t *out_size,
                                               const uint8_t *in, unsigned size, void *) {
            static const uint8_t protocol[]{2, 'h', '2'};
            if (size != sizeof(protocol) || memcmp(in, protocol, sizeof(protocol)) != 0)
                return SSL_TLSEXT_ERR_ALERT_FATAL;
            *out = protocol + 1; *out_size = 2;
            return SSL_TLSEXT_ERR_OK;
        }, nullptr);
    } else {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
        require(SSL_CTX_load_verify_locations(ctx.get(), (dir / "cert.pem").c_str(), nullptr),
                "cannot install process-local trust");
    }
    return ctx;
}

void observation(SSL *ssl, int fd, bool server, const HelloEvidence &hello, bool success,
                 bool installed, bool grease, const std::string &profile, uint64_t started,
                 const std::string &session, const std::string &attempt) {
    const uint8_t *alpn = nullptr;
    unsigned alpn_size = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpn_size);
    std::cout << "{\"event\":\"connection\",\"role\":" << quote(server ? "server" : "client")
              << ",\"session\":" << quote(session) << ",\"attempt_id\":" << quote(attempt)
              << ",\"profile\":" << quote(profile)
              << ",\"config_sha256\":" << quote(hello.config_sha256)
              << ",\"client_ip\":\"127.0.0.1\",\"server_ip\":\"127.0.0.1\""
              << ",\"client_port\":" << socket_port(fd, server)
              << ",\"server_port\":" << socket_port(fd, !server)
              << ",\"outer_random\":" << quote(hello.outer_random)
              << ",\"outer_count\":" << hello.outer_count << ",\"inner_count\":" << hello.inner_count
              << ",\"config_installed\":" << (installed ? "true" : "false")
              << ",\"ech_grease_enabled\":" << (grease ? "true" : "false")
              << ",\"handshake_success\":" << (success ? "true" : "false")
              << ",\"certificate_verified\":" << ((!server && success && SSL_get_verify_result(ssl) == X509_V_OK) ? "true" : "false")
              << ",\"accepted\":" << (SSL_ech_accepted(ssl) ? "true" : "false")
              << ",\"resumed\":" << (SSL_session_reused(ssl) ? "true" : "false")
              << ",\"hrr\":" << (SSL_used_hello_retry_request(ssl) ? "true" : "false")
              << ",\"version\":" << SSL_version(ssl)
              << ",\"group\":" << SSL_get_group_id(ssl)
              << ",\"alpn\":" << quote(alpn ? std::string(reinterpret_cast<const char *>(alpn), alpn_size) : "")
              << ",\"started_us\":" << started << ",\"finished_us\":" << now_us() << "}\n" << std::flush;
}

void serve(const fs::path &dir, unsigned attempts, const std::string &session) {
    auto ctx = context(dir, true);
    Socket listener(socket(AF_INET, SOCK_STREAM, 0));
    auto addr = address(0);
    require(bind(listener.get(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0 &&
            listen(listener.get(), 4) == 0, "cannot bind loopback listener");
    std::cout << "{\"event\":\"ready\",\"port\":" << socket_port(listener.get(), false) << "}\n" << std::flush;
    for (unsigned i = 0; i < attempts; ++i) {
        Socket socket(accept(listener.get(), nullptr, nullptr));
        socket_timeout(socket.get());
        bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
        require(ssl && SSL_set_fd(ssl.get(), socket.get()), "cannot attach server TLS socket");
        HelloEvidence hello = hello_evidence(dir);
        SSL_set_msg_callback(ssl.get(), message_callback);
        SSL_set_msg_callback_arg(ssl.get(), &hello);
        const uint64_t started = now_us();
        const bool success = SSL_accept(ssl.get()) == 1;
        observation(ssl.get(), socket.get(), true, hello, success, true, false, "", started, session, "");
        if (success) SSL_shutdown(ssl.get());
        ERR_clear_error();
    }
}

int connect_client(const fs::path &dir, int port, const std::string &profile, bool grease,
                   const std::string &session, const std::string &attempt) {
    require(profile == "A" || profile == "B", "profile must be A or B");
    auto ctx = context(dir, false);
    require(SSL_CTX_set1_groups_list(ctx.get(), profile == "A" ? "X25519" : "P-256"), "cannot set profile group");
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    require(bool(ssl), "cannot initialize client TLS");
    const char *name = grease ? kPublicName : kInnerName;
    require(SSL_set_tlsext_host_name(ssl.get(), name) &&
            SSL_set1_host(ssl.get(), name), "cannot set verified hostname");
    const uint8_t alpn[]{2, 'h', '2'};
    require(SSL_set_alpn_protos(ssl.get(), alpn, sizeof(alpn)) == 0, "cannot set ALPN");
    SSL_set_enable_ech_grease(ssl.get(), grease);
    if (!grease) {
        const auto config = read_bytes(dir / "ech-config-list.bin");
        require(SSL_set1_ech_config_list(ssl.get(), config.data(), config.size()), "cannot install client ECH config");
    }
    Socket socket(::socket(AF_INET, SOCK_STREAM, 0));
    socket_timeout(socket.get());
    auto addr = address(port);
    require(connect(socket.get(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0 &&
            SSL_set_fd(ssl.get(), socket.get()), "cannot connect to lab server");
    HelloEvidence hello = hello_evidence(dir);
    SSL_set_msg_callback(ssl.get(), message_callback);
    SSL_set_msg_callback_arg(ssl.get(), &hello);
    const uint64_t started = now_us();
    const bool success = SSL_connect(ssl.get()) == 1;
    observation(ssl.get(), socket.get(), false, hello, success, !grease, grease, profile, started, session, attempt);
    if (success) SSL_shutdown(ssl.get());
    else ERR_print_errors_fp(stderr);
    return success ? 0 : 1;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    umask(0077);
    try {
        require(argc >= 3, "usage: ech_lab prepare DIR | server DIR COUNT SESSION | client DIR PORT A|B accepted|grease SESSION ATTEMPT");
        const std::string command = argv[1];
        if (command == "prepare" && argc == 3) prepare(argv[2]);
        else if (command == "server" && argc == 5) serve(argv[2], std::stoul(argv[3]), argv[4]);
        else if (command == "client" && argc == 8) {
            require(std::string(argv[5]) == "accepted" || std::string(argv[5]) == "grease", "invalid client mode");
            const int port = std::stoi(argv[3]);
            require(port > 0 && port <= 65535, "invalid port");
            return connect_client(argv[2], port, argv[4], std::string(argv[5]) == "grease", argv[6], argv[7]);
        } else throw std::runtime_error("invalid command or argument count");
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        ERR_print_errors_fp(stderr);
        return 1;
    }
}
