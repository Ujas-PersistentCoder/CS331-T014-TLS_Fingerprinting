#include "tlsfp/db.hpp"

#include <cerrno>
#include <cctype>
#include <fstream>
#include <map>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits>
#include <utility>
#include <cstring>
#include <charconv>

namespace tlsfp {

struct FingerprintDatabase::RedisValue {
    char type{'-'};
    std::string text;
    std::vector<RedisValue> items;
};

namespace {

class JsonReader {
public:
    explicit JsonReader(std::string text) : text_(std::move(text)) {}

    bool read_seed_entries(
        const std::map<std::string, std::map<std::string, std::string>> &manifest,
        std::vector<FingerprintRecord> &records) {
        skip_space();
        if (!consume('{')) return false;

        while (true) {
            skip_space();
            if (consume('}')) return true;

            std::string section;
            if (!read_string(section) || !consume(':')) return false;
            if (section == "ja3" || section == "ja3s" || section == "ja4" || section == "ja4s") {
                FingerprintKind kind = FingerprintKind::JA3;
                if (section == "ja3s") kind = FingerprintKind::JA3S;
                if (section == "ja4") kind = FingerprintKind::JA4;
                if (section == "ja4s") kind = FingerprintKind::JA4S;
                if (!read_seed_array(kind, manifest, records)) return false;
            } else if (!skip_value()) {
                return false;
            }

            skip_space();
            if (consume('}')) return true;
            if (!consume(',')) return false;
        }
    }

    bool read_manifest(std::map<std::string, std::map<std::string, std::string>> &manifest) {
        skip_space();
        if (!consume('{')) return false;

        while (true) {
            skip_space();
            if (consume('}')) return true;

            std::string key;
            if (!read_string(key) || !consume(':')) return false;
            std::map<std::string, std::string> fields;
            if (peek() == '{') {
                if (!read_string_object(fields)) return false;
                manifest.emplace(std::move(key), std::move(fields));
            } else if (!skip_value()) {
                return false;
            }

            skip_space();
            if (consume('}')) return true;
            if (!consume(',')) return false;
        }
    }

    bool read_legacy_entries(std::vector<std::pair<std::string, std::string>> &entries) {
        skip_space();
        if (!consume('{')) return false;

        while (true) {
            skip_space();
            if (consume('}')) return true;

            std::string hash;
            std::string label;
            if (!read_string(hash) || !consume(':') || !read_string(label)) return false;
            entries.emplace_back(std::move(hash), std::move(label));

            skip_space();
            if (consume('}')) return true;
            if (!consume(',')) return false;
        }
    }

private:
    bool read_seed_array(
        FingerprintKind kind,
        const std::map<std::string, std::map<std::string, std::string>> &manifest,
        std::vector<FingerprintRecord> &records) {
        skip_space();
        if (!consume('[')) return false;

        while (true) {
            skip_space();
            if (consume(']')) return true;

            std::map<std::string, std::string> fields;
            if (!read_string_object(fields)) return false;

            FingerprintRecord record;
            record.kind = kind;
            record.hash = fields["hash"];
            record.role = (kind == FingerprintKind::JA3S || kind == FingerprintKind::JA4S)
                              ? "server" : "client";
            record.name = fields.count("client") ? fields["client"] : fields["server"];
            record.version = fields["version"];
            record.os = fields["os"];
            record.category = fields["category"];
            record.source = fields["source"];
            record.notes = fields["notes"];

            enrich_from_manifest(record, manifest);
            if (!record.hash.empty()) records.push_back(std::move(record));

            skip_space();
            if (consume(']')) return true;
            if (!consume(',')) return false;
        }
    }

    bool read_string_object(std::map<std::string, std::string> &fields) {
        skip_space();
        if (!consume('{')) return false;

        while (true) {
            skip_space();
            if (consume('}')) return true;

            std::string key;
            if (!read_string(key) || !consume(':')) return false;
            skip_space();
            if (peek() == '"') {
                std::string value;
                if (!read_string(value)) return false;
                fields.emplace(std::move(key), std::move(value));
            } else if (!skip_value()) {
                return false;
            }

            skip_space();
            if (consume('}')) return true;
            if (!consume(',')) return false;
        }
    }

    void enrich_from_manifest(
        FingerprintRecord &record,
        const std::map<std::string, std::map<std::string, std::string>> &manifest) {
        const std::string marker = "self-captured: ";
        std::string label;
        if (record.source.rfind(marker, 0) == 0) {
            label = record.source.substr(marker.size());
            const std::size_t first_separator = label.find('_');
            const std::size_t timestamp_separator = label.find('_', first_separator + 1);
            if (timestamp_separator != std::string::npos) label.resize(timestamp_separator);
        }
        if (label.empty()) label = record.name;

        const auto found = manifest.find(label);
        if (found == manifest.end()) return;
        const auto &metadata = found->second;
        if (metadata.count("role")) record.role = metadata.at("role");
        if (record.name.empty() && metadata.count("name")) record.name = metadata.at("name");
        if (record.version.empty() && metadata.count("version")) record.version = metadata.at("version");
        if (record.os.empty() && metadata.count("os")) record.os = metadata.at("os");
        if (record.category.empty() && metadata.count("category")) record.category = metadata.at("category");
        if (record.notes.empty() && metadata.count("notes")) record.notes = metadata.at("notes");
    }

    [[nodiscard]] char peek() const noexcept {
        return position_ < text_.size() ? text_[position_] : '\0';
    }

    bool consume(char expected) {
        skip_space();
        if (peek() != expected) return false;
        ++position_;
        return true;
    }

    void skip_space() {
        while (position_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[position_]))) {
            ++position_;
        }
    }

    bool read_string(std::string &value) {
        skip_space();
        if (peek() != '"') return false;
        ++position_;
        value.clear();

        while (position_ < text_.size()) {
            const char current = text_[position_++];
            if (current == '"') return true;
            if (current != '\\' || position_ >= text_.size()) {
                value.push_back(current);
                continue;
            }

            const char escaped = text_[position_++];
            switch (escaped) {
                case '"':  value.push_back('"'); break;
                case '\\': value.push_back('\\'); break;
                case '/':  value.push_back('/'); break;
                case 'b':  value.push_back('\b'); break;
                case 'f':  value.push_back('\f'); break;
                case 'n':  value.push_back('\n'); break;
                case 'r':  value.push_back('\r'); break;
                case 't':  value.push_back('\t'); break;
                default:   value.push_back(escaped); break;
            }
        }
        return false;
    }

    bool skip_value() {
        skip_space();
        const char current = peek();
        if (current == '"') {
            std::string ignored;
            return read_string(ignored);
        }
        if (current == '{' || current == '[') {
            const char close = current == '{' ? '}' : ']';
            ++position_;
            int depth = 1;
            bool in_string = false;
            bool escaped = false;
            while (position_ < text_.size() && depth > 0) {
                const char value = text_[position_++];
                if (in_string) {
                    if (escaped) escaped = false;
                    else if (value == '\\') escaped = true;
                    else if (value == '"') in_string = false;
                } else if (value == '"') {
                    in_string = true;
                } else if (value == current) {
                    ++depth;
                } else if (value == close) {
                    --depth;
                }
            }
            return depth == 0;
        }
        while (position_ < text_.size() && peek() != ',' && peek() != '}' && peek() != ']') {
            ++position_;
        }
        return true;
    }

    std::string text_;
    std::size_t position_{0};
};

bool write_all(int fd, const char *data, std::size_t length) {
    std::size_t total = 0;
    while (total < length) {
        ssize_t written = ::send(fd, data + total, length - total, 0);
        if (written <= 0) {
            if (written < 0 && errno == EINTR) continue;
            return false;
        }
        total += static_cast<std::size_t>(written);
    }
    return true;
}

bool read_exact(int fd, char *buffer, std::size_t length) {
    std::size_t total = 0;
    while (total < length) {
        ssize_t bytes_read = ::recv(fd, buffer + total, length - total, 0);
        if (bytes_read <= 0) {
            if (bytes_read < 0 && errno == EINTR) continue;
            return false;
        }
        total += static_cast<std::size_t>(bytes_read);
    }
    return true;
}

bool read_line(int fd, std::string &line) {
    line.clear();
    char ch = 0;
    while (true) {
        ssize_t bytes_read = ::recv(fd, &ch, 1, 0);
        if (bytes_read <= 0) {
            if (bytes_read < 0 && errno == EINTR) continue;
            return false;
        }
        if (ch == '\r') {
            char next = 0;
            if (!read_exact(fd, &next, 1) || next != '\n') {
                return false;
            }
            return true;
        }
        line.push_back(ch);
    }
}

bool parse_resp_integer(const std::string &str, long &val) {
    if (str.empty()) return false;
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), val);
    return ec == std::errc{} && ptr == (str.data() + str.size());
}

bool read_redis_value(int fd, FingerprintDatabase::RedisValue &value) {
    char type = 0;
    if (!read_exact(fd, &type, 1)) return false;
    value.type = type;
    value.text.clear();
    value.items.clear();

    if (type == '+' || type == '-' || type == ':') {
        return read_line(fd, value.text);
    }
    if (type == '$') {
        std::string len_str;
        if (!read_line(fd, len_str)) return false;
        long length = 0;
        if (!parse_resp_integer(len_str, length)) return false;
        if (length == -1) return true; // Null bulk string
        if (length < 0) return false;

        value.text.resize(static_cast<std::size_t>(length));
        if (!read_exact(fd, value.text.data(), static_cast<std::size_t>(length))) {
            return false;
        }
        char crlf[2];
        return read_exact(fd, crlf, 2) && crlf[0] == '\r' && crlf[1] == '\n';
    }
    if (type == '*') {
        std::string count_str;
        if (!read_line(fd, count_str)) return false;
        long count = 0;
        if (!parse_resp_integer(count_str, count)) return false;
        if (count == -1) return true;
        if (count < 0) return false;

        value.items.resize(static_cast<std::size_t>(count));
        for (std::size_t i = 0; i < static_cast<std::size_t>(count); ++i) {
            if (!read_redis_value(fd, value.items[i])) return false;
        }
        return true;
    }
    return false;
}

} // anonymous namespace

FingerprintDatabase::FingerprintDatabase(RedisConfig config)
    : config_(std::move(config)) {}

FingerprintDatabase::~FingerprintDatabase() {
    disconnect();
}

FingerprintDatabase::FingerprintDatabase(FingerprintDatabase &&other) noexcept
    : config_(std::move(other.config_)),
      socket_(other.socket_),
      cache_(std::move(other.cache_)),
      missing_cache_(std::move(other.missing_cache_)) {
    other.socket_ = -1;
}

FingerprintDatabase &FingerprintDatabase::operator=(FingerprintDatabase &&other) noexcept {
    if (this != &other) {
        disconnect();
        config_ = std::move(other.config_);
        socket_ = other.socket_;
        other.socket_ = -1;
        cache_ = std::move(other.cache_);
        missing_cache_ = std::move(other.missing_cache_);
    }
    return *this;
}

bool FingerprintDatabase::connect() {
    disconnect();

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = nullptr;
    const std::string port_str = std::to_string(config_.port);
    if (::getaddrinfo(config_.host.c_str(), port_str.c_str(), &hints, &result) != 0) {
        return false;
    }

    for (struct addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
        int fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        struct timeval timeout{};
        timeout.tv_sec = config_.connect_timeout_ms / 1000;
        timeout.tv_usec = (config_.connect_timeout_ms % 1000) * 1000;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            socket_ = fd;
            break;
        }
        ::close(fd);
    }
    ::freeaddrinfo(result);

    if (socket_ < 0) return false;
    if (!select_database()) {
        disconnect();
        return false;
    }
    return true;
}

void FingerprintDatabase::disconnect() noexcept {
    if (socket_ >= 0) {
        ::close(socket_);
        socket_ = -1;
    }
}

bool FingerprintDatabase::is_connected() const noexcept {
    return socket_ >= 0;
}

bool FingerprintDatabase::ping() {
    RedisValue reply;
    return send_command({"PING"}, reply) && reply.type == '+' && reply.text == "PONG";
}

bool FingerprintDatabase::store(const FingerprintRecord &record) {
    if (record.hash.empty()) return false;
    const std::string key = redis_key(record.kind, record.hash);
    cache_[key] = record;
    missing_cache_.erase(key);

    if (!is_connected()) return true; // Stored in local memory cache

    std::vector<std::string> args = {"HSET", key,
        "hash", record.hash,
        "role", record.role,
        "name", record.name,
        "version", record.version,
        "os", record.os,
        "category", record.category,
        "source", record.source,
        "notes", record.notes
    };
    RedisValue reply;
    return send_command(args, reply) && reply.type == ':';
}

bool FingerprintDatabase::enroll(FingerprintKind kind, const std::string &hash,
                                const std::string &name, const std::string &role) {
    FingerprintRecord record;
    record.kind = kind;
    record.hash = hash;
    record.name = name;
    record.role = role.empty() ? (kind == FingerprintKind::JA3S || kind == FingerprintKind::JA4S ? "server" : "client") : role;
    record.category = "enrolled";
    record.source = "analyst-cli";
    return store(record);
}

bool FingerprintDatabase::lookup(FingerprintKind kind, const std::string &hash,
                                FingerprintRecord &record) {
    const std::string key = redis_key(kind, hash);
    auto cached = cache_.find(key);
    if (cached != cache_.end()) {
        record = cached->second;
        return true;
    }
    if (missing_cache_.count(key)) return false;

    if (!is_connected()) {
        missing_cache_.insert(key);
        return false;
    }

    RedisValue reply;
    if (!send_command({"HGETALL", key}, reply) || reply.type != '*' || reply.items.empty()) {
        missing_cache_.insert(key);
        return false;
    }

    std::map<std::string, std::string> fields;
    for (std::size_t i = 0; i + 1 < reply.items.size(); i += 2) {
        fields[reply.items[i].text] = reply.items[i + 1].text;
    }
    if (fields.empty()) {
        missing_cache_.insert(key);
        return false;
    }

    record.kind = kind;
    record.hash = fields["hash"];
    record.role = fields["role"];
    record.name = fields["name"];
    record.version = fields["version"];
    record.os = fields["os"];
    record.category = fields["category"];
    record.source = fields["source"];
    record.notes = fields["notes"];

    cache_[key] = record;
    return true;
}

std::size_t FingerprintDatabase::load_seed_files(const std::string &seed_path,
                                                const std::string &manifest_path) {
    std::ifstream seed_file(seed_path);
    if (!seed_file) return 0;
    const std::string seed_text((std::istreambuf_iterator<char>(seed_file)),
                                 std::istreambuf_iterator<char>());

    std::map<std::string, std::map<std::string, std::string>> manifest;
    if (!manifest_path.empty()) {
        std::ifstream manifest_file(manifest_path);
        if (manifest_file) {
            const std::string manifest_text((std::istreambuf_iterator<char>(manifest_file)),
                                             std::istreambuf_iterator<char>());
            JsonReader manifest_reader(manifest_text);
            manifest_reader.read_manifest(manifest);
        }
    }

    std::vector<FingerprintRecord> records;
    JsonReader seed_reader(seed_text);
    if (!seed_reader.read_seed_entries(manifest, records)) return 0;

    std::size_t stored = 0;
    for (const FingerprintRecord &record : records) {
        if (store(record)) ++stored;
    }
    return stored;
}

std::size_t FingerprintDatabase::load_legacy_ja3_file(const std::string &legacy_path) {
    std::ifstream legacy_file(legacy_path);
    if (!legacy_file) return 0;
    const std::string legacy_text((std::istreambuf_iterator<char>(legacy_file)),
                                  std::istreambuf_iterator<char>());

    std::vector<std::pair<std::string, std::string>> entries;
    JsonReader reader(legacy_text);
    if (!reader.read_legacy_entries(entries)) return 0;

    std::size_t stored = 0;
    for (const auto &entry : entries) {
        if (entry.first.size() != 32) continue;
        FingerprintRecord existing;
        if (lookup(FingerprintKind::JA3, entry.first, existing)) continue;

        FingerprintRecord record;
        record.kind = FingerprintKind::JA3;
        record.hash = entry.first;
        record.role = "client";
        record.name = entry.second;
        record.category = "public-catalog";
        record.source = legacy_path;
        if (store(record)) ++stored;
    }
    return stored;
}

const char* FingerprintDatabase::kind_name(FingerprintKind kind) noexcept {
    switch (kind) {
        case FingerprintKind::JA3:  return "ja3";
        case FingerprintKind::JA3S: return "ja3s";
        case FingerprintKind::JA4:  return "ja4";
        case FingerprintKind::JA4S: return "ja4s";
    }
    return "unknown";
}

std::string FingerprintDatabase::redis_key(FingerprintKind kind, const std::string &hash) {
    return "tlsfp:" + std::string(kind_name(kind)) + ":" + hash;
}

bool FingerprintDatabase::select_database() {
    if (config_.database == 0) return true;
    RedisValue reply;
    return send_command({"SELECT", std::to_string(config_.database)}, reply) &&
           reply.type == '+' && reply.text == "OK";
}

bool FingerprintDatabase::send_command(const std::vector<std::string> &arguments,
                                       RedisValue &reply) {
    if (!is_connected() || arguments.empty()) return false;

    std::string request = "*" + std::to_string(arguments.size()) + "\r\n";
    for (const std::string &argument : arguments) {
        request += "$" + std::to_string(argument.size()) + "\r\n" + argument + "\r\n";
    }
    if (!write_all(socket_, request.data(), request.size())) {
        disconnect();
        return false;
    }
    if (!read_redis_value(socket_, reply)) {
        disconnect();
        return false;
    }
    return reply.type != '-';
}

} // namespace tlsfp