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
			record.role = kind == FingerprintKind::JA3S || kind == FingerprintKind::JA4S
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

	char peek() const noexcept {
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
				case '"': value.push_back('"'); break;
				case '\\': value.push_back('\\'); break;
				case '/': value.push_back('/'); break;
				case 'b': value.push_back('\b'); break;
				case 'f': value.push_back('\f'); break;
				case 'n': value.push_back('\n'); break;
				case 'r': value.push_back('\r'); break;
				case 't': value.push_back('\t'); break;
				default: value.push_back(escaped); break;
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
			const char open = current;
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
				} else if (value == open) {
					++depth;
				} else if (value == close) {
					--depth;
				}
			}
			return depth == 0;
		}

		while (position_ < text_.size() && text_[position_] != ',' &&
			   text_[position_] != '}' && text_[position_] != ']') {
			++position_;
		}
		return current != '\0';
	}

	std::string text_;
	std::size_t position_{0};
};

bool write_all(int socket, const char *data, std::size_t length) {
	while (length > 0) {
		const ssize_t written = send(socket, data, length, MSG_NOSIGNAL);
		if (written <= 0) return false;
		data += written;
		length -= static_cast<std::size_t>(written);
	}
	return true;
}

bool read_byte(int socket, char &value) {
	return recv(socket, &value, 1, 0) == 1;
}

bool read_line(int socket, std::string &line) {
	line.clear();
	char value = '\0';
	while (read_byte(socket, value)) {
		if (value == '\r') {
			if (!read_byte(socket, value) || value != '\n') return false;
			return true;
		}
		line.push_back(value);
	}
	return false;
}

bool parse_size(const std::string &text, std::size_t &value) {
	try {
		const unsigned long long parsed = std::stoull(text);
		if (parsed > std::numeric_limits<std::size_t>::max()) return false;
		value = static_cast<std::size_t>(parsed);
		return true;
	} catch (...) {
		return false;
	}
}

bool read_redis_value(int socket, FingerprintDatabase::RedisValue &value) {
	char prefix = '\0';
	if (!read_byte(socket, prefix)) return false;
	value.type = prefix;

	if (prefix == '+' || prefix == '-' || prefix == ':') return read_line(socket, value.text);
	if (prefix == '$') {
		std::string length_text;
		std::size_t length = 0;
		if (!read_line(socket, length_text) || length_text == "-1") return true;
		if (!parse_size(length_text, length)) return false;
		value.text.resize(length);
		std::size_t received = 0;
		while (received < length) {
			const ssize_t count = recv(socket, value.text.data() + received, length - received, 0);
			if (count <= 0) return false;
			received += static_cast<std::size_t>(count);
		}
		char cr = '\0';
		char lf = '\0';
		return read_byte(socket, cr) && read_byte(socket, lf) && cr == '\r' && lf == '\n';
	}
	if (prefix == '*') {
		std::string count_text;
		std::size_t count = 0;
		if (!read_line(socket, count_text) || count_text == "-1") return true;
		if (!parse_size(count_text, count)) return false;
		value.items.resize(count);
		for (FingerprintDatabase::RedisValue &item : value.items) {
			if (!read_redis_value(socket, item)) return false;
		}
		return true;
	}
	return false;
}

} // namespace

FingerprintDatabase::FingerprintDatabase(RedisConfig config) : config_(std::move(config)) {}

FingerprintDatabase::~FingerprintDatabase() {
	disconnect();
}

bool FingerprintDatabase::connect() {
	if (is_connected()) return true;

	addrinfo hints{};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	addrinfo *addresses = nullptr;
	const std::string port = std::to_string(config_.port);
	if (getaddrinfo(config_.host.c_str(), port.c_str(), &hints, &addresses) != 0) return false;

	for (addrinfo *address = addresses; address != nullptr; address = address->ai_next) {
		const int candidate = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
		if (candidate < 0) continue;

		timeval timeout{};
		timeout.tv_sec = config_.connect_timeout_ms / 1000;
		timeout.tv_usec = (config_.connect_timeout_ms % 1000) * 1000;
		setsockopt(candidate, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(candidate, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

		if (::connect(candidate, address->ai_addr, address->ai_addrlen) == 0) {
			socket_ = candidate;
			break;
		}
		close(candidate);
	}
	freeaddrinfo(addresses);

	return is_connected() && select_database();
}

void FingerprintDatabase::disconnect() noexcept {
	if (socket_ >= 0) {
		close(socket_);
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
	if (record.hash.empty() || !is_connected()) return false;
	RedisValue reply;
	const bool sent = send_command({"HSET", redis_key(record.kind, record.hash),
									"hash", record.hash,
									"kind", kind_name(record.kind),
									"role", record.role,
									"name", record.name,
									"version", record.version,
									"os", record.os,
									"category", record.category,
									"source", record.source,
									"notes", record.notes}, reply);
	return sent && reply.type != '-';
}

bool FingerprintDatabase::enroll(FingerprintKind kind, const std::string &hash,
								 const std::string &name, const std::string &role) {
	if (hash.empty() || name.empty()) return false;

	FingerprintRecord record;
	record.kind = kind;
	record.hash = hash;
	record.name = name;
	record.role = role.empty() ? (kind == FingerprintKind::JA3S || kind == FingerprintKind::JA4S
											 ? "server" : "client") : role;
	return store(record);
}

bool FingerprintDatabase::lookup(FingerprintKind kind, const std::string &hash,
								 FingerprintRecord &record) {
	if (hash.empty() || !is_connected()) return false;
	RedisValue reply;
	if (!send_command({"HGETALL", redis_key(kind, hash)}, reply) || reply.type != '*') return false;
	if (reply.items.empty()) return false;

	std::map<std::string, std::string> fields;
	for (std::size_t index = 0; index + 1 < reply.items.size(); index += 2) {
		fields[reply.items[index].text] = reply.items[index + 1].text;
	}
	if (fields.empty()) return false;

	record.kind = kind;
	record.hash = fields["hash"];
	record.role = fields["role"];
	record.name = fields["name"];
	record.version = fields["version"];
	record.os = fields["os"];
	record.category = fields["category"];
	record.source = fields["source"];
	record.notes = fields["notes"];
	return !record.hash.empty();
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
	if (!seed_reader.read_seed_entries(manifest, records) || !is_connected()) return 0;

	std::size_t stored = 0;
	for (const FingerprintRecord &record : records) {
		if (store(record)) ++stored;
	}
	return stored;
}

std::size_t FingerprintDatabase::load_legacy_ja3_file(const std::string &legacy_path) {
	std::ifstream legacy_file(legacy_path);
	if (!legacy_file || !is_connected()) return 0;
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

const char *FingerprintDatabase::kind_name(FingerprintKind kind) noexcept {
	switch (kind) {
		case FingerprintKind::JA3: return "ja3";
		case FingerprintKind::JA3S: return "ja3s";
		case FingerprintKind::JA4: return "ja4";
		case FingerprintKind::JA4S: return "ja4s";
	}
	return "unknown";
}

std::string FingerprintDatabase::redis_key(FingerprintKind kind,
										   const std::string &hash) {
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
