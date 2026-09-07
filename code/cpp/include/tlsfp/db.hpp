#ifndef TLSFP_DB_HPP
#define TLSFP_DB_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace tlsfp {

enum class FingerprintKind {
	JA3,
	JA3S,
	JA4,
	JA4S
};

struct FingerprintRecord {
	FingerprintKind kind{FingerprintKind::JA3};
	std::string hash;
	std::string role;
	std::string name;
	std::string version;
	std::string os;
	std::string category;
	std::string source;
	std::string notes;
};

struct RedisConfig {
	std::string host{"127.0.0.1"};
	uint16_t port{6379};
	int database{0};
	int connect_timeout_ms{1000};
};

class FingerprintDatabase {
public:
	explicit FingerprintDatabase(RedisConfig config = {});
	~FingerprintDatabase();

	FingerprintDatabase(const FingerprintDatabase &) = delete;
	FingerprintDatabase &operator=(const FingerprintDatabase &) = delete;

	bool connect();
	void disconnect() noexcept;
	bool is_connected() const noexcept;
	bool ping();

	bool store(const FingerprintRecord &record);
	bool enroll(FingerprintKind kind, const std::string &hash,
				const std::string &name, const std::string &role = {});
	bool lookup(FingerprintKind kind, const std::string &hash,
				FingerprintRecord &record);

	std::size_t load_seed_files(const std::string &seed_path,
								const std::string &manifest_path = {});
	std::size_t load_legacy_ja3_file(const std::string &legacy_path);

	static const char *kind_name(FingerprintKind kind) noexcept;
	static std::string redis_key(FingerprintKind kind,
								 const std::string &hash);

	struct RedisValue;

private:
	bool send_command(const std::vector<std::string> &arguments,
					  RedisValue &reply);
	bool select_database();

	RedisConfig config_;
	int socket_{-1};
	std::unordered_map<std::string, FingerprintRecord> cache_;
	std::unordered_set<std::string> missing_cache_;
};

} // namespace tlsfp

#endif
