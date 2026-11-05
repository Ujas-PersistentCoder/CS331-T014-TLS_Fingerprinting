import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


FINGERPRINT_KINDS = ("ja3", "ja3s", "ja4", "ja4s")


@dataclass(frozen=True)
class FingerprintRecord:
    kind: str
    hash: str
    role: str = ""
    name: str = ""
    version: str = ""
    os: str = ""
    category: str = ""
    source: str = ""
    notes: str = ""


class FingerprintDB:
    """Redis-backed fingerprint database with a JSON compatibility fallback."""

    def __init__(
        self,
        db_path: str = "fingerprints.json",
        redis_url: str = "redis://127.0.0.1:6379/0",
        use_redis: bool = True,
        seed_path: str | None = None,
        manifest_path: str | None = None,
    ):
        self._path = Path(db_path)
        self._data: dict[str, str] = {}
        self._redis: Any | None = None
        self._cache: dict[tuple[str, str], FingerprintRecord | None] = {}
        self._load()

        if use_redis and self.connect(redis_url):
            default_db_dir = Path(__file__).resolve().parents[2] / "db"
            selected_seed = Path(seed_path) if seed_path else default_db_dir / "seed_fingerprints.json"
            selected_manifest = (
                Path(manifest_path) if manifest_path else default_db_dir / "capture_manifest.json"
            )
            selected_legacy = default_db_dir.parent / "python" / "fingerprints.json"
            if selected_seed.exists():
                self.load_seed_files(selected_seed, selected_manifest)
            if selected_legacy.exists():
                self.load_legacy_file(selected_legacy)

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as database_file:
                loaded = json.load(database_file)
            if isinstance(loaded, dict):
                self._data = {
                    str(hash_value): str(label)
                    for hash_value, label in loaded.items()
                    if isinstance(label, (str, int, float))
                }
        except (OSError, json.JSONDecodeError):
            self._data = {}

    def connect(self, redis_url: str = "redis://127.0.0.1:6379/0") -> bool:
        """Connect to Redis and return False when the local service is unavailable."""
        try:
            import redis

            client = redis.Redis.from_url(redis_url, decode_responses=True)
            client.ping()
            self._redis = client
            return True
        except Exception:
            self._redis = None
            return False

    def close(self) -> None:
        if self._redis is not None:
            self._redis.close()
            self._redis = None

    def __enter__(self) -> "FingerprintDB":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()

    @staticmethod
    def _redis_key(kind: str, hash_str: str) -> str:
        if kind not in FINGERPRINT_KINDS:
            raise ValueError(f"Unsupported fingerprint kind: {kind}")
        return f"tlsfp:{kind}:{hash_str}"

    @staticmethod
    def _record_from_fields(kind: str, fields: dict[str, str]) -> FingerprintRecord | None:
        hash_str = fields.get("hash", "")
        if not hash_str:
            return None
        return FingerprintRecord(
            kind=kind,
            hash=hash_str,
            role=fields.get("role", ""),
            name=fields.get("name", ""),
            version=fields.get("version", ""),
            os=fields.get("os", ""),
            category=fields.get("category", ""),
            source=fields.get("source", ""),
            notes=fields.get("notes", ""),
        )

    def lookup_record(self, hash_str: str, kind: str | None = None) -> FingerprintRecord | None:
        kinds = (kind,) if kind else FINGERPRINT_KINDS
        for candidate_kind in kinds:
            cache_key = (candidate_kind, hash_str)
            if cache_key in self._cache:
                cached = self._cache[cache_key]
                if cached is not None:
                    return cached
                continue
        if self._redis is not None:
            try:
                for candidate_kind in kinds:
                    cache_key = (candidate_kind, hash_str)
                    if cache_key in self._cache:
                        cached = self._cache[cache_key]
                        if cached is not None:
                            return cached
                        continue
                    fields = self._redis.hgetall(self._redis_key(candidate_kind, hash_str))
                    record = self._record_from_fields(candidate_kind, fields)
                    self._cache[cache_key] = record
                    if record is not None:
                        return record
            except Exception:
                self._redis = None

        return None

    def lookup(self, hash_str: str, kind: str | None = None) -> str | None:
        """Return the matched name, checking Redis before the legacy JSON map."""
        record = self.lookup_record(hash_str, kind)
        if record is not None:
            return record.name or None
        return self._data.get(hash_str)

    def store_record(self, record: FingerprintRecord) -> None:
        if self._redis is not None:
            self._redis.hset(self._redis_key(record.kind, record.hash), mapping=asdict(record))
        self._cache[(record.kind, record.hash)] = record

    def store(self, hash_str: str, label: str, kind: str | None = None) -> None:
        """Store a legacy label and optionally persist a typed Redis record."""
        self._data[hash_str] = label
        if self._redis is not None and kind is not None:
            self.store_record(FingerprintRecord(kind=kind, hash=hash_str, name=label))

    def enroll(self, hash_str: str, kind: str, name: str, role: str | None = None) -> None:
        """Persist an analyst-confirmed fingerprint label in both backends."""
        clean_hash = hash_str.strip()
        clean_name = name.strip()
        if not clean_hash or not clean_name:
            raise ValueError("A fingerprint hash and client name are required")
        if kind not in FINGERPRINT_KINDS:
            raise ValueError(f"Unsupported fingerprint kind: {kind}")

        record = FingerprintRecord(
            kind=kind,
            hash=clean_hash,
            role=role or ("server" if kind.endswith("s") else "client"),
            name=clean_name,
        )
        self._data[clean_hash] = clean_name
        self.store_record(record)
        self.save()

    def bulk_load(self, entries: dict[str, str]) -> None:
        for hash_str, label in entries.items():
            self.store(hash_str, label)

    def load_seed_files(self, seed_path: str | Path, manifest_path: str | Path | None = None) -> int:
        """Import all seed fingerprint sections into Redis and return the count."""
        if self._redis is None:
            return 0

        with Path(seed_path).open("r", encoding="utf-8") as seed_file:
            seed_data = json.load(seed_file)
        manifest = self._load_manifest(manifest_path)
        loaded = 0

        pipeline = self._redis.pipeline(transaction=False)
        pending = 0
        for kind in FINGERPRINT_KINDS:
            entries = seed_data.get(kind, [])
            for entry in entries:
                if not isinstance(entry, dict) or not entry.get("hash"):
                    continue
                role = "server" if kind.endswith("s") else "client"
                record = FingerprintRecord(
                    kind=kind,
                    hash=str(entry["hash"]),
                    role=role,
                    name=str(entry.get("client", entry.get("server", ""))),
                    version=str(entry.get("version", "")),
                    os=str(entry.get("os", "")),
                    category=str(entry.get("category", "")),
                    source=str(entry.get("source", "")),
                    notes=str(entry.get("notes", "")),
                )
                record = self._enrich_from_manifest(record, manifest)
                pipeline.hset(self._redis_key(record.kind, record.hash), mapping=asdict(record))
                self._cache[(record.kind, record.hash)] = record
                pending += 1
                loaded += 1
        if pending:
            pipeline.execute()
        return loaded

    def load_legacy_file(self, legacy_path: str | Path) -> int:
        """Import flat public JA3 labels without replacing curated Redis records."""
        if self._redis is None:
            return 0

        with Path(legacy_path).open("r", encoding="utf-8") as legacy_file:
            entries = json.load(legacy_file)
        candidates = {
            str(hash_str): FingerprintRecord(
                kind="ja3",
                hash=str(hash_str),
                role="client",
                name=str(name),
                category="public-catalog",
                source=str(legacy_path),
            )
            for hash_str, name in entries.items()
            if len(str(hash_str)) == 32
        }
        exists_pipeline = self._redis.pipeline(transaction=False)
        for hash_str in candidates:
            exists_pipeline.exists(self._redis_key("ja3", hash_str))
        existing = exists_pipeline.execute()

        write_pipeline = self._redis.pipeline(transaction=False)
        loaded = 0
        for (hash_str, record), already_exists in zip(candidates.items(), existing):
            if already_exists:
                continue
            write_pipeline.hset(self._redis_key("ja3", hash_str), mapping=asdict(record))
            self._cache[("ja3", hash_str)] = record
            loaded += 1
        if loaded:
            write_pipeline.execute()
        return loaded

    @staticmethod
    def _load_manifest(manifest_path: str | Path | None) -> dict[str, dict[str, str]]:
        if manifest_path is None or not Path(manifest_path).exists():
            return {}
        with Path(manifest_path).open("r", encoding="utf-8") as manifest_file:
            data = json.load(manifest_file)
        return {
            str(key): value
            for key, value in data.items()
            if key != "_readme" and isinstance(value, dict)
        }

    @staticmethod
    def _enrich_from_manifest(
        record: FingerprintRecord, manifest: dict[str, dict[str, str]]
    ) -> FingerprintRecord:
        source_name = record.source.removeprefix("self-captured: ")
        metadata = next(
            (
                fields
                for label, fields in manifest.items()
                if source_name == label or source_name.startswith(f"{label}_")
            ),
            {},
        )
        if not metadata:
            return record

        values = asdict(record)
        for field in ("version", "os", "category", "notes"):
            if not values[field] and metadata.get(field):
                values[field] = str(metadata[field])
        return FingerprintRecord(**values)

    def save(self) -> None:
        with self._path.open("w", encoding="utf-8") as database_file:
            json.dump(self._data, database_file, indent=4)

    def all_entries(self) -> dict[str, str]:
        return self._data.copy()