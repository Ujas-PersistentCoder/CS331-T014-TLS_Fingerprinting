import json
from pathlib import Path

class FingerprintDB:
    """Thin JSON-backed fingerprint database."""

    def __init__(self, db_path: str = "fingerprints.json"):
        self._path = Path(db_path)
        self._data: dict[str, str] = {}  # hash -> label
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                with open(self._path, 'r', encoding='utf-8') as f:
                    self._data = json.load(f)
            except json.JSONDecodeError:
                self._data = {}
        else:
            self._data = {}

    def lookup(self, hash_str: str) -> str | None:
        """Lookup a fingerprint hash. Returns the client/server label if found."""
        return self._data.get(hash_str)

    def store(self, hash_str: str, label: str) -> None:
        """Store a new fingerprint mapping."""
        self._data[hash_str] = label

    def bulk_load(self, entries: dict[str, str]) -> None:
        """Merge multiple entries into the database."""
        self._data.update(entries)

    def save(self) -> None:
        """Persist the database to disk."""
        with open(self._path, 'w', encoding='utf-8') as f:
            json.dump(self._data, f, indent=4)

    def all_entries(self) -> dict[str, str]:
        """Return a copy of all fingerprint entries."""
        return self._data.copy()
