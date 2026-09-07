"""Import an approved external fingerprint catalog into Redis.

Supported input formats:

JSON object grouped by kind::

    {"ja3": [{"hash": "...", "client": "curl"}], "ja4": [...]}

Or CSV with columns::

    kind,hash,name,role,version,os,category,source,notes

Existing Redis records are preserved unless --overwrite is supplied.
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, TextIO

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "code" / "python"))

from src.db import FINGERPRINT_KINDS, FingerprintDB, FingerprintRecord  # type: ignore[reportMissingImports]


JA3_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")
JA4_PATTERN = re.compile(r"^[0-9a-zA-Z_]+$")
FOXIO_MAPPING_URL = "https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv"


def normalize_record(raw: dict[str, Any], kind: str, source: str) -> FingerprintRecord | None:
    hash_value = str(raw.get("hash", "")).strip()
    if kind in ("ja3", "ja3s"):
        valid_hash = bool(JA3_PATTERN.fullmatch(hash_value))
    else:
        valid_hash = bool(JA4_PATTERN.fullmatch(hash_value))
    if not valid_hash:
        return None

    name = str(raw.get("name", raw.get("client", raw.get("server", "")))).strip()
    if not name:
        return None
    role = str(raw.get("role", "server" if kind.endswith("s") else "client")).strip()
    return FingerprintRecord(
        kind=kind,
        hash=hash_value.lower(),
        role=role,
        name=name,
        version=str(raw.get("version", "")).strip(),
        os=str(raw.get("os", "")).strip(),
        category=str(raw.get("category", "external-catalog")).strip(),
        source=str(raw.get("source", source)).strip(),
        notes=str(raw.get("notes", "")).strip(),
    )


def read_json(path: Path) -> Iterable[FingerprintRecord]:
    with path.open("r", encoding="utf-8") as input_file:
        payload = json.load(input_file)

    if isinstance(payload, dict):
        grouped = ((kind, entries) for kind, entries in payload.items() if kind in FINGERPRINT_KINDS)
        for kind, entries in grouped:
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        record = normalize_record(entry, kind, str(path))
                        if record is not None:
                            yield record
    elif isinstance(payload, list):
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            kind = str(entry.get("kind", "")).lower()
            if kind in FINGERPRINT_KINDS:
                record = normalize_record(entry, kind, str(path))
                if record is not None:
                    yield record


def read_csv(path: Path) -> Iterable[FingerprintRecord]:
    with path.open("r", encoding="utf-8", newline="") as input_file:
        for row in csv.DictReader(input_file):
            kind = str(row.get("kind", "")).lower().strip()
            if kind not in FINGERPRINT_KINDS:
                continue
            record = normalize_record(row, kind, str(path))
            if record is not None:
                yield record


def read_foxio_csv(input_file: TextIO) -> Iterable[FingerprintRecord]:
    """Read FoxIO's ja4plus-mapping.csv format."""
    for row in csv.DictReader(input_file):
        label = next(
            (
                str(row.get(field, "")).replace("\n", " ").strip()
                for field in ("Application", "Library", "Device")
                if str(row.get(field, "")).strip()
            ),
            "",
        )
        if not label:
            continue

        metadata = {
            "name": label,
            "os": str(row.get("OS", "")).replace("\n", " ").strip(),
            "category": "foxio-ja4-mapping",
            "source": FOXIO_MAPPING_URL,
            "notes": "Imported from FoxIO JA4+ mapping; verify against local traffic.",
        }
        for kind, field, role in (("ja4", "ja4", "client"), ("ja4s", "ja4s", "server")):
            hash_value = str(row.get(field, "")).strip()
            # q-prefixed rows are QUIC fingerprints and are outside this TCP tool.
            if not hash_value or not hash_value.startswith("t"):
                continue
            record = normalize_record({**metadata, "hash": hash_value, "role": role}, kind, FOXIO_MAPPING_URL)
            if record is not None:
                yield record


def main() -> int:
    parser = argparse.ArgumentParser(description="Import external TLS fingerprints into Redis")
    parser.add_argument("input", type=Path, help="Approved JSON or CSV catalog")
    parser.add_argument("--foxio", action="store_true", help="Read FoxIO ja4plus-mapping.csv format")
    parser.add_argument("--redis-url", default="redis://127.0.0.1:6379/0")
    parser.add_argument("--overwrite", action="store_true", help="Replace existing Redis records")
    args = parser.parse_args()

    if args.input.suffix.lower() == ".csv":
        if args.foxio:
            with args.input.open("r", encoding="utf-8", newline="") as input_file:
                records = list(read_foxio_csv(input_file))
        else:
            records = read_csv(args.input)
    elif args.input.suffix.lower() == ".json":
        records = read_json(args.input)
    else:
        parser.error("input must be a .json or .csv file")

    database = FingerprintDB(redis_url=args.redis_url)
    if database._redis is None:
        print("Redis is unavailable. Start Redis and retry.", file=sys.stderr)
        return 1

    imported = 0
    skipped = 0
    rejected = 0
    seen: set[tuple[str, str]] = set()

    for record in records:
        key = (record.kind, record.hash)
        if key in seen:
            rejected += 1
            continue
        seen.add(key)

        existing = database.lookup_record(record.hash, record.kind)
        if existing is not None and not args.overwrite:
            skipped += 1
            continue
        database.store_record(record)
        imported += 1

    database.close()
    print(f"Imported: {imported}; skipped existing: {skipped}; rejected: {rejected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())