import csv
import sys
from pathlib import Path

# Add the project root to python path to import src
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "code" / "python"))

from src.db import FingerprintDB

def seed_db():
    # Adjust paths relative to the project root
    ja3_csv = PROJECT_ROOT.parent / "ja3" / "lists" / "osx-nix-ja3.csv"
    local_csv = PROJECT_ROOT / "code" / "reference" / "expected_hashes.csv"
    db_path = PROJECT_ROOT / "code" / "python" / "fingerprints.json"
    
    db = FingerprintDB(str(db_path))
    
    added = 0
    if ja3_csv.exists():
        with open(ja3_csv, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith("Copyright"):
                    continue
                if len(row) >= 2:
                    ja3_hash = row[0].strip()
                    label = row[1].strip()
                    if len(ja3_hash) == 32:
                        db.store(ja3_hash, label)
                        added += 1
                        
    if local_csv.exists():
        with open(local_csv, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            # Skip header if it exists
            header_skipped = False
            for row in reader:
                if not row:
                    continue
                if not header_skipped and row[0].lower() == "hash":
                    header_skipped = True
                    continue
                if len(row) >= 2:
                    ja3_hash = row[0].strip()
                    label = row[1].strip()
                    if len(ja3_hash) == 32:
                        db.store(ja3_hash, label)
                        added += 1

    db.save()
    print(f"Seeded {added} fingerprints into {db_path.name}")

if __name__ == "__main__":
    seed_db()
