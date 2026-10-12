from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data" / "file_manifest.csv"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    failures = 0
    with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            path = ROOT / row["package_path"]
            expected_size = int(row["bytes"])
            expected_hash = row["sha256"]
            if not path.is_file():
                print(f"MISSING\t{row['package_path']}")
                failures += 1
                continue
            if path.stat().st_size != expected_size:
                print(f"SIZE\t{row['package_path']}")
                failures += 1
                continue
            actual_hash = sha256(path)
            if actual_hash != expected_hash:
                print(f"HASH\t{row['package_path']}")
                failures += 1
    if failures:
        print(f"Manifest verification failed: {failures} file(s)")
        return 1
    print("Manifest verification passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

