"""One-command entrypoint: generate synthetic logs + ground truth, init SQLite.

Usage:
    python -m generator.run
"""
from pathlib import Path

from generator import synth
from db.schema import init_db, DB_PATH

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    print("=== J-001 Phase 0: generate data + init DB ===")
    synth.main()
    init_db()
    print(f"SQLite ready at {DB_PATH}")


if __name__ == "__main__":
    main()
