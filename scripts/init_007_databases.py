#!/usr/bin/env python3
"""Initialize the three 007 SQLite database layers."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {
    "007_core.sqlite": ROOT / "database" / "007_core_schema.sql",
    "007_graph.sqlite": ROOT / "database" / "007_graph_schema.sql",
    "007_outputs.sqlite": ROOT / "database" / "007_outputs_schema.sql",
}


def apply_schema(db_path: Path, schema_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(schema_path.read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize 007 core/graph/output SQLite databases")
    parser.add_argument("--out-dir", required=True, help="Directory where database files should be written")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    for db_name, schema_path in SCHEMAS.items():
        db_path = out_dir / db_name
        apply_schema(db_path, schema_path)
        print(db_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
