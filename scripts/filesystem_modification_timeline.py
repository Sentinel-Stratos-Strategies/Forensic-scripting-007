#!/usr/bin/env python3
"""
Filesystem Modification Timeline Scanner

This script walks the filesystem (default: root) and builds a timeline of
recent file modifications. It is designed to be run before or alongside
other detectors to give investigators temporal context about when files were
last changed. No files are modified; the script only reads metadata.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional


class ModificationTimelineScanner:
    """Collects file metadata and outputs a modification timeline."""

    def __init__(
        self,
        root: str = "/",
        max_entries: int = 500,
        exclude: Optional[List[str]] = None,
        keyword_hints: Optional[List[str]] = None,
    ) -> None:
        self.root = Path(root)
        self.max_entries = max_entries
        self.exclude = set(exclude or ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"])
        self.keyword_hints = [hint.lower() for hint in (keyword_hints or [
            "beacon",
            "square",
            "tile",
            "airtag",
            "bluetooth",
            "ble",
            "tracker",
            "rtc",
            "urtc",
            "account",
            "class",
            "password",
            "token",
            "keychain",
            "pair",
            "sync",
            "network",
        ])]
        self.records: List[Dict[str, str]] = []

    def _is_excluded_dir(self, path: Path) -> bool:
        return any(str(path).startswith(prefix) for prefix in self.exclude)

    def _iter_files(self) -> Iterable[Path]:
        for dirpath, dirnames, filenames in os.walk(self.root, topdown=True):
            if self._is_excluded_dir(Path(dirpath)):
                dirnames[:] = []
                continue

            dirnames[:] = [d for d in dirnames if not self._is_excluded_dir(Path(dirpath) / d)]

            for filename in filenames:
                yield Path(dirpath) / filename

    def _keyword_match(self, path: Path) -> Optional[str]:
        lower_name = path.name.lower()
        for hint in self.keyword_hints:
            if hint in lower_name:
                return hint
        return None

    def scan(self) -> None:
        print(f"[*] Building modification timeline from root: {self.root}")
        collected = []

        for path in self._iter_files():
            try:
                stat = path.stat()
            except OSError:
                continue

            keyword = self._keyword_match(path)
            collected.append(
                {
                    "path": str(path),
                    "modified_time": datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z",
                    "size_bytes": stat.st_size,
                    "keyword_hint": keyword or "",
                }
            )

        collected.sort(key=lambda item: item["modified_time"], reverse=True)
        self.records = collected[: self.max_entries]
        print(f"[+] Collected {len(self.records)} timeline entries (max {self.max_entries})")

    def write_json_report(self, report_path: str = "modification_timeline_report.json") -> None:
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump({"timeline": self.records}, handle, indent=2)
        print(f"[+] JSON timeline report written to {report_path}")

    def print_summary(self) -> None:
        print("\n" + "=" * 80)
        print("MODIFICATION TIMELINE SUMMARY")
        print("=" * 80)
        if not self.records:
            print("No entries recorded.")
            return

        for item in self.records[:10]:
            hint_text = f" | hint: {item['keyword_hint']}" if item["keyword_hint"] else ""
            print(f"{item['modified_time']} | {item['path']}{hint_text}")

        print("\nNote: showing up to 10 most recent entries for quick review.")


def main() -> None:
    scanner = ModificationTimelineScanner()
    scanner.scan()
    scanner.write_json_report()
    scanner.print_summary()


if __name__ == "__main__":
    main()
