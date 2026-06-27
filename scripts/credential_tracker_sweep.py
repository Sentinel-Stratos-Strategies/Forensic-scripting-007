#!/usr/bin/env python3
"""
Credential and Tracker Artifact Scanner

This script performs a root-level sweep for credential material (keychains,
tokens, encryption keys) and tracker-related artifacts (AirTag, BLE
beacons, etc). It is designed for forensic use alongside the other
LLM/AI-focused detectors and outputs both JSON and SQLite records so the
results can be queried later.
"""

import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List


class CredentialArtifactScanner:
    """Scan the filesystem and SQLite databases for sensitive artifacts."""

    def __init__(self, root: str = "/", db_path: str = "credential_artifacts.db"):
        self.root = Path(root)
        self.db_path = Path(db_path)
        self.results: List[Dict[str, str]] = []
        self._compiled_keywords = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [
                r"keychain", r"token", r"encryption key", r"private key", r"secret",
                r"credential", r"password", r"passcode", r"auth", r"bearer",
                r"api[_-]?key", r"session", r"cookie", r"ticket",
                r"beacon", r"square", r"tile", r"airtag", r"bluetooth", r"ble",
                r"tracker", r"rtc", r"urtc", r"account", r"class", r"network",
                r"pair", r"sync"
            ]
        ]
        self.suspicious_filenames = [
            "keychain.db",
            "login.keychain",
            "tokens.json",
            "credentials.db",
            "secrets.db",
            "network_keys.db",
            "bluetooth.db",
            "pairings.db",
            "wifi.db",
        ]
        self.excluded_dirs = {
            "/proc",
            "/sys",
            "/dev",
            "/run",
            "/tmp",
            "/var/tmp",
        }
        self.max_file_size_bytes = 5 * 1024 * 1024  # 5MB for text inspection
        self.max_rows_per_table = 25
        self._init_database()

    def _init_database(self) -> None:
        """Create the SQLite database used to store findings."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT,
                    finding_type TEXT,
                    keyword TEXT,
                    evidence TEXT,
                    severity TEXT,
                    created_at TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _persist_finding(self, finding: Dict[str, str]) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO findings (path, finding_type, keyword, evidence, severity, created_at)
                VALUES (:path, :type, :keyword, :evidence, :severity, :created_at)
                """,
                finding,
            )
            conn.commit()
        finally:
            conn.close()

    def _record(self, *, finding_type: str, path: Path, keyword: str, evidence: str, severity: str = "medium") -> None:
        entry = {
            "type": finding_type,
            "path": str(path),
            "keyword": keyword,
            "evidence": evidence[:500],  # limit to keep reports concise
            "severity": severity,
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        self.results.append(entry)
        self._persist_finding(entry)

    def _is_excluded_dir(self, path: Path) -> bool:
        return any(str(path).startswith(excluded) for excluded in self.excluded_dirs)

    def _iter_files(self) -> Iterable[Path]:
        for dirpath, dirnames, filenames in os.walk(self.root, topdown=True):
            if self._is_excluded_dir(Path(dirpath)):
                dirnames[:] = []
                continue

            # Remove excluded directories from traversal in-place
            dirnames[:] = [d for d in dirnames if not self._is_excluded_dir(Path(dirpath) / d)]

            for filename in filenames:
                yield Path(dirpath) / filename

    def _scan_text_file(self, path: Path) -> None:
        try:
            if not path.is_file():
                return

            if path.stat().st_size > self.max_file_size_bytes:
                return

            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
        except (OSError, UnicodeDecodeError):
            return

        for pattern in self._compiled_keywords:
            match = pattern.search(content)
            if match:
                start = max(match.start() - 40, 0)
                end = min(match.end() + 40, len(content))
                context = content[start:end].replace("\n", " ")
                self._record(
                    finding_type="file_content_match",
                    path=path,
                    keyword=pattern.pattern,
                    evidence=f"...{context}...",
                    severity=self._severity_from_keyword(pattern.pattern),
                )
                break

    def _severity_from_keyword(self, keyword: str) -> str:
        high_keywords = ["token", "password", "private key", "keychain", "encryption key"]
        return "high" if any(k in keyword.lower() for k in high_keywords) else "medium"

    def _scan_filename(self, path: Path) -> None:
        lowercase_name = path.name.lower()
        for name in self.suspicious_filenames:
            if lowercase_name == name:
                self._record(
                    finding_type="filename_match",
                    path=path,
                    keyword=name,
                    evidence="Suspicious filename discovered",
                    severity="high",
                )
                break

    def _scan_sqlite_db(self, path: Path) -> None:
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error:
            return

        try:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            for table in tables:
                self._scan_sqlite_table(conn, path, table)
        except sqlite3.Error:
            pass
        finally:
            conn.close()

    def _scan_sqlite_table(self, conn: sqlite3.Connection, db_path: Path, table: str) -> None:
        try:
            cursor = conn.execute(f"PRAGMA table_info('{table}')")
            columns = [row[1] for row in cursor.fetchall()]
        except sqlite3.Error:
            return

        for column in columns:
            for pattern in self._compiled_keywords:
                if pattern.search(column):
                    self._record(
                        finding_type="sqlite_schema_match",
                        path=db_path,
                        keyword=pattern.pattern,
                        evidence=f"Column '{column}' in table '{table}' matches pattern",
                        severity="high",
                    )
                    break

        try:
            preview_query = f"SELECT * FROM '{table}' LIMIT {self.max_rows_per_table}"
            cursor = conn.execute(preview_query)
            rows = cursor.fetchall()
        except sqlite3.Error:
            return

        for row in rows:
            for cell in row:
                if isinstance(cell, str):
                    for pattern in self._compiled_keywords:
                        if pattern.search(cell):
                            self._record(
                                finding_type="sqlite_value_match",
                                path=db_path,
                                keyword=pattern.pattern,
                                evidence=f"Table '{table}' contains value snippet: {cell[:120]}",
                                severity=self._severity_from_keyword(pattern.pattern),
                            )
                            return

    def _is_sqlite_candidate(self, path: Path) -> bool:
        return path.suffix.lower() in {".db", ".sqlite", ".sqlite3"} or path.name in self.suspicious_filenames

    def scan(self) -> None:
        print(f"[*] Starting credential and tracker artifact scan at {datetime.now()}")
        print("[*] Root scan scope:", self.root)
        print("[*] Results will be persisted to:", self.db_path)
        print("-" * 80)

        for path in self._iter_files():
            if not path.exists():
                continue

            self._scan_filename(path)

            if self._is_sqlite_candidate(path):
                self._scan_sqlite_db(path)
                continue

            self._scan_text_file(path)

    def write_json_report(self, report_path: str = "credential_artifact_report.json") -> None:
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump({"findings": self.results}, handle, indent=2)
        print(f"[+] JSON report written to {report_path}")

    def print_summary(self) -> None:
        print("\n" + "=" * 80)
        print("CREDENTIAL & TRACKER ARTIFACT SCAN REPORT")
        print("=" * 80)
        print(f"Total findings: {len(self.results)}")

        by_type: Dict[str, int] = {}
        for item in self.results:
            by_type[item["type"]] = by_type.get(item["type"], 0) + 1

        for finding_type, count in sorted(by_type.items()):
            print(f"  {finding_type}: {count}")

        print("\nNote: Detailed findings are stored in the SQLite database and JSON report.")


def main() -> None:
    scanner = CredentialArtifactScanner()
    scanner.scan()
    scanner.write_json_report()
    scanner.print_summary()


if __name__ == "__main__":
    main()
