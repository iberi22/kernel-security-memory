#!/usr/bin/env python3
"""The NVD call cap is per run: a large persisted lifetime total must not stop a fetch."""

import importlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/studies"))

PROJECTS = ["curl", "git", "glibc", "nginx", "openssh", "openssl",
            "postgresql", "qemu", "sqlite", "systemd", "unbound"]


class TestFetcherRunCap(unittest.TestCase):
    def test_lifetime_total_at_cap_still_fetches(self):
        for project in PROJECTS:
            with self.subTest(project=project):
                module = importlib.import_module(f"fetch_history_{project}")
                calls = []

                def fake_request(url, cumulative_bytes, *args, **kwargs):
                    calls.append(url)
                    return {"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 0}

                with tempfile.TemporaryDirectory() as tmp:
                    (Path(tmp) / "index.json").write_text(json.dumps({
                        "project": project, "coverage": "INCOMPLETE", "requests": 400,
                        "resume": {"next_start_date": "2026-09-01"}, "errors": [],
                    }))
                    (Path(tmp) / "catalog.jsonl").write_text("")
                    with mock.patch.object(module, "make_nvd_request", side_effect=fake_request), \
                         mock.patch.object(module.time, "sleep"), \
                         redirect_stdout(io.StringIO()):
                        module.fetch_nvd_data(tmp, max_time_seconds=60)
                    index = json.loads((Path(tmp) / "index.json").read_text())

                self.assertGreater(len(calls), 0, f"{project} made no call with lifetime total at the cap")
                self.assertEqual(index["requests"], 400 + len(calls))


if __name__ == "__main__":
    unittest.main()
