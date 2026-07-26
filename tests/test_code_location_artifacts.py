from __future__ import annotations

import copy
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import fix_code_locations as fixer  # noqa: E402
import verify_code_location_outputs as verifier  # noqa: E402


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return b"ok"


class CodeLocationArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = verifier.load_jsonl(verifier.BASELINE_JSONL)
        cls.fixed = verifier.load_jsonl(verifier.FIXED_JSONL)
        cls.diff = verifier.load_csv(verifier.DIFF_CSV)
        cls.human = verifier.load_csv(verifier.NEEDS_HUMAN_CSV)

    def test_manifest_matches_all_committed_artifacts(self) -> None:
        verifier.check_manifest(self.baseline, self.fixed, self.diff, self.human)

    def test_only_recorded_location_fields_change(self) -> None:
        verifier.check_fixed_matches_diff(self.baseline, self.fixed, self.diff)
        baseline_by_id = {row["entry_id"]: row for row in self.baseline}
        fixed_by_id = {row["entry_id"]: row for row in self.fixed}
        verifier.check_needs_human_unchanged(
            baseline_by_id, fixed_by_id, self.human
        )

    @mock.patch.object(verifier, "fetch_bytes")
    def test_source_check_accepts_normalized_multiline_match(
        self, fetch_bytes: mock.Mock
    ) -> None:
        fetch_bytes.return_value = b"before\nreturn   value;\nafter();\nend\n"
        node = {
            "file": "src/example.py",
            "line": 2,
            "code": "return value;\nafter();",
            "desc": "returns the propagated value",
        }
        fixed_by_id = {
            "entry-test": {
                "entry_id": "entry-test",
                "entry_point": node,
                "critical_operation": copy.deepcopy(node),
                "trace": [],
            }
        }
        diff = [
            {
                "entry_id": "entry-test",
                "field_path": "entry_point",
                "repo_url": "https://github.com/owner/repo",
                "commit": "a" * 40,
                "new_file": "src/example.py",
            }
        ]
        self.assertEqual(verifier.check_upstream_sources(fixed_by_id, diff), 1)

    @mock.patch.object(verifier.time, "sleep")
    @mock.patch.object(verifier.urllib.request, "urlopen")
    def test_fetch_retries_transient_network_error(
        self, urlopen: mock.Mock, sleep: mock.Mock
    ) -> None:
        urlopen.side_effect = [urllib.error.URLError("temporary"), FakeResponse()]
        self.assertEqual(verifier.fetch_bytes("https://example.invalid", attempts=2), b"ok")
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(1)


if __name__ == "__main__":
    unittest.main()
