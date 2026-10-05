#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parents[1]
CAMPAIGN = HERE / "postgresql-afl-campaign.sh"


class PostgreSQLAFLCampaignTests(unittest.TestCase):
    def test_worker_liveness_uses_fresh_stats_across_pid_namespaces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fast = root / "fast"
            stateful = root / "stateful"
            (fast / "live").mkdir(parents=True)
            (stateful / "stale").mkdir(parents=True)
            (stateful / "future").mkdir(parents=True)
            (fast / "live" / "fuzzer_stats").write_text(
                "last_update : 950\n", encoding="utf-8"
            )
            (stateful / "stale" / "fuzzer_stats").write_text(
                "last_update : 800\n", encoding="utf-8"
            )
            (stateful / "future" / "fuzzer_stats").write_text(
                "last_update : 1001\n", encoding="utf-8"
            )
            env = os.environ.copy()
            env["DBFUZZ_STATUS_NOW"] = "1000"
            env["DBFUZZ_AFL_HEARTBEAT_SECONDS"] = "120"
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; count_fresh_workers "$2" "$3"',
                    "bash",
                    str(CAMPAIGN),
                    str(fast),
                    str(stateful),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=env,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "1\n")


if __name__ == "__main__":
    unittest.main()
