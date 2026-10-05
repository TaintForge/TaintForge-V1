#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parents[1]
TRIAGE = HERE / "postgresql-afl-triage.sh"


class PostgreSQLAFLTriagerTests(unittest.TestCase):
    def test_bounded_capture_drains_but_retains_only_the_prefix(self) -> None:
        payload = bytes(range(256)) * 8192
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "stdout.txt"
            env = os.environ.copy()
            env["DBFUZZ_TRIAGE_STDOUT_LIMIT"] = "1024"
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; capture_bounded_stdout "$2"',
                    "bash",
                    str(TRIAGE),
                    str(output),
                ],
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=env,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(output.read_bytes(), payload[:1024])


if __name__ == "__main__":
    unittest.main()
