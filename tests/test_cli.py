"""Verify public CLI output, exit status and bounded stdin handling."""

import json
from pathlib import Path
import subprocess
import sys
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]


class CliTests(TestCase):
    def run_cli(self, command, data=b""):
        return subprocess.run([sys.executable, "-m", "tool_policy_lab", command],
                              input=data, capture_output=True, cwd=ROOT, timeout=10, check=False)

    def test_demo(self):
        result = self.run_cli("demo")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)["passed"])

    def test_call_allowed_and_denied(self):
        allowed = self.run_cli("call", b'{"tool":"calculate","arguments":{"operation":"add","a":2,"b":3}}')
        self.assertEqual(allowed.returncode, 0)
        self.assertEqual(json.loads(allowed.stdout)["decision"]["result"], 5)
        denied = self.run_cli("call", b'{"tool":"shell","arguments":{}}')
        self.assertEqual(denied.returncode, 2)
        self.assertEqual(json.loads(denied.stdout)["audit"]["reason"], "unknown_tool")

    def test_stdin_limit(self):
        result = self.run_cli("call", b"x" * 5000)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["audit"]["reason"], "request_limit")
