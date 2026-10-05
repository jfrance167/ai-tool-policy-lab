"""Behavior and adversarial boundary tests using only synthetic inputs."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

from tool_policy_lab import ToolBroker
from tool_policy_lab.broker import MAX_REQUEST_BYTES
from tool_policy_lab.demo import run_demo


class BrokerTests(TestCase):
    def setUp(self):
        self.broker = ToolBroker({"public": "Synthetic public text", "private": "SENTINEL"},
                                 frozenset({"public"}))

    def call(self, tool, arguments):
        return self.broker.execute(json.dumps({"tool": tool, "arguments": arguments}))

    def assertDenied(self, raw, reason=None):
        decision = self.broker.execute(raw)
        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.result)
        if reason:
            self.assertEqual(reason, decision.reason)
        return decision

    def test_arithmetic(self):
        for operation, expected in [("add", 12), ("subtract", 2), ("multiply", 35), ("divide", 1.4)]:
            with self.subTest(operation=operation):
                result = self.call("calculate", {"operation": operation, "a": 7, "b": 5})
                self.assertTrue(result.allowed)
                self.assertEqual(result.result, expected)

    def test_numeric_edges(self):
        for value, reason in [(True, "invalid_number"), (False, "invalid_number"),
                              (None, "invalid_number"), ("1", "invalid_number"),
                              ([], "invalid_number"), ({}, "invalid_number"),
                              (1_000_000_001, "operand_limit"), (-1_000_000_001, "operand_limit")]:
            with self.subTest(value=value):
                decision = self.call("calculate", {"operation": "add", "a": value, "b": 0})
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, reason)
        self.assertEqual(self.call("calculate", {"operation": "multiply", "a": 1e9, "b": 1e9}).result, 1e18)
        self.assertEqual(self.call("calculate", {"operation": "add", "a": -0.5, "b": 0.5}).result, 0)

    def test_division_by_zero_and_tiny_divisor(self):
        for divisor in (0, -0.0):
            self.assertEqual(self.call("calculate", {"operation": "divide", "a": 1, "b": divisor}).reason,
                             "division_by_zero")
        # Arithmetic may overflow with subnormal divisors despite bounded operands.
        decision = self.call("calculate", {"operation": "divide", "a": 1e9, "b": 5e-324})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "result_limit")
        self.assertEqual(self.call("calculate", {"operation": "divide", "a": 1, "b": 1e-30}).reason,
                         "result_limit")

    def test_nonfinite_json(self):
        for value in ("NaN", "Infinity", "-Infinity", "1e999"):
            with self.subTest(value=value):
                self.assertDenied('{"tool":"calculate","arguments":{"operation":"add","a":' + value + ',"b":1}}',
                                  "non_finite_number")

    def test_no_arbitrary_operations(self):
        for operation in ("eval", "pow", "__import__", "ADD", None, [], {}):
            with self.subTest(operation=operation):
                self.assertFalse(self.call("calculate", {"operation": operation, "a": 1, "b": 2}).allowed)

    def test_document_permissions_and_no_inventory_disclosure(self):
        self.assertEqual(self.call("read_document", {"document_id": "public"}).result, "Synthetic public text")
        for document_id in ("private", "absent"):
            self.assertEqual(self.call("read_document", {"document_id": document_id}).reason, "document_denied")
        self.assertFalse(ToolBroker({"public": "text"}).execute(
            '{"tool":"read_document","arguments":{"document_id":"public"}}').allowed)

    def test_paths_and_disguised_ids_never_open_files(self):
        paths = ["../public", "..\\public", "/etc/passwd", "C:\\Windows\\win.ini",
                 "\\\\server\\share", "public:stream", "%2e%2e%2fpublic", "public\x00", "PUBLIC", "рublic", "public\n"]
        with patch("builtins.open", side_effect=AssertionError("file access")), \
             patch.object(Path, "open", side_effect=AssertionError("path access")):
            for document_id in paths:
                with self.subTest(document_id=document_id):
                    self.assertEqual(self.call("read_document", {"document_id": document_id}).reason,
                                     "invalid_document_id")
            self.assertTrue(self.call("read_document", {"document_id": "public"}).allowed)

    def test_exact_schema(self):
        requests = [[], None, 1, "text", {}, {"tool": "calculate"},
                    {"tool": "read_document", "arguments": {}, "approved": True},
                    {"tool": "read_document", "arguments": []},
                    {"tool": "read_document", "arguments": {"document_id": "public", "authorized": True}},
                    {"tool": "calculate", "arguments": {"operation": "add", "a": 1}},
                    {"tool": "calculate", "arguments": {"operation": "add", "a": 1, "b": 2, "code": "ignored"}}]
        for request in requests:
            with self.subTest(request=request):
                self.assertDenied(json.dumps(request))

    def test_unknown_tools_are_not_echoed(self):
        for tool in ("shell", "write_file", "network", "change_policy", "calculate\nSENTINEL", [], {}, 1):
            decision = self.call(tool, {})
            self.assertFalse(decision.allowed)
            self.assertIsNone(decision.tool)
            self.assertNotIn("SENTINEL", json.dumps(decision.audit_event()))

    def test_duplicate_keys_including_escaped_and_nested(self):
        for request in ('{"tool":"shell","tool":"calculate","arguments":{}}',
                        '{"tool":"read_document","arguments":{"document_id":"public","document_id":"private"}}',
                        '{"tool":"calculate","arguments":{"a":1,"\\u0061":2}}'):
            self.assertDenied(request, "duplicate_key")

    def test_invalid_json_and_encoding(self):
        for raw in ("", "{", "{} {}", "/*comment*/{}", b"\xff", "\ud800"):
            with self.subTest(raw=repr(raw[:20])):
                self.assertDenied(raw, "invalid_json")
        # Parser recursion limits vary by Python version; either a parse denial
        # or a schema denial is safe. Deep lists must never reach a tool.
        self.assertDenied("[" * 1500 + "]" * 1500)
        for raw in (None, {}, bytearray(b"{}")):
            self.assertDenied(raw, "invalid_request_type")

    def test_request_byte_limits(self):
        self.assertDenied(b" " * (MAX_REQUEST_BYTES + 1), "request_limit")
        self.assertDenied("é" * (MAX_REQUEST_BYTES // 2 + 1), "request_limit")
        raw = '{"tool":"read_document","arguments":{"document_id":"public"}}'
        self.assertTrue(self.broker.execute(raw + " " * (MAX_REQUEST_BYTES - len(raw))).allowed)
        self.assertDenied(raw + " " * (MAX_REQUEST_BYTES - len(raw) + 1), "request_limit")

    def test_trusted_policy_is_copied_and_immutable(self):
        documents = {"public": "original"}
        broker = ToolBroker(documents, frozenset({"public"}))
        documents["public"] = "changed"
        self.assertEqual(broker.execute('{"tool":"read_document","arguments":{"document_id":"public"}}').result,
                         "original")
        with self.assertRaises(TypeError):
            broker._documents["public"] = "changed"
        with self.assertRaises(FrozenInstanceError):
            broker._allowed_document_ids = frozenset({"private"})

    def test_invalid_trusted_configuration(self):
        for documents, permissions in [({"../bad": "text"}, frozenset()), ({"ok": 3}, frozenset()),
                                        ({"ok": "\ud800"}, frozenset()), ({"ok": "x" * 4097}, frozenset()),
                                        ({"ok": "text"}, {"ok"}), ({}, frozenset({"missing"})),
                                        ({f"d{i}": "text" for i in range(17)}, frozenset()), ([], frozenset())]:
            with self.subTest(documents=type(documents).__name__):
                with self.assertRaises(ValueError):
                    ToolBroker(documents, permissions)

    def test_audit_contains_no_arguments_or_document_contents(self):
        for document_id in ("public", "private", "absent"):
            event = self.call("read_document", {"document_id": document_id}).audit_event()
            self.assertEqual(set(event), {"allowed", "tool", "reason"})
            self.assertNotIn("SENTINEL", json.dumps(event))
            self.assertNotIn("Synthetic public text", json.dumps(event))

    def test_demo_is_reproducible_and_labels_fixture_calls(self):
        report = run_demo()
        self.assertTrue(report["passed"])
        self.assertFalse(report["model_used"])
        self.assertEqual(len(report["cases"]), 6)
        self.assertEqual(report, run_demo())


if __name__ == "__main__":
    main()
