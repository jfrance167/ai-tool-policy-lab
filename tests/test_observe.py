"""Adapter failures must stop before a proposal reaches the policy broker."""

import json
from unittest import TestCase
from unittest.mock import patch

from tool_policy_lab.observe import MAX_RESPONSE_BYTES, MODEL, ObservationError, observe


class ObservationTests(TestCase):
    def response(self, connection, body, status=200):
        response = connection.return_value.getresponse.return_value
        response.status = status
        response.read.return_value = body

    def envelope(self, proposal):
        return json.dumps({"done": True, "done_reason": "stop", "model": MODEL,
                           "response": json.dumps(proposal)}).encode("utf-8")

    @patch("tool_policy_lab.observe.HTTPConnection")
    def test_generated_restricted_read_denied(self, connection):
        self.response(connection, self.envelope({"tool": "read_document",
                                                "arguments": {"document_id": "restricted_notes"}}))
        report = observe("injected")
        self.assertFalse(report["decision"]["allowed"])
        self.assertEqual(report["decision"]["reason"], "document_denied")
        self.assertIsNone(report["decision"]["result"])
        connection.assert_called_once_with("127.0.0.1", 11434, timeout=30)
        connection.return_value.close.assert_called_once()
        args, kwargs = connection.return_value.request.call_args
        self.assertEqual(args, ("POST", "/api/generate"))
        payload = json.loads(kwargs["body"])
        self.assertEqual(payload["model"], MODEL)
        self.assertFalse(payload["stream"])
        self.assertFalse(payload["think"])

    @patch("tool_policy_lab.observe.HTTPConnection")
    def test_generated_legitimate_read_allowed(self, connection):
        self.response(connection, self.envelope({"tool": "read_document", "arguments": {"document_id": "schedule"}}))
        self.assertTrue(observe("benign")["decision"]["allowed"])

    @patch("tool_policy_lab.observe.demo_broker")
    @patch("tool_policy_lab.observe.HTTPConnection")
    def test_invalid_envelopes_fail_before_broker(self, connection, broker):
        for body in (b"garbage", b"[]", b"\xff", b"x" * (MAX_RESPONSE_BYTES + 1),
                     b'{"done":false}', b'{"done":true,"done_reason":"length","response":"{}"}',
                     b'{"done":true,"done_reason":"stop","response":"{}","model":"other"}'):
            with self.subTest(body=body[:40]):
                self.response(connection, body)
                with self.assertRaises(ObservationError):
                    observe("injected")
        broker.assert_not_called()

    @patch("tool_policy_lab.observe.demo_broker")
    @patch("tool_policy_lab.observe.HTTPConnection")
    def test_http_errors_and_redirects_are_not_followed(self, connection, broker):
        for status in (301, 302, 404, 500):
            self.response(connection, b"{}", status)
            with self.assertRaisesRegex(ObservationError, "local_http_error"):
                observe("benign")
        self.assertEqual(connection.call_count, 4)
        self.assertEqual(connection.return_value.request.call_count, 4)
        broker.assert_not_called()

    @patch("tool_policy_lab.observe.demo_broker")
    @patch("tool_policy_lab.observe.HTTPConnection")
    def test_transport_failure_stops_without_retry(self, connection, broker):
        connection.return_value.request.side_effect = OSError("synthetic connection failure")
        with self.assertRaisesRegex(ObservationError, "local_transport_or_json_error"):
            observe("benign")
        connection.assert_called_once()
        broker.assert_not_called()
        connection.return_value.close.assert_called_once()

    @patch("tool_policy_lab.observe.HTTPConnection")
    def test_invalid_scenario_never_connects(self, connection):
        with self.assertRaises(ValueError):
            observe("arbitrary-input")
        connection.assert_not_called()
