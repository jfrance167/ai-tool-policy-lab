"""Validate hostile tool proposals against trusted application permissions.

This module is a policy boundary, not an operating-system sandbox. Trusted
application code supplies document contents and permissions at construction.
Every model-proposed action must enter through ToolBroker.execute.
"""

from collections.abc import Mapping
from dataclasses import dataclass
import json
import math
import operator
import re
from types import MappingProxyType

MAX_REQUEST_BYTES = 4096
MAX_DOCUMENT_BYTES = 4096
MAX_DOCUMENTS = 16
MAX_OPERAND = 1_000_000_000
MAX_RESULT = 1_000_000_000_000_000_000
DOCUMENT_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}", re.ASCII)
OPERATIONS = MappingProxyType({
    "add": operator.add,
    "subtract": operator.sub,
    "multiply": operator.mul,
    "divide": operator.truediv,
})
TOOL_NAMES = frozenset({"calculate", "read_document"})


class _Denied(ValueError):
    """Internal validation failure carrying a fixed, non-sensitive reason."""


@dataclass(frozen=True)
class Decision:
    """Tool result and a separate metadata-only event suitable for auditing.

    Results can contain permitted document text. Log audit_event(), not the
    entire decision, when handling sensitive data outside this synthetic lab.
    """

    allowed: bool
    tool: str | None
    reason: str
    result: str | int | float | None = None

    def audit_event(self) -> dict:
        """Return fixed outcome metadata without arguments or result contents."""
        return {"allowed": self.allowed, "tool": self.tool, "reason": self.reason}

    def to_dict(self) -> dict:
        """Serialize the response for its authorized caller, including result."""
        return {**self.audit_event(), "result": self.result}


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _Denied("duplicate_key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise _Denied("non_finite_number")


def _number(value: object) -> int | float:
    # bool is a subclass of int in Python, but not a numeric tool argument.
    if type(value) not in (int, float):
        raise _Denied("invalid_number")
    if type(value) is float and not math.isfinite(value):
        raise _Denied("non_finite_number")
    if abs(value) > MAX_OPERAND:
        raise _Denied("operand_limit")
    return value


@dataclass(frozen=True, init=False)
class ToolBroker:
    """A fixed tool registry with a copied, immutable document-ID policy.

    Args:
        documents: Trusted preloaded strings, at most 16 documents of 4096
            UTF-8 bytes each. IDs use lowercase ASCII letters/digits/_/-.
        allowed_document_ids: Explicit trusted read permissions. The default
            grants no document access. Model text cannot change these values.

    No tool accepts a path, opens a file, launches code, or accesses a network.
    Immutability prevents accidental changes, not hostile in-process Python.
    """

    _documents: Mapping[str, str]
    _allowed_document_ids: frozenset[str]

    def __init__(
        self,
        documents: Mapping[str, str],
        allowed_document_ids: frozenset[str] = frozenset(),
    ) -> None:
        if not isinstance(documents, Mapping) or len(documents) > MAX_DOCUMENTS:
            raise ValueError("invalid trusted document collection")
        snapshot = dict(documents)
        for document_id, content in snapshot.items():
            if type(document_id) is not str or not DOCUMENT_ID.fullmatch(document_id):
                raise ValueError("invalid trusted document ID")
            if type(content) is not str:
                raise ValueError("invalid trusted document content")
            try:
                size = len(content.encode("utf-8"))
            except UnicodeEncodeError as error:
                raise ValueError("invalid trusted document encoding") from error
            if size > MAX_DOCUMENT_BYTES:
                raise ValueError("trusted document exceeds size limit")
        if type(allowed_document_ids) is not frozenset:
            raise ValueError("permissions must be a frozenset of document IDs")
        if not allowed_document_ids.issubset(snapshot):
            raise ValueError("permission references an unknown document")
        object.__setattr__(self, "_documents", MappingProxyType(snapshot))
        object.__setattr__(self, "_allowed_document_ids", allowed_document_ids)

    def execute(self, raw_request: str | bytes) -> Decision:
        """Deny invalid requests before execution; return fixed reason codes.

        Accept exactly one UTF-8 JSON object with tool and arguments keys.
        Duplicate keys, extra fields, invalid types and oversized input fail
        closed. Unknown tool names are never echoed into the audit event.
        """
        tool = None
        try:
            if type(raw_request) not in (str, bytes):
                raise _Denied("invalid_request_type")
            if len(raw_request) > MAX_REQUEST_BYTES:
                raise _Denied("request_limit")
            if type(raw_request) is str:
                raw_request = raw_request.encode("utf-8")
            if len(raw_request) > MAX_REQUEST_BYTES:
                raise _Denied("request_limit")
            request = json.loads(
                raw_request.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
            if type(request) is not dict or set(request) != {"tool", "arguments"}:
                raise _Denied("invalid_request_schema")
            candidate = request["tool"]
            if type(candidate) is not str or candidate not in TOOL_NAMES:
                raise _Denied("unknown_tool")
            tool = candidate
            arguments = request["arguments"]
            if type(arguments) is not dict:
                raise _Denied("invalid_arguments")
            if tool == "calculate":
                result = self._calculate(arguments)
            else:
                result = self._read_document(arguments)
            return Decision(True, tool, "allowed", result)
        except _Denied as error:
            return Decision(False, tool, str(error))
        except (ValueError, UnicodeError, RecursionError):
            return Decision(False, tool, "invalid_json")

    @staticmethod
    def _calculate(arguments: dict) -> int | float:
        if set(arguments) != {"operation", "a", "b"}:
            raise _Denied("invalid_arguments")
        operation = arguments["operation"]
        if type(operation) is not str or operation not in OPERATIONS:
            raise _Denied("unknown_operation")
        a, b = _number(arguments["a"]), _number(arguments["b"])
        if operation == "divide" and b == 0:
            raise _Denied("division_by_zero")
        result = OPERATIONS[operation](a, b)
        if not math.isfinite(result) or abs(result) > MAX_RESULT:
            raise _Denied("result_limit")
        return result

    def _read_document(self, arguments: dict) -> str:
        if set(arguments) != {"document_id"}:
            raise _Denied("invalid_arguments")
        document_id = arguments["document_id"]
        if type(document_id) is not str or not DOCUMENT_ID.fullmatch(document_id):
            raise _Denied("invalid_document_id")
        # Use the same denial for absent and disallowed IDs to avoid revealing
        # the private document inventory. There is deliberately no path lookup.
        if document_id not in self._allowed_document_ids:
            raise _Denied("document_denied")
        return self._documents[document_id]
