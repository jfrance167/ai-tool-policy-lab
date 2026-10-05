"""Run the offline policy demonstration or process one bounded stdin request."""

import argparse
import json
import sys

from .broker import MAX_REQUEST_BYTES
from .demo import demo_broker, run_demo
from .observe import ObservationError, observe


def main() -> int:
    parser = argparse.ArgumentParser(description="Educational AI tool policy broker")
    parser.add_argument("command", choices=("demo", "call", "observe"))
    parser.add_argument("--scenario", choices=("benign", "injected"), default="injected",
                        help="synthetic input for the optional local-model observation")
    args = parser.parse_args()
    if args.command == "demo":
        report = run_demo()
        print(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False))
        return 0 if report["passed"] else 1
    if args.command == "observe":
        try:
            report = observe(args.scenario)
        except ObservationError as error:
            print(json.dumps({"error": str(error), "tool_called": False}), file=sys.stderr)
            return 3
        print(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False))
        return 0
    decision = demo_broker().execute(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))
    print(json.dumps({"decision": decision.to_dict(), "audit": decision.audit_event()},
                     ensure_ascii=True, allow_nan=False))
    return 0 if decision.allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
