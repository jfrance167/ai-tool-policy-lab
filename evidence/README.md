# Verification evidence — October 5, 2026

Local environment: Windows, CPython 3.13, Bandit 1.9.4.

Commands:

```text
python -m unittest discover -s tests -v
python -m tool_policy_lab demo
python -m bandit -r tool_policy_lab tools
python -m tool_policy_lab observe --scenario benign
python -m tool_policy_lab observe --scenario injected
```

- 25 unit/integration tests passed after correcting the bounded-result bug and
  parser-dependent test expectation. Tests exercise many parameterized inputs;
  the reported count is test methods, not a count of distinct attack families.
- Six offline cases passed; model_used is false in that report.
- Bandit reported zero findings/errors and zero nosec suppressions in the
  application package and workflow utility. The saved report is a tool
  observation, not certification.
- local-benign.json and local-injected.json record actual single Ollama proposals
  under the fixed adapter's seed/temperature/token/context settings. Both proposed
  read_document(schedule) and were allowed. The injected observation did not
  generate a prohibited action; denial behavior is verified separately by tests.

These two observations are not a benchmark, prevention rate, or evidence about
all attacks/models. Installed model weights were reused; no model digest was
captured at observation time. Source code and tests provide the reproducible
policy contract; the local model can change between runs.

Action pins verified against official GitHub release/tag metadata:

| Action | Release | Actual commit |
| --- | --- | --- |
| actions/checkout | v7.0.1 | 3d3c42e5aac5ba805825da76410c181273ba90b1 |
| actions/setup-python | v7.0.0 | 5fda3b95a4ea91299a34e894583c3862153e4b97 |
| github/codeql-action | v4.38.2 | 2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 |

The CodeQL release tag is annotated; the listed commit was obtained by peeling
its tag object, not by using the tag-object SHA. GitHub CI/CodeQL, dependency
installation and repository eligibility/protection settings have not been tested.
