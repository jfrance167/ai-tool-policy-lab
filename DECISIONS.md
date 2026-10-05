# Decisions

2026-10-05:

- Build a small original standard-library broker. NeMo Guardrails offers broader
  orchestration but is disproportionate for two fixed educational tools.
- Use preloaded synthetic document IDs. This removes filesystem path/link/race
  behavior from tool execution; it sacrifices real file access in version one.
- Keep the registry fixed and permissions copied/immutable. Model input cannot
  register a tool, change policy, or request an import/callback.
- Test prohibited calls independently of model behavior. Offline proposals prove
  specific policy decisions; local model observations measure only those calls.
- Log metadata separately from responses. Authorized document output is useful
  to the caller but inappropriate for a sensitive audit log.
- Bound operands and results: a tiny divisor revealed that finite, bounded
  operands alone do not ensure finite, bounded results.
- Prepare SHA-pinned GitHub workflows locally. Publication and remote eligibility
  checks remain separate. Scanner dependencies have exact version pins but no
  verified artifact hashes after repeated official PyPI transport failures.
