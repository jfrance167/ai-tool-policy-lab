# Approved implementation scope

Jake approved beginning on October 5, 2026 after research and a presented plan.
Tier 3: security functionality and portfolio learning.

Success: allowed demo requests work; restricted/unknown/malformed proposals are
denied by trusted application policy, independently of model compliance.

Stages:

1. Fixed calculator and synthetic document reader with strict bounded JSON.
2. Offline adversarial demo/tests, then optional installed loopback model check.
3. README, threat model, license, learning/state/decision records, security review
   and local preparations for the owned-repository security baseline.

Architecture: model proposes action -> broker validates trusted policy -> fixed
tool executes -> bounded caller response and separate audit metadata.
No arbitrary code, shell, writes, outbound network tools or real secrets.
Optional loopback model transport is separate from model-callable tools.

Main risks: incomplete mediation, permissive future tools, sensitive logs and
overclaiming model safety. Tests focus on denied requests, parser ambiguity,
resource bounds and authorized functionality. Manual review precedes any merge
or deployment. No publication, visibility change, merge or deployment is approved.

Alternatives: NeMo Guardrails for future broader integration; RestrictedPython
does not supply the required OS isolation boundary. Build the bounded broker
with standard-library primitives and reuse existing lab reporting concepts.
Primary research links are in README; no third-party source is copied.
