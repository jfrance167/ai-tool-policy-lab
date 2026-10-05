# Security model and reporting

This is an educational policy broker, not an OS sandbox or a production security
product. No universal prompt-injection prevention claim is made.

## Trust boundaries

Attacker-controlled data: retrieved document text and every byte of a proposed
JSON tool call. Trusted data: application source, tool registry, document map,
permission allowlist, Python runtime and local Ollama process when used.
Unknown tool names and ambiguous/malformed arguments fail closed.

| Threat | Control | Remaining limit |
| --- | --- | --- |
| Document claims new authority | Permissions defined outside model context | Model text can still be manipulated |
| Restricted document access | Explicit document-ID allowlist | Permitted document contents can be disclosed to their caller |
| Path traversal, junction or link escape | Tools use preloaded strings, never filesystem paths | Loading real documents requires separate trusted ingestion design |
| Shell/code execution or network exfiltration | No such registered tool | Cannot constrain separate application code that bypasses this broker |
| Schema ambiguity | Exact fields/types, duplicate-key rejection | Caller must mediate every action through execute |
| Resource abuse | Bounded requests/documents/numbers/model responses | Not a multi-user service; no rate limits or OS resource isolation |
| Sensitive audit/log injection | Fixed reason codes and recognized tool names only | Complete CLI responses contain results and are not metadata-only logs |

The optional model adapter connects only to fixed loopback Ollama, without
proxies/redirects. Loopback is not authentication against another local process.
It is not a TLS-protected remote inference channel. Do not expose this adapter
or Ollama to a network as part of this lab.

Out of scope: hostile host administrators, compromised dependencies/runtime,
arbitrary Python inside this process, semantic correctness of model responses,
tool result sanitization for downstream browser rendering, persistent memory,
real secrets, autonomous agents, multi-user authorization and real filesystem
confinement. Any future tool needs its own capability and parameter review.

## Manual review before merge or deployment

Review broker JSON validation, default-deny permissions, complete mediation and
metadata-only audit handling. Adding arbitrary execution, real file access,
plugins, writes or outbound network tools materially changes this threat model.
This local version has no confirmed unresolved policy bypass after its recorded
tests and source review; that is not a certification.

## Reporting

Use a private security advisory/contact channel when one is configured for the
published repository. No remote reporting channel exists for this local-only
project yet. Do not put credentials, real private documents or nonpublic exploit
evidence in public issues. Provide a minimal synthetic request and observed
decision when reporting policy behavior to the owner.
