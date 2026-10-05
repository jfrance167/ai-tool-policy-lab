# Learning

The model's willingness to obey an injected document and the application's
authority to run a tool are separate questions. A model may propose a restricted
read; trusted code must still deny it. Neither a stronger prompt nor a second
guardrail model is a substitute for enforcing capabilities.

Useful edge cases encountered:

- Python booleans are integers by inheritance; numeric arguments need exact type
  checks when the schema rejects booleans.
- JSON parsers may accept duplicate keys and nonstandard NaN/Infinity values.
  Reject these instead of accepting whichever key/value wins.
- Even bounded finite inputs can yield infinity after division by a tiny number.
  Validate arithmetic results too.
- Deep JSON can fail during parsing or after parsing because the top-level shape
  is wrong. Tests should require denial without depending on version-specific
  parser recursion behavior.
- A GitHub release can point to an annotated tag object. Peel it to the actual
  commit before claiming an immutable action commit pin.

Optional exercise: distinguish the trusted allowlist from the untrusted
`authorized` field in the offline demo. Why does one grant permission while the
other is rejected?
