# Security Policy

Sentinel is a **security tool**, so security matters doubly here. Please read
this before reporting a vulnerability.

## Supported versions

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| tagged releases | ✅ |

## Reporting a vulnerability

**Do NOT open a public issue** for a security vulnerability. Instead, report it
privately via GitHub's **Security → Report a vulnerability** feature (the
"Private vulnerability reporting" button on the repository), or contact the
maintainers directly.

Please include:
1. A clear description of the vulnerability and its impact.
2. Steps to reproduce (a minimal `.eml` or command sequence, if possible).
3. Affected component(s) — e.g. `sentinel/tools/*`, `sentinel/sandbox.py`,
   `overlay/sentinel_pet.py`, `sentinel/blockchain/*`.

We will acknowledge within 48 hours and aim to triage within 7 days.

## What is in scope

- Prompt-injection / sandbox-escape in the agent or tool layer.
- Any path that would let an untrusted `.eml`/attachment execute code on the
  host (outside the Docker sandbox).
- Any way the blockchain ledger could be tampered with undetectably.
- Data exfiltration: email content leaking to the network when it should stay
  local.

## What is out of scope

- Issues in third-party tools (Ollama, Mailpit, VirusTotal, exiftool, ...) —
  report those upstream.
- Self-inflicted misconfiguration (e.g. running the agent with
  `SANDBOX_ENABLED=0` and expecting isolation).

## Security model (design commitments)

1. **Tool whitelist** — the LLM only *names* tools; `sentinel/tools/registry.py`
   is the only name→function mapping. No `eval`/`exec`/shell.
2. **Sandbox** — file-touching tools run in a one-shot container
   (`--network none`, `--read-only`, `--cap-drop ALL`, non-root, destroyed per run).
3. **Static-only** — attachments are never executed, only parsed.
4. **Prompt isolation** — email content is wrapped in `<EMAIL_DATA>` tags and
   the system prompt forbids obeying instructions found inside them.
5. **Immutable evidence** — SHA-256 before analysis; hash-linked ledger with
   `--verify-chain`.
