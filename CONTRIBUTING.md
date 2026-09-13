# Contributing to Sentinel

Thanks for your interest! Sentinel is a local-first AI cybersecurity agent.
This guide covers how to contribute effectively.

## Ways to help

- **Code** — new tools, sandbox improvements, blockchain backends, pet features.
- **Threat intelligence** — YARA rules (`sandbox/yara_rules/`), phishing
  heuristics, brand-domain mappings (`sentinel/tools/extract_urls.py`).
- **Docs** — clearer setup steps, architecture notes, translations.
- **Bug reports** — especially around safety/isolation boundaries.

## Getting started

```bash
git clone https://github.com/17krishna8/project.git
cd project
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest                 # 14 tests, run offline
```

## Adding a new tool

1. Implement the function in `sentinel/tools/`.
2. Register it in `sentinel/tools/registry.py` with a clear description +
   schema. Mark `requires_confirmation=True` + `file_touching=True` if it
   touches file bytes.
3. If it touches files, route it through `sentinel/sandbox.py` (Docker) and
   add the binary to `sandbox/Dockerfile` + a handler in
   `overlay/forensic_tool.py`.
4. Add a test in `tests/`.

## Code style

- Python 3.10+; keep the runtime dependency footprint small (stdlib +
  `rich` + `requests`).
- Inline comments must explain **safety** decisions, not just logic.
- Never weaken the sandbox, whitelist, or confirmation gate.

## Commit conventions

Use conventional, lowercase summary lines (e.g. `feat: add yara_scan tool`).

## Pull requests

- Open from a feature branch; target `main`.
- Ensure `python -m pytest` passes.
- Link any related issue.

## Code of Conduct

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).
