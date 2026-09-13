# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-09-07

### Added

- **AI** — local Ollama tool-calling loop (`llama3.1` / `qwen2.5`) with
  `<EMAIL_DATA>` prompt-injection defense and deterministic offline fallback.
- **Cybersecurity** — 16 whitelisted tools:
  - header parsing + Gmail/webmail IP-hiding fallback (`resolve_origin`),
  - multi-source confidence-scored geolocation (`geolocate_ip`),
  - Tor exit-node detection (`check_tor_exit`),
  - URL/brand/typosquat analysis (`extract_urls`),
  - VirusTotal/AbuseIPDB reputation (`check_reputation`),
  - 7 sandboxed forensic binaries (binwalk, pdfid, capa, strings, yara,
    pecheck, + exiftool/oletools),
  - DNS + whois phishing-infrastructure tracing.
- **Blockchain** — tamper-evident hash-chain (default) and Ganache/Ethereum
  backends; logs only `{hash, verdict, confidence, timestamp, geo}`.
- **Safety** — tool whitelist, Docker sandbox (`--network none`, read-only),
  human confirmation gate, 15s tool timeouts, keypress kill-switch,
  hash-before-analysis.
- **Desktop pet** — static pixel-art guard with 10 live expressions, local-LLM
  chat, Mailpit inbox integration (self-hosted demo), screen-OCR + Gmail-OAuth
  stubs, and OS notifications.
- **Samples** — clean, phishing, BEC (Gmail webmail), and disguised-attachment
  `.eml` fixtures.
- **Tests** — 14-test offline suite covering all three pillars.
