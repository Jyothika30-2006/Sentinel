# Mail Watcher — automatic activation on mail events

Sentinel runs when *real mail events* happen — never on a timer, never by
sweeping an inbox. Two activation models share one trigger core
(`sentinel/watcher.py`):

## 1. Open-activation (default)

The agent activates **exactly when the user opens a mail**:

| Tier | Source | Detects | Message source | Pipeline |
|---|---|---|---|---|
| 1 | `extension` (Chrome/Edge MV3, tokenless) | conversation-open in Gmail | full RFC822 via Gmail's *Show original* fetch | full forensics |
| 3 | `title` (Windows title watcher) | foreground tab becomes `«Subject» - … - Gmail` | none — surface only | **confidence capped at 60%** |

## 2. Arrival auto-triage (opt-in)

Every **incoming** message is analyzed automatically as it lands:

| Source | How | Message source | Pipeline |
|---|---|---|---|
| `mailpit` | `sentinel/arrival_watch.py` polls Mailpit's REST API (~3s) and diffs new content-hash IDs | full raw via `/raw` endpoint | deterministic triage (no LLM quota) |
| `extension-arrival` | `extension/content.js` watches Gmail's inbox list rows for new thread IDs and posts them (raw fetched without opening the thread) | full RFC822 | full forensics |

Opt in/out: pet right-click menu **"📥 Arrival Watch: ON/OFF"** (or
`arrival_watch_enabled` in `sentinel_settings.json`; requires a guard
restart after toggling). The Mailpit watcher needs Mailpit running on
`localhost:8025` (SMTP capture on `1025`) — e.g.
`tools/mailpit/mailpit.exe`, or `docker run -p 8025:8025 -p 1025:1025 axllent/mailpit`.

Arrival and open share the same TTL dedupe: a mail that is auto-triaged on
arrival shows its cached verdict instantly if opened later. Arrivals run
the deterministic pipeline; deep LLM analysis stays available through the
dashboard/CLI.

---

## The two tiers

| | Tier 1 — Browser extension | Tier 3 — Title watcher |
|---|---|---|
| Lives in | `extension/` (Chrome/Edge MV3) | `sentinel/title_watch.py` |
| Open signal | conversation-open URL/DOM event (`#<label>/<threadId>`) | foreground tab title becomes `«Subject» - … - Gmail` |
| Message source | full RFC822 via Gmail's *Show original* fetch (session cookies) | none — surface only (optional OCR of the visible pane) |
| Pipeline | full forensics (headers, SPF/DKIM, origin IP, geo, URLs, sandboxed attachments) | surface analysis: URLs/content heuristics on what's visible; **confidence capped at 60%** |
| Sees opens from | that browser, that machine | any app whose foreground title matches, that machine |
| Fragility | Gmail DOM/internal endpoint can change | localized Gmail UI titles can be misread |

The honesty contract: a tier that cannot read the raw message *says so*.
Surface-only results carry `"surface_only": true`, a `[surface analysis]`
note in the summary, and never claim high confidence — the same rule
`resolve_origin.py` applies when Gmail hides the sender IP.

## Architecture

```
you open a mail
   │
   ├─ Tier 1: extension content script ──► background service worker ──► POST /api/watch/open
   │          (fetch original .eml)                (CORS-exempt fetch)
   │
   └─ Tier 3: Win32TitleWatcher (2 s foreground-title poll) ─────────────┘
                                              │
                                    sentinel/watcher.py  WatchWorker
                                    (one job at a time, dedupe + TTL cache)
                                              │
                          orchestrator.run_investigation() → report + ledger block
                                              │
                                   statebus.publish (state/verdict/case_file)
                                     │                   │
                              desktop pet reacts    dashboard companion bar
                                                     + "📂 View case" link
```

Key pieces:

- `sentinel/watcher.py` — `WatchTrigger`, `WatchWorker` (serial queue,
  `sha256(raw)` / subject+sender dedupe with TTL), surface-eml builder,
  confidence cap. Settings: `title_watch_enabled` (default on) and
  `watch_dedupe_ttl_seconds` (600) in `sentinel_settings.json` — shared with
  the pet's settings dialog and the right-click "Watch Mail Opens: ON/OFF"
  toggle.
- `app.py` — `POST /api/watch/open` (auth via the existing
  `require_api_key`; CORS enabled **only** under `/api/watch/*`) and
  `GET /api/watch/last` (full result for the dashboard's View-case link).
- `run_guard.py` — arms the watcher at startup (title tier on Windows only;
  extension tier works anywhere the server runs).
- `templates/index.html` — companion bar shows a "📂 View case" chip when a
  watched verdict lands; clicking it opens the full case in the Investigate
  tab.

## Setup

**Tier 1 (extension)** — see [extension/README.md](../extension/README.md):
load the folder unpacked via `chrome://extensions`, paste a token if the
server has an active API key, open a Gmail conversation.

**Tier 3 (title watcher)** — launch `python run_guard.py` on Windows. That's
it. Toggle it from the pet's right-click menu or Settings dialog. Manual
probe of the current window title:

```bash
python -m sentinel.title_watch --once
```

Optional (body OCR): `pip install pillow pytesseract` plus the tesseract
binary on PATH. Without it, Tier 3 still works — metadata-only surface
analysis.

## Safety & privacy notes

- Activation is event-driven only; there is no inbox sweep. Re-opening the
  same mail inside the dedupe TTL returns the cached verdict instead of
  re-scanning (the ledger stays append-only without duplicate spam).
- The extension reads the opened conversation only, and only when you open
  it; it sends data solely to `http://127.0.0.1:5000`.
- The forensic pipeline's optional reputation/geo lookups (ip-api.com,
  VirusTotal, AbuseIPDB) transmit the *sender's* IP/domain to those
  third-party APIs regardless of trigger tier — configure keys/toggles in
  `.env` if that matters to you.
- Tier 3 cannot see attachments, so no sandbox scan can be triggered by a
  title-watch activation (nothing file-touching is ever auto-approved).
- Tier 1's raw fetch relies on an undocumented Gmail endpoint; if it breaks,
  the extension degrades to surface mode automatically.

## Known limitations

- Non-English Gmail UIs: list-view titles may be misparsed as thread titles
  (the `- Gmail` suffix and unread counts remain reliable).
- Tier 3 fires on the foreground window only — opens on a phone or a
  second monitor's background tab are invisible without Tier 1.
- Two different mails with the same subject dedupe into one cache entry at
  Tier 3 (no message-id is available); full raw mode keys on content hash.
