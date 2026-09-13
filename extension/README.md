# Sentinel Guard Connector (Tier 1 — browser extension)

A Chrome/Edge MV3 extension that activates the Sentinel agent **only when you
open a mail** in Gmail. No OAuth token, no Google Cloud project, no account
access beyond the page you already have open.

## Install (load unpacked)

1. Start Sentinel: `python run_guard.py` (server at http://127.0.0.1:5000).
2. Open `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select this `extension/` folder.
5. Pin the extension and click its icon: optionally paste an API key
   (`sk_sentinel_…`) or session token (`sk_session_…`) if the server has one
   active. While no key is configured, the server accepts unauthenticated
   watch calls.

## How it works

1. Opening a conversation changes the URL to `#<label>/<threadId>` — the
   content script fires on that exact event (and re-checks every 1.2 s).
2. It fetches the message's **original RFC822 source** (the document behind
   Gmail's *Show original*) with your own session cookies.
   - Success → the server runs the **full forensic pipeline** (headers,
     SPF/DKIM, origin IP, geolocation, URLs, attachments in the sandbox).
   - Failure (Gmail DOM/endpoint changed) → it posts only the visible
     subject/sender/body; the server runs **surface-only analysis** with the
     confidence capped at 60%.
3. The verdict comes back and is shown as a small chip in the corner of the
   reading pane; the desktop pet and dashboard react through the statebus.

## Privacy

- Reads nothing in the background: activation happens on conversation-open only.
- The message goes only to your local Sentinel server (127.0.0.1).
- The server's optional reputation lookups (VirusTotal/AbuseIPDB/ip-api) do
  send the sender's IP/domain to those third parties — see docs/WATCHER.md.
