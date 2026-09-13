/**
 * Sentinel Guard Connector — content script (mail.google.com).
 *
 * Detects the moment the user OPENS a conversation (URL fragment changes to
 * #/<label>/<threadId>) and hands it to the local Sentinel server. The agent
 * then activates for exactly that message — nothing is scanned on arrival,
 * on a timer, or in the background.
 *
 * Tier 1 behavior:
 *   1. Try to fetch the message's ORIGINAL RFC822 source (the same document
 *      Gmail's "Show original" uses) with the user's own session cookies.
 *      -> full forensic pipeline on the server (headers, SPF/DKIM, ...).
 *   2. On any failure, post only what the DOM shows (subject/sender/body).
 *      -> server runs surface-only analysis with capped confidence.
 * The server response (or the statebus) carries the verdict; we render a
 * small chip in the corner of the reading pane.
 */
(() => {
  "use strict";

  const SERVER = "http://127.0.0.1:5000";
  const POLL_MS = 1200;

  let lastThreadId = null;
  let busy = false;

  // ------------------------------------------------------------------
  // Open detection
  // ------------------------------------------------------------------
  function currentThreadId() {
    // Gmail thread URLs look like: #inbox/AbCdEf123, #label/X/Y, #search/foo/AbCdEf
    const m = location.hash.match(/^#(?:[^/]+)\/([A-Za-z0-9-_]{8,})(?:[/?]|$)/);
    return m ? m[1] : null;
  }

  function threadSubject() {
    const el =
      document.querySelector("h2.hP") ||
      document.querySelector('[data-thread-perm-id] h2') ||
      document.querySelector('div[role="main"] h2');
    return el ? el.textContent.trim() : "";
  }

  function threadSender() {
    const el =
      document.querySelector(".gD") ||                       // sender name/email chip
      document.querySelector(".yW span[email]") ||
      document.querySelector('span[email][name="from"]');
    if (!el) return "";
    return el.getAttribute("email") || el.textContent.trim() || "";
  }

  function threadBodyText() {
    const body = document.querySelector("div.a3s.aiL");     // rendered message body
    return body ? body.innerText.trim().slice(0, 20000) : "";
  }

  // ------------------------------------------------------------------
  // Raw source fetch (same endpoint Gmail's "Show original" uses)
  // ------------------------------------------------------------------
  function findIkKey() {
    const html = document.documentElement.innerHTML.slice(0, 400000);
    const m = html.match(/\bik=["']([a-zA-Z0-9_-]+)["']/);
    return m ? m[1] : null;
  }

  async function fetchRawEml(threadId) {
    try {
      const ik = findIkKey();
      if (!ik) return null;
      const res = await fetch(
        `https://mail.google.com/mail/u/0/?ui=2&ik=${encodeURIComponent(ik)}` +
        `&view=om&th=${encodeURIComponent(threadId)}&num=0&zw`,
        { credentials: "include" }
      );
      if (!res.ok) return null;
      const text = await res.text();
      // Heuristic: an original message document contains RFC822 headers.
      if (text && text.length > 40 && /(^|\n)(Received|Return-Path|From|Message-ID|DKIM-Signature):/i.test(text.slice(0, 4000))) {
        return text;
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  // ------------------------------------------------------------------
  // Server round-trip (through the service worker: CORS-exempt there)
  // ------------------------------------------------------------------
  function postToServer(payload) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type: "sentinel-watch-open", payload }, (resp) => {
          void chrome.runtime.lastError; // e.g. worker restarting
          resolve(resp || { error: "no response from extension worker" });
        });
      } catch (e) {
        resolve({ error: String(e) });
      }
    });
  }

  // ------------------------------------------------------------------
  // Verdict chip
  // ------------------------------------------------------------------
  function showChip(text, color) {
    let chip = document.getElementById("sentinel-watch-chip");
    if (!chip) {
      chip = document.createElement("div");
      chip.id = "sentinel-watch-chip";
      chip.style.cssText = [
        "position:fixed", "right:18px", "bottom:18px", "z-index:99999",
        "background:#0F172A", "color:#E2E8F0", "border:1px solid rgba(59,130,246,0.5)",
        "border-radius:12px", "padding:10px 16px", "font:600 13px Inter,Segoe UI,sans-serif",
        "box-shadow:0 8px 24px rgba(0,0,0,0.45)", "max-width:340px", "opacity:0",
        "transition:opacity .25s", "pointer-events:none",
      ].join(";");
      document.documentElement.appendChild(chip);
    }
    chip.style.border = `1px solid ${color}`;
    chip.textContent = text;
    chip.style.opacity = "1";
    clearTimeout(showChip._t);
    showChip._t = setTimeout(() => { chip.style.opacity = "0"; }, 9000);
  }

  const VERDICT_COLOR = { SAFE: "#10B981", SUSPICIOUS: "#F59E0B", MALICIOUS: "#EF4444" };

  // ------------------------------------------------------------------
  // Main loop
  // ------------------------------------------------------------------
  async function checkForOpen() {
    if (busy) return;
    const threadId = currentThreadId();
    if (!threadId || threadId === lastThreadId) return;
    lastThreadId = threadId;
    busy = true;

    try {
      const subject = threadSubject();
      const sender = threadSender();
      showChip(`🛡️ Sentinel activated — analyzing "${subject || "opened mail"}"…`, "rgba(59,130,246,0.6)");

      const raw = await fetchRawEml(threadId);
      const payload = {
        source: "extension",
        thread_id: threadId,
        subject: subject,
        sender: sender,
        raw_eml: raw,
      };
      if (!raw) {
        // Surface fallback: give the server the visible body so URL/content
        // analysis still runs (headers/attachments are unavailable).
        payload.body_text = threadBodyText();
      }

      const resp = await postToServer(payload);
      if (resp && resp.queued) {
        showChip("🛡️ Sentinel: investigation queued — verdict will appear on the desktop guard.", "rgba(59,130,246,0.8)");
      } else if (resp && resp.verdict) {
        const v = resp.verdict;
        const c = VERDICT_COLOR[v] || "#3B82F6";
        const tag = resp.surface_only ? " [surface]" : "";
        showChip(`🛡️ Sentinel: ${v}${tag} — ${resp.risk_score}/100 (${resp.confidence_score}%)`, c);
        try { chrome.storage.local.set({ sentinel_last: resp }); } catch (e) {}
      } else {
        showChip(`🛡️ Sentinel: ${resp && resp.error ? resp.error : "no response from server"}`, "#F59E0B");
      }
    } finally {
      busy = false;
    }
  }

  window.addEventListener("hashchange", () => setTimeout(checkForOpen, 400)); // let the DOM render
  setInterval(checkForOpen, POLL_MS);

  // ==================================================================
  // ARRIVAL WATCH (tokenless): auto-triage mail as it LANDS in Gmail.
  // Watches the inbox list rows for new thread IDs. The raw source is
  // fetched the same way as for opens (view=om works without opening
  // the thread), so arrivals get FULL forensics with no account access.
  // Only non-SAFE arrivals surface a chip; everything is recorded for
  // the popup and the desktop pet/dashboard via the statebus.
  // ==================================================================
  let seenArrivals = null; // seeded on the first successful inbox scan

  function inboxRows() {
    const out = [];
    document.querySelectorAll('tr.zA a[href*="#inbox/"]').forEach((a) => {
      const m = (a.getAttribute("href") || "").match(/#inbox\/([A-Za-z0-9-_]+)/);
      if (m) {
        const row = a.closest("tr.zA");
        out.push({ threadId: m[1], row });
      }
    });
    return out;
  }

  function rowSubject(row) {
    const el = row && (row.querySelector(".y6") || row.querySelector("div[role='link'] .bog"));
    return el ? el.textContent.trim() : "";
  }

  function rowSender(row) {
    const el = row && row.querySelector(".yW span[email]");
    if (!el) return "";
    return el.getAttribute("email") || el.textContent.trim() || "";
  }

  async function handleArrival(item) {
    try {
      const subject = rowSubject(item.row) || "(new mail)";
      const sender = rowSender(item.row);
      const raw = await fetchRawEml(item.threadId);
      const payload = {
        source: "extension-arrival",
        thread_id: item.threadId,
        subject: subject,
        sender: sender,
        raw_eml: raw,
      };
      const resp = await postToServer(payload);
      try { chrome.storage.local.set({ sentinel_last_arrival: resp }); } catch (e) {}
      if (resp && (resp.verdict === "MALICIOUS" || resp.verdict === "SUSPICIOUS")) {
        const v = resp.verdict;
        showChip(`🛡️ New mail auto-scanned — ${v}: "${subject}" (${resp.risk_score}/100)`,
                 v === "MALICIOUS" ? "#EF4444" : "#F59E0B");
      }
    } catch (e) { /* never break the page on a failed scan */ }
  }

  function scanArrivals() {
    const rows = inboxRows();
    if (!rows.length) return;                 // not on a list view right now
    const ids = rows.map((r) => r.threadId);
    if (seenArrivals === null) {              // first scan: baseline, no back-scan
      seenArrivals = new Set(ids);
      return;
    }
    for (const item of rows) {
      if (seenArrivals.has(item.threadId)) continue;
      seenArrivals.add(item.threadId);
      handleArrival(item);
    }
  }
  setInterval(scanArrivals, POLL_MS * 3);
})();
