const SERVER = "http://127.0.0.1:5000";

const tokenInput = document.getElementById("token");
const statusEl = document.getElementById("status");
const lastEl = document.getElementById("last");

chrome.storage.local.get(["sentinel_token"], ({ sentinel_token }) => {
  tokenInput.value = sentinel_token || "";
});

document.getElementById("save").addEventListener("click", () => {
  chrome.storage.local.set({ sentinel_token: tokenInput.value.trim() }, () => {
    statusEl.innerHTML = '<span class="ok">✓ Token saved.</span>';
  });
});

(async () => {
  try {
    const res = await fetch(`${SERVER}/api/status`);
    if (!res.ok) throw new Error(res.status);
    const data = await res.json();
    const key = data.key_status ? data.key_status.status : "unknown";
    statusEl.innerHTML =
      `<span class="ok">● Sentinel server online</span><br>` +
      `Ledger blocks: ${data.total_investigations ?? "?"} · Integrity: ` +
      `<span class="${data.ledger_status && data.ledger_status.valid ? "ok" : "bad"}">` +
      `${data.ledger_status && data.ledger_status.valid ? "valid" : "TAMPERED"}</span><br>` +
      `Auth mode: ${key}`;
  } catch (e) {
    statusEl.innerHTML = '<span class="bad">● Sentinel server unreachable</span><br>Start it with run_guard.py (or python app.py).';
  }
})();

chrome.storage.local.get(["sentinel_last"], ({ sentinel_last }) => {
  if (sentinel_last && sentinel_last.verdict) {
    lastEl.style.display = "block";
    lastEl.textContent =
      `Last verdict: ${sentinel_last.verdict} — ${sentinel_last.risk_score}/100` +
      (sentinel_last.surface_only ? " [surface]" : "");
  }
});
