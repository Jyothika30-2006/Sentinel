/**
 * Sentinel Guard Connector — MV3 service worker.
 *
 * MV3 content scripts cannot bypass page CORS, so the cross-origin POST to
 * the local Sentinel server happens here (host_permissions make this
 * CORS-exempt). Adds the stored auth header if the user saved one in the
 * popup; the server also accepts unauthenticated calls while no API key is
 * configured.
 */

const SERVER = "http://127.0.0.1:5000";

async function authHeaders() {
  const headers = { "Content-Type": "application/json" };
  try {
    const { sentinel_token } = await chrome.storage.local.get(["sentinel_token"]);
    const token = (sentinel_token || "").trim();
    if (token.startsWith("sk_session_")) {
      headers["X-Session-Token"] = token;
    } else if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  } catch (e) { /* storage unavailable — go unauthenticated */ }
  return headers;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "sentinel-watch-open") return false;

  (async () => {
    try {
      const res = await fetch(`${SERVER}/api/watch/open`, {
        method: "POST",
        headers: await authHeaders(),
        body: JSON.stringify(msg.payload || {}),
      });
      const data = await res.json().catch(() => ({}));
      data._status = res.status;
      try {
        const { sentinel_last } = await chrome.storage.local.get(["sentinel_last"]);
        void sentinel_last;
        if (data.verdict) await chrome.storage.local.set({ sentinel_last: data });
      } catch (e) { /* non-fatal */ }
      sendResponse(data);
    } catch (e) {
      sendResponse({ error: `Sentinel server unreachable (${e}). Is run_guard.py running?` });
    }
  })();

  return true; // async sendResponse
});
