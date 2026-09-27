chrome.runtime.onMessage.addListener((message) => {
  if (!message || message.type !== "edit") return;
  const removed = Number.isInteger(message.removed) ? message.removed : 0;
  const len = Number.isInteger(message.len) ? message.len : 0;
  const boundary = message.boundary === true;
  if (removed < 0 || len < 0 || (removed === 0 && len === 0)) return;
  chrome.storage.local.get(["port", "token"], (saved) => {
    const port = String(saved.port ?? "").trim();
    const token = String(saved.token ?? "").trim();
    if (!/^[0-9]+$/.test(port) || token.length < 32) return;
    fetch(`http://127.0.0.1:${port}/events`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ changes: [{ removed, len, boundary }] }),
    }).catch(() => {});
  });
});
