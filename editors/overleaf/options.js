const port = document.getElementById("port");
const token = document.getElementById("token");
const status = document.getElementById("status");

chrome.storage.local.get(["port", "token"], (saved) => {
  port.value = saved.port ?? "";
  token.value = saved.token ?? "";
});

document.getElementById("save").addEventListener("click", () => {
  chrome.storage.local.set(
    { port: port.value.trim(), token: token.value.trim() },
    () => {
      status.textContent = "Saved on this browser.";
    },
  );
});
