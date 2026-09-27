const EDITOR = ".cm-content";

document.addEventListener(
  "beforeinput",
  (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const editor = target.closest(EDITOR);
    if (!editor) return;
    const before = editor.textContent ? editor.textContent.length : 0;
    const removed = removedLength(event);
    editor.addEventListener(
      "input",
      () => {
        const after = editor.textContent ? editor.textContent.length : before;
        const len = Math.max(0, after - (before - removed));
        const last = len > 0 && editor.textContent ? editor.textContent.slice(-1) : "";
        const boundary = /[\s.!?;:\n]/.test(last);
        if (removed === 0 && len === 0) return;
        chrome.runtime.sendMessage({ type: "edit", removed, len, boundary });
      },
      { once: true },
    );
  },
  true,
);

function removedLength(event) {
  if (typeof event.getTargetRanges === "function") {
    const ranges = event.getTargetRanges();
    let count = 0;
    for (const range of ranges) count += range.toString().length;
    if (count > 0) return count;
  }
  const inputType = String(event.inputType || "");
  if (inputType.startsWith("delete") || inputType === "deleteByCut") return 1;
  return 0;
}
