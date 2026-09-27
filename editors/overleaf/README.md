# ZK-Scribe for Overleaf

The extension captures the Overleaf source editor. Each edit becomes a length, a removal count, and a boundary flag. The manuscript text is not sent to the local bridge.

1. Clone the Overleaf Git remote and run `zk-scribe init`.
2. Run `zk-scribe overleaf` in that clone. It prints a port, a token, and this folder.
3. In Chrome, open `chrome://extensions`, turn on Developer mode, and choose **Load unpacked**. Select this folder.
4. Open the extension options and paste the port and token.
5. Write in the Overleaf source editor. Commit from the clone. The hook attests the captured session.

The visual editor is not captured. A Git pull is not turned into keystrokes. A paste of 15 characters or more stays one paste, and the composition check refuses it.

Overleaf can change the editor markup. When `.cm-content` is no longer where typing happens, this extension stops seeing edits.
