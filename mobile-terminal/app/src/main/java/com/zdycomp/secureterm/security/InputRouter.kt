package com.zdycomp.secureterm.security

/**
 * Sits between the view's raw character stream and the PTY.
 *
 * Responsibilities:
 *  - Shadow-tracks the line being typed (best effort: printable chars,
 *    backspace, Ctrl-U/Ctrl-C resets) so [CommandGuard] can vet it and
 *    [SecureHistoryStore] can record it at Enter time.
 *  - Holds Enter back when the guard flags the line, asks the UI for
 *    confirmation, and on refusal sends Ctrl-U (kill-line) so the
 *    dangerous text is wiped from the shell's input buffer too.
 *  - Applies the Ctrl-modifier toggle from the extra-keys bar.
 *  - Vets pasted text line-by-line before forwarding, honoring the
 *    emulator's bracketed-paste mode.
 *
 * Limitation, stated plainly: shell line-editing (arrow-key history
 * recall, Ctrl-R search) can desynchronize the shadow line. The guard is
 * an accident seatbelt on top of the app sandbox, not the sandbox itself.
 */
class InputRouter(
    private val sendToPty: (String) -> Unit,
    private val historySink: (String) -> Unit,
    /** UI hook: show dialog, call back with the user's decision. */
    private val confirmDangerous: (reason: String, line: String, proceed: (Boolean) -> Unit) -> Unit,
    private val isBracketedPaste: () -> Boolean
) {
    private val shadow = StringBuilder()
    private var ctrlPending = false
    private var awaitingDecision = false

    fun toggleCtrl(): Boolean {
        ctrlPending = !ctrlPending
        return ctrlPending
    }

    /** Entry point for every character the view produces. */
    fun onInput(text: String) {
        if (awaitingDecision) return // freeze input while the dialog is up
        for (c in text) onChar(c)
    }

    private fun onChar(c: Char) {
        if (ctrlPending && c.code >= 0x20) {
            ctrlPending = false
            val base = c.uppercaseChar()
            if (base in '@'..'_') {
                val ctrl = (base.code and 0x1F).toChar()
                if (ctrl == '\u0003' || ctrl == '\u0015') shadow.setLength(0) // ^C / ^U
                sendToPty(ctrl.toString())
            }
            return
        }
        when (c) {
            '\r', '\n' -> onEnter()
            '\u007F', '\b' -> {
                if (shadow.isNotEmpty()) shadow.setLength(shadow.length - 1)
                sendToPty("\u007F")
            }
            '\u0003', '\u0015' -> { // ^C, ^U reset the line
                shadow.setLength(0)
                sendToPty(c.toString())
            }
            '\u001B' -> {
                // Escape sequences (arrows etc.) may recall history we can't
                // see; drop shadow tracking for this line rather than guess.
                shadow.setLength(0)
                sendToPty(c.toString())
            }
            else -> {
                if (c.code >= 0x20 && shadow.length < 4096) shadow.append(c)
                sendToPty(c.toString())
            }
        }
    }

    private fun onEnter() {
        val line = shadow.toString()
        shadow.setLength(0)
        val verdict = CommandGuard.check(line)
        if (!verdict.dangerous) {
            if (line.isNotBlank()) historySink(line)
            sendToPty("\r")
            return
        }
        awaitingDecision = true
        confirmDangerous(verdict.reason, line) { proceed ->
            awaitingDecision = false
            if (proceed) {
                historySink(line)
                sendToPty("\r")
            } else {
                sendToPty("\u0015") // kill-line: clear it in the shell too
            }
        }
    }

    /**
     * Pasted text is scanned as a batch: if any line is flagged, one dialog
     * covers the whole paste; refusal drops the entire paste unsent.
     */
    fun onPaste(text: String) {
        if (awaitingDecision) return
        // Control characters other than newline/tab are stripped from pastes:
        // a malicious clipboard cannot smuggle escape sequences or raw ^D.
        val clean = text.filter { it == '\n' || it == '\t' || it.code >= 0x20 }.take(65536)
        if (clean.isEmpty()) return

        val flagged = clean.lines().firstNotNullOfOrNull { line ->
            CommandGuard.check(line).let { if (it.dangerous) it to line else null }
        }
        val deliver = {
            shadow.setLength(0)
            if (isBracketedPaste()) {
                sendToPty("\u001B[200~" + clean + "\u001B[201~")
            } else {
                sendToPty(clean.replace("\n", "\r"))
            }
        }
        if (flagged == null) {
            deliver()
        } else {
            awaitingDecision = true
            confirmDangerous(flagged.first.reason, flagged.second) { proceed ->
                awaitingDecision = false
                if (proceed) deliver()
            }
        }
    }
}
