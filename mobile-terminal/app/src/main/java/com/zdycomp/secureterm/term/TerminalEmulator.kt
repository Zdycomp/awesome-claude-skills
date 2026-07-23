package com.zdycomp.secureterm.term

/**
 * A bounded VT100/xterm-subset emulator.
 *
 * Threat surface: everything fed to [append] is attacker-influenced — any
 * file the user `cat`s, any program output, can contain arbitrary escape
 * sequences. Defenses:
 *  - The parser is a strict state machine with hard caps on parameter
 *    count (16), parameter value (9999), and OSC string length (2048);
 *    anything over-limit is discarded, never buffered unbounded.
 *  - The only sequences that ever *send* data back to the child are two
 *    fixed-format replies (cursor position report, device attributes).
 *    There is deliberately no OSC 52 (clipboard write), no font/keyboard
 *    remapping, no answerback string — the classic escape-injection
 *    exfiltration channels are simply not implemented.
 *  - Window-title updates are stripped of control characters and capped
 *    at 128 chars before reaching the UI.
 *  - Scrollback is a capped ring (2000 lines): output floods cannot
 *    exhaust memory.
 *
 * Threading: all mutation happens on the main thread (TerminalSession
 * posts decoded chunks there), so the renderer may read state directly.
 */
class TerminalEmulator(
    rows: Int,
    cols: Int,
    /** Writes emulator replies (DSR/DA) back to the PTY. */
    private val responder: (String) -> Unit,
    private val onBell: () -> Unit,
    private val onTitle: (String) -> Unit
) {
    companion object {
        const val MAX_SCROLLBACK = 2000
        private const val MAX_PARAMS = 16
        private const val MAX_PARAM_VALUE = 9999
        private const val MAX_OSC_LENGTH = 2048
        private const val MAX_TITLE_LENGTH = 128

        // Style bit layout: fg(9) | bg(9) | bold | underline | inverse
        const val COLOR_DEFAULT_FG = 256
        const val COLOR_DEFAULT_BG = 257
        private const val BG_SHIFT = 9
        const val FLAG_BOLD = 1 shl 18
        const val FLAG_UNDERLINE = 1 shl 19
        const val FLAG_INVERSE = 1 shl 20

        fun makeStyle(fg: Int, bg: Int, flags: Int): Int =
            (fg and 0x1FF) or ((bg and 0x1FF) shl BG_SHIFT) or flags

        fun styleFg(style: Int): Int = style and 0x1FF
        fun styleBg(style: Int): Int = (style shr BG_SHIFT) and 0x1FF

        val DEFAULT_STYLE = makeStyle(COLOR_DEFAULT_FG, COLOR_DEFAULT_BG, 0)
    }

    class Row(cols: Int) {
        var chars = CharArray(cols) { ' ' }
        var styles = IntArray(cols) { DEFAULT_STYLE }

        fun clear(from: Int, to: Int, style: Int) {
            val hi = to.coerceAtMost(chars.size)
            for (i in from.coerceAtLeast(0) until hi) {
                chars[i] = ' '
                styles[i] = style
            }
        }

        fun resized(newCols: Int): Row {
            val r = Row(newCols)
            val n = minOf(newCols, chars.size)
            System.arraycopy(chars, 0, r.chars, 0, n)
            System.arraycopy(styles, 0, r.styles, 0, n)
            return r
        }
    }

    var rows = rows.coerceIn(2, 1000); private set
    var cols = cols.coerceIn(2, 1000); private set

    private var screen: Array<Row> = Array(this.rows) { Row(this.cols) }
    private var altScreen: Array<Row>? = null
    val scrollback = ArrayDeque<Row>()

    var cursorRow = 0; private set
    var cursorCol = 0; private set
    var cursorVisible = true; private set

    private var savedRow = 0
    private var savedCol = 0
    private var savedStyle = DEFAULT_STYLE

    private var scrollTop = 0
    private var scrollBottom = this.rows - 1

    private var style = DEFAULT_STYLE
    private var pendingWrap = false
    var bracketedPaste = false; private set
    private val inAltScreen get() = altScreen != null

    // Parser state machine
    private enum class State { NORMAL, ESC, CSI, OSC, OSC_ESC, CHARSET }

    private var state = State.NORMAL
    private val params = IntArray(MAX_PARAMS)
    private var paramCount = 0
    private var csiPrivate = false
    private var csiOverflow = false
    private val oscBuffer = StringBuilder()

    /** Monotonic counter the view uses to know a redraw is needed. */
    var changeCount = 0L; private set

    fun screenRow(index: Int): Row = screen[index.coerceIn(0, rows - 1)]

    fun append(text: CharSequence) {
        for (i in text.indices) processChar(text[i])
        changeCount++
    }

    private fun processChar(c: Char) {
        when (state) {
            State.NORMAL -> processNormal(c)
            State.ESC -> processEsc(c)
            State.CSI -> processCsi(c)
            State.OSC -> processOsc(c)
            State.OSC_ESC -> {
                // ESC inside OSC: only ESC \ (ST) terminates.
                state = if (c == '\\') { finishOsc(); State.NORMAL } else State.OSC
            }
            State.CHARSET -> state = State.NORMAL // consume charset designator
        }
    }

    private fun processNormal(c: Char) {
        when (c) {
            '\u0000' -> {}
            '\u0007' -> onBell()
            '\b' -> { if (cursorCol > 0) cursorCol--; pendingWrap = false }
            '\t' -> {
                cursorCol = ((cursorCol / 8 + 1) * 8).coerceAtMost(cols - 1)
                pendingWrap = false
            }
            '\n', '\u000B', '\u000C' -> lineFeed()
            '\r' -> { cursorCol = 0; pendingWrap = false }
            '\u000E', '\u000F' -> {} // SO/SI charset shifts: single charset only
            '\u001B' -> state = State.ESC
            else -> if (c >= ' ') putChar(c)
        }
    }

    private fun putChar(c: Char) {
        if (pendingWrap) {
            cursorCol = 0
            lineFeed()
            pendingWrap = false
        }
        // Non-BMP halves render as replacement char; keeps cell grid 1:1.
        val ch = if (Character.isSurrogate(c)) '�' else c
        val row = screen[cursorRow]
        row.chars[cursorCol] = ch
        row.styles[cursorCol] = style
        if (cursorCol == cols - 1) pendingWrap = true else cursorCol++
    }

    private fun lineFeed() {
        if (cursorRow == scrollBottom) scrollUp(1) else if (cursorRow < rows - 1) cursorRow++
        pendingWrap = false
    }

    private fun scrollUp(n: Int) {
        repeat(n.coerceIn(1, rows)) {
            val removed = screen[scrollTop]
            if (scrollTop == 0 && !inAltScreen) {
                scrollback.addLast(removed)
                while (scrollback.size > MAX_SCROLLBACK) scrollback.removeFirst()
                for (r in scrollTop until scrollBottom) screen[r] = screen[r + 1]
                screen[scrollBottom] = Row(cols)
            } else {
                for (r in scrollTop until scrollBottom) screen[r] = screen[r + 1]
                removed.clear(0, cols, DEFAULT_STYLE)
                screen[scrollBottom] = removed
            }
        }
    }

    private fun scrollDown(n: Int) {
        repeat(n.coerceIn(1, rows)) {
            val removed = screen[scrollBottom]
            for (r in scrollBottom downTo scrollTop + 1) screen[r] = screen[r - 1]
            removed.clear(0, cols, DEFAULT_STYLE)
            screen[scrollTop] = removed
        }
    }

    private fun processEsc(c: Char) {
        state = State.NORMAL
        when (c) {
            '[' -> {
                params.fill(0); paramCount = 0
                csiPrivate = false; csiOverflow = false
                state = State.CSI
            }
            ']' -> { oscBuffer.setLength(0); state = State.OSC }
            '(', ')', '*', '+' -> state = State.CHARSET
            'D' -> lineFeed()
            'E' -> { cursorCol = 0; lineFeed() }
            'M' -> { // reverse index
                if (cursorRow == scrollTop) scrollDown(1)
                else if (cursorRow > 0) cursorRow--
                pendingWrap = false
            }
            '7' -> saveCursor()
            '8' -> restoreCursor()
            'c' -> fullReset()
            else -> {} // unsupported: ignore, never crash
        }
    }

    private fun processCsi(c: Char) {
        when {
            c in '0'..'9' -> {
                if (paramCount == 0) paramCount = 1
                if (paramCount <= MAX_PARAMS) {
                    val idx = paramCount - 1
                    params[idx] = (params[idx] * 10 + (c - '0')).coerceAtMost(MAX_PARAM_VALUE)
                }
            }
            c == ';' -> {
                if (paramCount == 0) paramCount = 1
                paramCount++
                if (paramCount > MAX_PARAMS) csiOverflow = true
            }
            c == '?' -> csiPrivate = true
            c == ' ' || c == '>' || c == '=' || c == '!' || c == '"' || c == '\'' -> {} // intermediates: tolerate
            c.code in 0x40..0x7E -> {
                state = State.NORMAL
                if (!csiOverflow) dispatchCsi(c)
            }
            else -> state = State.NORMAL // malformed: abort sequence
        }
    }

    private fun param(i: Int, default: Int): Int =
        if (i < paramCount && params[i] != 0) params[i] else default

    private fun dispatchCsi(final: Char) {
        pendingWrap = false
        when (final) {
            'A' -> cursorRow = (cursorRow - param(0, 1)).coerceAtLeast(scrollTop)
            'B' -> cursorRow = (cursorRow + param(0, 1)).coerceAtMost(scrollBottom)
            'C' -> cursorCol = (cursorCol + param(0, 1)).coerceAtMost(cols - 1)
            'D' -> cursorCol = (cursorCol - param(0, 1)).coerceAtLeast(0)
            'E' -> { cursorRow = (cursorRow + param(0, 1)).coerceAtMost(scrollBottom); cursorCol = 0 }
            'F' -> { cursorRow = (cursorRow - param(0, 1)).coerceAtLeast(scrollTop); cursorCol = 0 }
            'G' -> cursorCol = (param(0, 1) - 1).coerceIn(0, cols - 1)
            'd' -> cursorRow = (param(0, 1) - 1).coerceIn(0, rows - 1)
            'H', 'f' -> {
                cursorRow = (param(0, 1) - 1).coerceIn(0, rows - 1)
                cursorCol = (param(1, 1) - 1).coerceIn(0, cols - 1)
            }
            'J' -> eraseDisplay(if (paramCount > 0) params[0] else 0)
            'K' -> eraseLine(if (paramCount > 0) params[0] else 0)
            'L' -> insertLines(param(0, 1))
            'M' -> deleteLines(param(0, 1))
            'P' -> deleteChars(param(0, 1))
            '@' -> insertChars(param(0, 1))
            'X' -> screen[cursorRow].clear(cursorCol, cursorCol + param(0, 1), style)
            'S' -> scrollUp(param(0, 1))
            'T' -> scrollDown(param(0, 1))
            'r' -> {
                val top = (param(0, 1) - 1).coerceIn(0, rows - 1)
                val bottom = (param(1, rows) - 1).coerceIn(0, rows - 1)
                if (top < bottom) {
                    scrollTop = top; scrollBottom = bottom
                    cursorRow = scrollTop; cursorCol = 0
                }
            }
            'm' -> applySgr()
            'h' -> setMode(true)
            'l' -> setMode(false)
            'n' -> if (param(0, 0) == 6) {
                // Fixed-format reply only; values are clamped screen coords.
                responder("\u001B[${cursorRow + 1};${cursorCol + 1}R")
            }
            'c' -> responder("\u001B[?6c") // "I am a VT102" — constant string
            's' -> saveCursor()
            'u' -> restoreCursor()
            else -> {} // unimplemented finals ignored
        }
    }

    private fun setMode(set: Boolean) {
        if (!csiPrivate) return // ANSI modes (IRM etc.) not supported
        for (i in 0 until paramCount.coerceAtLeast(1)) {
            when (params[i]) {
                25 -> cursorVisible = set
                2004 -> bracketedPaste = set
                47, 1047, 1049 -> if (set) enterAltScreen() else exitAltScreen()
                // Mouse reporting (1000/1002/1006) intentionally not
                // implemented: avoids synthetic-input injection surface.
                else -> {}
            }
        }
    }

    private fun enterAltScreen() {
        if (inAltScreen) return
        saveCursor()
        altScreen = screen
        screen = Array(rows) { Row(cols) }
        cursorRow = 0; cursorCol = 0
    }

    private fun exitAltScreen() {
        val main = altScreen ?: return
        screen = main
        altScreen = null
        restoreCursor()
    }

    private fun eraseDisplay(mode: Int) {
        when (mode) {
            0 -> {
                eraseLine(0)
                for (r in cursorRow + 1 until rows) screen[r].clear(0, cols, style)
            }
            1 -> {
                eraseLine(1)
                for (r in 0 until cursorRow) screen[r].clear(0, cols, style)
            }
            2 -> for (r in 0 until rows) screen[r].clear(0, cols, style)
            3 -> { for (r in 0 until rows) screen[r].clear(0, cols, style); scrollback.clear() }
        }
    }

    private fun eraseLine(mode: Int) {
        val row = screen[cursorRow]
        when (mode) {
            0 -> row.clear(cursorCol, cols, style)
            1 -> row.clear(0, cursorCol + 1, style)
            2 -> row.clear(0, cols, style)
        }
    }

    private fun insertLines(n: Int) {
        if (cursorRow < scrollTop || cursorRow > scrollBottom) return
        repeat(n.coerceIn(1, rows)) {
            val removed = screen[scrollBottom]
            for (r in scrollBottom downTo cursorRow + 1) screen[r] = screen[r - 1]
            removed.clear(0, cols, DEFAULT_STYLE)
            screen[cursorRow] = removed
        }
    }

    private fun deleteLines(n: Int) {
        if (cursorRow < scrollTop || cursorRow > scrollBottom) return
        repeat(n.coerceIn(1, rows)) {
            val removed = screen[cursorRow]
            for (r in cursorRow until scrollBottom) screen[r] = screen[r + 1]
            removed.clear(0, cols, DEFAULT_STYLE)
            screen[scrollBottom] = removed
        }
    }

    private fun deleteChars(n: Int) {
        val row = screen[cursorRow]
        val count = n.coerceIn(1, cols - cursorCol)
        for (i in cursorCol until cols - count) {
            row.chars[i] = row.chars[i + count]
            row.styles[i] = row.styles[i + count]
        }
        row.clear(cols - count, cols, style)
    }

    private fun insertChars(n: Int) {
        val row = screen[cursorRow]
        val count = n.coerceIn(1, cols - cursorCol)
        for (i in cols - 1 downTo cursorCol + count) {
            row.chars[i] = row.chars[i - count]
            row.styles[i] = row.styles[i - count]
        }
        row.clear(cursorCol, cursorCol + count, style)
    }

    private fun applySgr() {
        if (paramCount == 0) { style = DEFAULT_STYLE; return }
        var i = 0
        var fg = styleFg(style)
        var bg = styleBg(style)
        var flags = style and (FLAG_BOLD or FLAG_UNDERLINE or FLAG_INVERSE)
        while (i < paramCount) {
            when (val p = params[i]) {
                0 -> { fg = COLOR_DEFAULT_FG; bg = COLOR_DEFAULT_BG; flags = 0 }
                1 -> flags = flags or FLAG_BOLD
                4 -> flags = flags or FLAG_UNDERLINE
                7 -> flags = flags or FLAG_INVERSE
                22 -> flags = flags and FLAG_BOLD.inv()
                24 -> flags = flags and FLAG_UNDERLINE.inv()
                27 -> flags = flags and FLAG_INVERSE.inv()
                in 30..37 -> fg = p - 30
                38 -> { // 38;5;n (256-color); 38;2;r;g;b consumed but mapped to default
                    if (i + 2 < paramCount && params[i + 1] == 5) {
                        fg = params[i + 2].coerceIn(0, 255); i += 2
                    } else if (i + 4 < paramCount && params[i + 1] == 2) {
                        fg = COLOR_DEFAULT_FG; i += 4
                    }
                }
                39 -> fg = COLOR_DEFAULT_FG
                in 40..47 -> bg = p - 40
                48 -> {
                    if (i + 2 < paramCount && params[i + 1] == 5) {
                        bg = params[i + 2].coerceIn(0, 255); i += 2
                    } else if (i + 4 < paramCount && params[i + 1] == 2) {
                        bg = COLOR_DEFAULT_BG; i += 4
                    }
                }
                49 -> bg = COLOR_DEFAULT_BG
                in 90..97 -> fg = p - 90 + 8
                in 100..107 -> bg = p - 100 + 8
                else -> {}
            }
            i++
        }
        style = makeStyle(fg, bg, flags)
    }

    private fun processOsc(c: Char) {
        when {
            c == '\u0007' -> { finishOsc(); state = State.NORMAL }
            c == '\u001B' -> state = State.OSC_ESC
            oscBuffer.length >= MAX_OSC_LENGTH -> {} // over cap: swallow silently
            else -> oscBuffer.append(c)
        }
    }

    private fun finishOsc() {
        val s = oscBuffer.toString()
        oscBuffer.setLength(0)
        // Only window-title updates are honored (OSC 0/2). Everything else —
        // notably OSC 52 clipboard writes — is deliberately dropped.
        val title = when {
            s.startsWith("0;") -> s.substring(2)
            s.startsWith("2;") -> s.substring(2)
            else -> return
        }
        val clean = title.asSequence()
            .filter { !it.isISOControl() }
            .take(MAX_TITLE_LENGTH)
            .joinToString("")
        onTitle(clean)
    }

    private fun saveCursor() {
        savedRow = cursorRow; savedCol = cursorCol; savedStyle = style
    }

    private fun restoreCursor() {
        cursorRow = savedRow.coerceIn(0, rows - 1)
        cursorCol = savedCol.coerceIn(0, cols - 1)
        style = savedStyle
        pendingWrap = false
    }

    private fun fullReset() {
        style = DEFAULT_STYLE
        cursorVisible = true
        bracketedPaste = false
        scrollTop = 0; scrollBottom = rows - 1
        cursorRow = 0; cursorCol = 0
        pendingWrap = false
        altScreen = null
        screen = Array(rows) { Row(cols) }
    }

    fun resize(newRows: Int, newCols: Int) {
        val nr = newRows.coerceIn(2, 1000)
        val nc = newCols.coerceIn(2, 1000)
        if (nr == rows && nc == cols) return

        fun remap(old: Array<Row>): Array<Row> = Array(nr) { r ->
            if (r < old.size) old[r].resized(nc) else Row(nc)
        }
        screen = remap(screen)
        altScreen = altScreen?.let { remap(it) }

        rows = nr; cols = nc
        scrollTop = 0; scrollBottom = rows - 1
        cursorRow = cursorRow.coerceIn(0, rows - 1)
        cursorCol = cursorCol.coerceIn(0, cols - 1)
        pendingWrap = false
        changeCount++
    }
}
