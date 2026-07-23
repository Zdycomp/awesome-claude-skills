package com.zdycomp.secureterm.term

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.util.AttributeSet
import android.view.GestureDetector
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputMethodManager

/**
 * Renders a [TerminalEmulator] and turns Android input events into a raw
 * character stream.
 *
 * Input flows one way: keys/IME/paste → [inputSink] → (router/guard) → PTY.
 * The view itself never interprets or executes anything; it only forwards
 * characters. Rendering reads emulator state on the main thread only.
 */
class TerminalView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {

    var emulator: TerminalEmulator? = null
        set(value) {
            field = value
            scrollOffset = 0
            invalidate()
        }

    /** Receives every character of user input (already mapped to VT codes). */
    var inputSink: ((String) -> Unit)? = null

    /** Called when the visible grid geometry changes. */
    var onGeometryChanged: ((rows: Int, cols: Int) -> Unit)? = null

    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.MONOSPACE
        textSize = 14f * resources.displayMetrics.scaledDensity
    }
    private val bgPaint = Paint()

    private var charWidth = 1f
    private var charHeight = 1
    private var charAscent = 0

    /** Lines scrolled back into history; 0 = live screen. */
    private var scrollOffset = 0

    private val defaultFg = Color.rgb(0xE8, 0xE8, 0xE8)
    private val defaultBg = Color.rgb(0x14, 0x14, 0x14)

    private val basePalette = intArrayOf(
        Color.rgb(0x00, 0x00, 0x00), Color.rgb(0xCD, 0x3131),
        Color.rgb(0x0D, 0xBC, 0x79), Color.rgb(0xE5, 0xE5, 0x10),
        Color.rgb(0x24, 0x72, 0xC8), Color.rgb(0xBC, 0x3F, 0xBC),
        Color.rgb(0x11, 0xA8, 0xCD), Color.rgb(0xE5, 0xE5, 0xE5),
        Color.rgb(0x66, 0x66, 0x66), Color.rgb(0xF1, 0x4C, 0x4C),
        Color.rgb(0x23, 0xD1, 0x8B), Color.rgb(0xF5, 0xF5, 0x43),
        Color.rgb(0x3B, 0x8E, 0xEA), Color.rgb(0xD6, 0x70, 0xD6),
        Color.rgb(0x29, 0xB8, 0xDB), Color.rgb(0xFF, 0xFF, 0xFF)
    )

    private val gestureDetector =
        GestureDetector(context, object : GestureDetector.SimpleOnGestureListener() {
            private var pendingScroll = 0f

            override fun onDown(e: MotionEvent): Boolean {
                pendingScroll = 0f
                return true
            }

            override fun onScroll(
                e1: MotionEvent?, e2: MotionEvent,
                distanceX: Float, distanceY: Float
            ): Boolean {
                val em = emulator ?: return true
                pendingScroll += distanceY
                val lines = (pendingScroll / charHeight).toInt()
                if (lines != 0) {
                    pendingScroll -= lines * charHeight
                    scrollOffset = (scrollOffset - lines).coerceIn(0, em.scrollback.size)
                    invalidate()
                }
                return true
            }

            override fun onSingleTapUp(e: MotionEvent): Boolean {
                requestFocus()
                val imm = context.getSystemService(Context.INPUT_METHOD_SERVICE)
                        as InputMethodManager
                imm.showSoftInput(this@TerminalView, 0)
                return true
            }
        })

    init {
        isFocusable = true
        isFocusableInTouchMode = true
        recomputeCharMetrics()
    }

    private fun recomputeCharMetrics() {
        val fm = textPaint.fontMetricsInt
        charHeight = fm.descent - fm.ascent
        charAscent = -fm.ascent
        charWidth = textPaint.measureText("M")
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        if (w <= 0 || h <= 0) return
        val cols = (w / charWidth).toInt().coerceIn(2, 1000)
        val rows = (h / charHeight).coerceIn(2, 1000)
        onGeometryChanged?.invoke(rows, cols)
    }

    fun notifyScreenChanged() {
        // Fresh output snaps the viewport back to live.
        scrollOffset = 0
        invalidate()
    }

    private fun colorFor(index: Int, isFg: Boolean): Int = when {
        index == TerminalEmulator.COLOR_DEFAULT_FG -> defaultFg
        index == TerminalEmulator.COLOR_DEFAULT_BG -> defaultBg
        index in 0..15 -> basePalette[index]
        index in 16..231 -> {
            val v = index - 16
            val r = v / 36
            val g = (v % 36) / 6
            val b = v % 6
            fun ch(x: Int) = if (x == 0) 0 else 55 + x * 40
            Color.rgb(ch(r), ch(g), ch(b))
        }
        index in 232..255 -> {
            val gray = 8 + (index - 232) * 10
            Color.rgb(gray, gray, gray)
        }
        else -> if (isFg) defaultFg else defaultBg
    }

    override fun onDraw(canvas: Canvas) {
        canvas.drawColor(defaultBg)
        val em = emulator ?: return

        val sb = em.scrollback
        val offset = scrollOffset.coerceIn(0, sb.size)

        for (line in 0 until em.rows) {
            // Global line index: scrollback lines come first, then screen.
            val global = sb.size - offset + line
            val row: TerminalEmulator.Row = when {
                global < 0 -> continue
                global < sb.size -> sb[global]
                global - sb.size < em.rows -> em.screenRow(global - sb.size)
                else -> continue
            }
            drawRow(canvas, row, line)
        }

        if (offset == 0 && em.cursorVisible && isFocused) {
            val x = em.cursorCol * charWidth
            val y = em.cursorRow * charHeight
            bgPaint.color = defaultFg
            canvas.drawRect(x, y.toFloat(), x + charWidth, (y + charHeight).toFloat(), bgPaint)
            val r = em.screenRow(em.cursorRow)
            textPaint.color = defaultBg
            textPaint.isFakeBoldText = false
            textPaint.isUnderlineText = false
            canvas.drawText(
                charArrayOf(r.chars[em.cursorCol]), 0, 1,
                x, (y + charAscent).toFloat(), textPaint
            )
        }
    }

    private fun drawRow(canvas: Canvas, row: TerminalEmulator.Row, line: Int) {
        val y = line * charHeight
        val cols = minOf(row.chars.size, emulator?.cols ?: row.chars.size)
        var start = 0
        while (start < cols) {
            val style = row.styles[start]
            var end = start + 1
            while (end < cols && row.styles[end] == style) end++

            var fg = colorFor(TerminalEmulator.styleFg(style), true)
            var bg = colorFor(TerminalEmulator.styleBg(style), false)
            if (style and TerminalEmulator.FLAG_INVERSE != 0) {
                val t = fg; fg = bg; bg = t
            }

            val x0 = start * charWidth
            if (bg != defaultBg) {
                bgPaint.color = bg
                canvas.drawRect(
                    x0, y.toFloat(),
                    end * charWidth, (y + charHeight).toFloat(), bgPaint
                )
            }
            textPaint.color = fg
            textPaint.isFakeBoldText = style and TerminalEmulator.FLAG_BOLD != 0
            textPaint.isUnderlineText = style and TerminalEmulator.FLAG_UNDERLINE != 0
            canvas.drawText(row.chars, start, end - start, x0, (y + charAscent).toFloat(), textPaint)
            start = end
        }
    }

    // ---- input ----

    @Suppress("ClickableViewAccessibility")
    override fun onTouchEvent(event: MotionEvent): Boolean {
        gestureDetector.onTouchEvent(event)
        return true
    }

    override fun onCheckIsTextEditor(): Boolean = true

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection {
        // TYPE_NULL asks IMEs for plain key events without composing spans —
        // predictable input, nothing autocorrect can silently rewrite.
        outAttrs.inputType = EditorInfo.TYPE_NULL
        outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_FULLSCREEN or
                EditorInfo.IME_FLAG_NO_EXTRACT_UI
        return object : BaseInputConnection(this, false) {
            override fun commitText(text: CharSequence, newCursorPosition: Int): Boolean {
                inputSink?.invoke(text.toString())
                return true
            }

            override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean {
                repeat(beforeLength.coerceIn(0, 64)) { inputSink?.invoke("\u007F") }
                return true
            }

            override fun performEditorAction(actionCode: Int): Boolean {
                inputSink?.invoke("\r")
                return true
            }
        }
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        val sink = inputSink ?: return super.onKeyDown(keyCode, event)
        val seq: String? = when (keyCode) {
            KeyEvent.KEYCODE_ENTER, KeyEvent.KEYCODE_NUMPAD_ENTER -> "\r"
            KeyEvent.KEYCODE_DEL -> "\u007F"
            KeyEvent.KEYCODE_TAB -> "\t"
            KeyEvent.KEYCODE_ESCAPE -> "\u001B"
            KeyEvent.KEYCODE_DPAD_UP -> "\u001B[A"
            KeyEvent.KEYCODE_DPAD_DOWN -> "\u001B[B"
            KeyEvent.KEYCODE_DPAD_RIGHT -> "\u001B[C"
            KeyEvent.KEYCODE_DPAD_LEFT -> "\u001B[D"
            KeyEvent.KEYCODE_MOVE_HOME -> "\u001B[H"
            KeyEvent.KEYCODE_MOVE_END -> "\u001B[F"
            KeyEvent.KEYCODE_PAGE_UP -> "\u001B[5~"
            KeyEvent.KEYCODE_PAGE_DOWN -> "\u001B[6~"
            else -> {
                val uc = event.unicodeChar
                when {
                    event.isCtrlPressed && uc != 0 -> {
                        val base = uc.toChar().uppercaseChar()
                        if (base in '@'..'_') (base.code and 0x1F).toChar().toString() else null
                    }
                    uc != 0 -> uc.toChar().toString()
                    else -> null
                }
            }
        }
        return if (seq != null) {
            sink(seq)
            true
        } else {
            super.onKeyDown(keyCode, event)
        }
    }
}
