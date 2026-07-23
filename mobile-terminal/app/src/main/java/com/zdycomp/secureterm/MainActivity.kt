package com.zdycomp.secureterm

import android.app.AlertDialog
import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.zdycomp.secureterm.security.InputRouter
import com.zdycomp.secureterm.security.SecureHistoryStore
import com.zdycomp.secureterm.security.StorageBridge
import com.zdycomp.secureterm.term.ShellBootstrap
import com.zdycomp.secureterm.term.TerminalEmulator
import com.zdycomp.secureterm.term.TerminalSession
import com.zdycomp.secureterm.term.TerminalView
import java.io.File

/**
 * Wires the UI, the session, and the security layer together.
 *
 * The activity holds no privileged state; it is the only exported component
 * and it accepts no data-bearing intents (MAIN/LAUNCHER only), so another
 * app cannot use it to inject commands.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var terminalView: TerminalView
    private lateinit var titleView: TextView
    private var session: TerminalSession? = null
    private lateinit var router: InputRouter
    private lateinit var history: SecureHistoryStore
    private lateinit var storage: StorageBridge

    private val importPicker =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            uri ?: return@registerForActivityResult
            try {
                val path = storage.importInto(contentResolver, uri, this)
                if (path != null) {
                    // Feed the imported path to the shell as a comment for the
                    // user to act on; never auto-execute anything.
                    toast("Imported into sandbox")
                    session?.write("# imported: ${File(path).name}\n")
                } else {
                    toast("Import refused")
                }
            } catch (_: Exception) {
                toast("Import failed")
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val env = ShellBootstrap.prepare(filesDir, cacheDir)
        history = SecureHistoryStore(File(filesDir, "history.enc"))
        storage = StorageBridge(env.home)

        setContentView(buildLayout())

        val emulator = TerminalEmulator(
            rows = 24, cols = 80,
            responder = { session?.write(it) },
            onBell = { terminalView.performHapticFeedbackSafe() },
            onTitle = { runOnUiThread { titleView.text = it.ifBlank { getString(R.string.app_name) } } }
        )
        terminalView.emulator = emulator

        router = InputRouter(
            sendToPty = { session?.write(it) },
            historySink = { history.append(it) },
            confirmDangerous = { reason, line, decide -> confirmDialog(reason, line, decide) },
            isBracketedPaste = { emulator.bracketedPaste }
        )

        terminalView.inputSink = { router.onInput(it) }
        terminalView.onGeometryChanged = { rows, cols -> session?.resize(rows, cols) }

        val newSession = TerminalSession(
            shellPath = env.shellPath,
            homeDir = env.home.absolutePath,
            tmpDir = env.tmp.absolutePath,
            emulator = emulator,
            onExit = { code ->
                emulator.append("\r\n[process exited with code $code]\r\n")
                terminalView.notifyScreenChanged()
            }
        )
        newSession.onScreenUpdated = { terminalView.notifyScreenChanged() }
        session = newSession

        try {
            newSession.start()
        } catch (_: Exception) {
            emulator.append("\r\n[failed to start shell]\r\n")
            terminalView.notifyScreenChanged()
        }
    }

    private fun buildLayout(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(0xFF141414.toInt())
        }

        titleView = TextView(this).apply {
            text = getString(R.string.app_name)
            setTextColor(0xFFA0A0A0.toInt())
            textSize = 12f
            setPadding(24, 16, 24, 16)
        }
        root.addView(
            titleView,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        )

        terminalView = TerminalView(this)
        root.addView(
            terminalView,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
        )

        root.addView(buildExtraKeys(), LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT))
        return root
    }

    /** The accessory key bar: Esc, Tab, Ctrl toggle, arrows, paste, import. */
    private fun buildExtraKeys(): View {
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val scroll = HorizontalScrollView(this).apply { addView(bar) }

        fun key(label: String, onTap: () -> Unit): Button =
            Button(this).apply {
                text = label
                textSize = 12f
                isAllCaps = false
                minWidth = 0
                minimumWidth = 0
                setPadding(28, 8, 28, 8)
                setOnClickListener { onTap() }
            }

        val ctrlBtn = key("Ctrl") {}
        ctrlBtn.setOnClickListener {
            val active = router.toggleCtrl()
            ctrlBtn.alpha = if (active) 1f else 0.6f
        }
        ctrlBtn.alpha = 0.6f

        bar.addView(key("Esc") { router.onInput("\u001B") })
        bar.addView(key("Tab") { router.onInput("\t") })
        bar.addView(ctrlBtn)
        bar.addView(key("◄") { session?.write("\u001B[D") })
        bar.addView(key("▲") { session?.write("\u001B[A") })
        bar.addView(key("▼") { session?.write("\u001B[B") })
        bar.addView(key("►") { session?.write("\u001B[C") })
        bar.addView(key("Paste") { pasteFromClipboard() })
        bar.addView(key("Import") { importPicker.launch(arrayOf("*/*")) })
        return scroll
    }

    private fun pasteFromClipboard() {
        val clip = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        val text = clip.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString() ?: return
        router.onPaste(text)
    }

    private fun confirmDialog(reason: String, line: String, decide: (Boolean) -> Unit) {
        AlertDialog.Builder(this)
            .setTitle("Potentially destructive command")
            .setMessage("$reason\n\nCommand:\n$line\n\nRun it anyway?")
            .setCancelable(false)
            .setPositiveButton("Run") { _, _ -> decide(true) }
            .setNegativeButton("Cancel") { _, _ -> decide(false) }
            .show()
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    override fun onDestroy() {
        super.onDestroy()
        session?.finish()
    }
}

/** Haptic helper kept off the hot render path. */
fun TerminalView.performHapticFeedbackSafe() {
    performHapticFeedback(android.view.HapticFeedbackConstants.KEYBOARD_TAP)
}
