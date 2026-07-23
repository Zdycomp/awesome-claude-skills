package com.zdycomp.secureterm.term

import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns one shell process on one PTY.
 *
 * Security notes:
 *  - The child environment is built here, explicitly and minimally. The
 *    app process's own environment (which can carry runtime internals) is
 *    never inherited by the shell.
 *  - PTY output is decoded with a REPLACE-on-malformed UTF-8 decoder:
 *    hostile byte sequences become U+FFFD instead of exceptions or mojibake
 *    state confusion.
 *  - Writes go through a bounded queue (drop-on-full) so a wedged child
 *    can never block the UI thread or grow memory without bound.
 *  - Failure messages surfaced to the UI are generic; no paths, errno or
 *    stack traces leak to screen.
 */
class TerminalSession(
    private val shellPath: String,
    private val homeDir: String,
    private val tmpDir: String,
    val emulator: TerminalEmulator,
    private val onExit: (Int) -> Unit
) {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val running = AtomicBoolean(false)

    private var masterFd = -1
    private var pid = -1
    private var pfd: ParcelFileDescriptor? = null
    private var output: FileOutputStream? = null

    private val writeQueue = ArrayBlockingQueue<ByteArray>(1024)

    /** Fires on the main thread after every chunk is applied to the emulator. */
    var onScreenUpdated: (() -> Unit)? = null

    @Throws(IOException::class)
    fun start() {
        check(!running.get()) { "session already started" }

        val pidOut = IntArray(1)
        // Minimal, explicit environment — least privilege for the child.
        val env = arrayOf(
            "HOME=$homeDir",
            "TMPDIR=$tmpDir",
            "PATH=/system/bin:/system/xbin",
            "TERM=xterm-256color",
            "LANG=en_US.UTF-8",
            "ANDROID_ROOT=/system",
            "ANDROID_DATA=/data"
        )
        masterFd = Pty.createSubprocess(
            shellPath, homeDir,
            arrayOf("sh"), env,
            emulator.rows, emulator.cols,
            pidOut
        )
        pid = pidOut[0]
        running.set(true)

        // adoptFd takes ownership of the raw fd through a public API —
        // no hidden-API reflection, and exactly one owner of the descriptor.
        val fd = ParcelFileDescriptor.adoptFd(masterFd)
        pfd = fd
        val input = FileInputStream(fd.fileDescriptor)
        output = FileOutputStream(fd.fileDescriptor)

        Thread({ readLoop(input) }, "term-reader").start()
        Thread({ writeLoop() }, "term-writer").start()
        Thread({
            val code = Pty.waitFor(pid)
            running.set(false)
            mainHandler.post { onExit(code) }
        }, "term-waiter").start()
    }

    private fun readLoop(input: FileInputStream) {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE)
        val byteBuf = ByteBuffer.allocate(8192)
        val charBuf = CharBuffer.allocate(8192)
        val raw = ByteArray(4096)
        try {
            while (true) {
                val n = input.read(raw)
                if (n < 0) break
                var off = 0
                while (off < n) {
                    val take = minOf(n - off, byteBuf.remaining())
                    byteBuf.put(raw, off, take)
                    off += take
                    byteBuf.flip()
                    decoder.decode(byteBuf, charBuf, false)
                    byteBuf.compact()
                    charBuf.flip()
                    if (charBuf.hasRemaining()) {
                        val text = charBuf.toString()
                        mainHandler.post {
                            emulator.append(text)
                            onScreenUpdated?.invoke()
                        }
                    }
                    charBuf.clear()
                }
            }
        } catch (_: IOException) {
            // PTY closed (child exited or session finished): normal teardown.
        }
        // Deliberately not closed here: the ParcelFileDescriptor is the sole
        // owner of the fd (see finish()). Closing the stream too would double-
        // close a descriptor number the OS may have already reused.
    }

    private fun writeLoop() {
        try {
            while (running.get() || writeQueue.isNotEmpty()) {
                val chunk = writeQueue.poll(250, TimeUnit.MILLISECONDS) ?: continue
                output?.let {
                    it.write(chunk)
                    it.flush()
                }
            }
        } catch (_: IOException) {
            running.set(false)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    /** Queue bytes for the child. Drops (with no crash) if the child is wedged. */
    fun write(data: String) {
        if (!running.get()) return
        writeQueue.offer(data.toByteArray(Charsets.UTF_8))
    }

    fun resize(rows: Int, cols: Int) {
        emulator.resize(rows, cols)
        if (running.get() && masterFd >= 0) {
            Pty.setWindowSize(masterFd, emulator.rows, emulator.cols)
        }
    }

    val isRunning: Boolean get() = running.get()

    /** SIGHUP the child and release the PTY. Idempotent. */
    fun finish() {
        if (pid > 0) Pty.hangup(pid)
        running.set(false)
        try {
            pfd?.close()
        } catch (_: IOException) {
        }
        pfd = null
        masterFd = -1
    }
}
