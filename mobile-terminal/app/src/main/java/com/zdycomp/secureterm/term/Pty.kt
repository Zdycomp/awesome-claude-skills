package com.zdycomp.secureterm.term

import java.io.IOException

/**
 * JNI bindings to the hardened PTY launcher (termexec.c).
 *
 * All argument validation is duplicated on the native side; these wrappers
 * exist so callers get typed, non-leaky failures instead of raw errno.
 */
object Pty {
    init {
        System.loadLibrary("termexec")
    }

    /**
     * Fork a child on a fresh pseudo-terminal.
     *
     * @param pidOut single-element array receiving the child pid.
     * @return the PTY master file descriptor.
     * @throws IOException with a generic message on any failure — no system
     *         details are ever propagated to the UI.
     */
    @Throws(IOException::class)
    external fun createSubprocess(
        cmd: String,
        cwd: String,
        args: Array<String>,
        env: Array<String>,
        rows: Int,
        cols: Int,
        pidOut: IntArray
    ): Int

    external fun setWindowSize(fd: Int, rows: Int, cols: Int)

    /** Blocks until the child exits; returns exit code (128+signal if killed). */
    external fun waitFor(pid: Int): Int

    /** Sends SIGHUP to the child only (native side refuses pid <= 0). */
    external fun hangup(pid: Int)

    external fun closeFd(fd: Int)
}
