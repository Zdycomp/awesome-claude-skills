package com.zdycomp.secureterm.term

import java.io.File

/**
 * Locates a shell to run and prepares the per-app HOME/TMP directories.
 *
 * Least privilege / integrity notes:
 *  - We only ever exec a shell that ships with the OS in a system, read-only
 *    location (/system/bin/sh). We never download, unpack, or exec a shell
 *    binary from writable app storage — that would be a code-integrity hole
 *    (anything with write access to app data could replace the interpreter).
 *  - HOME and TMPDIR live in app-private storage (getFilesDir / cacheDir),
 *    created with default private permissions.
 */
object ShellBootstrap {

    private val CANDIDATE_SHELLS = listOf(
        "/system/bin/sh",
        "/system/bin/mksh",
        "/system/xbin/sh"
    )

    data class Env(val shellPath: String, val home: File, val tmp: File)

    fun prepare(filesDir: File, cacheDir: File): Env {
        val home = File(filesDir, "home").apply { mkdirs() }
        val tmp = File(cacheDir, "tmp").apply { mkdirs() }

        val shell = CANDIDATE_SHELLS.firstOrNull { path ->
            val f = File(path)
            // Must exist AND be in a system path we did not write to.
            f.canExecute() && (path.startsWith("/system/") )
        } ?: "/system/bin/sh"

        seedProfile(home)
        return Env(shell, home, tmp)
    }

    /** Write a minimal, safe default profile if none exists. */
    private fun seedProfile(home: File) {
        val profile = File(home, ".profile")
        if (!profile.exists()) {
            profile.writeText(
                """
                # SecureTerm default profile
                export PS1='secureterm:$ '
                alias ll='ls -la'
                echo "SecureTerm ready. This shell runs inside the app sandbox (uid=$(id -u))."
                echo "Type 'help' style commands as usual; destructive commands prompt first."
                """.trimIndent() + "\n"
            )
        }
    }
}
