package com.zdycomp.secureterm.security

/**
 * Best-effort detection of destructive command lines before they are sent
 * to the shell.
 *
 * Honest scope statement: this is a *seatbelt against accidents*, not a
 * sandbox. The real security boundary is the Android app sandbox — even a
 * command that evades these patterns can only damage the app's own private
 * data, never the OS or other apps. The guard exists so a typo'd
 * `rm -rf ~` gets a confirmation dialog instead of instantly wiping the
 * sandbox home.
 *
 * Matching is done on a tokenized copy of the line; the line itself is
 * never modified or interpreted here.
 */
object CommandGuard {

    /** Reason a line was flagged, phrased for the confirmation dialog. */
    data class Verdict(val dangerous: Boolean, val reason: String = "")

    private val FORK_BOMB = Regex("""\(\)\s*\{[^}]*\|[^}]*&[^}]*\}""")
    private val KILL_ALL = Regex("""\bkill\s+(-\w+\s+)?-1\b""")

    private val WIPE_TARGETS = setOf("/", "/*", "~", "~/", "~/*", "\$HOME", "\$HOME/", "\$HOME/*", "*", ".*")

    fun check(line: String): Verdict {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.length > 4096) {
            // Over-long lines are refused outright rather than scanned:
            // guarantees bounded work per keystroke.
            return if (trimmed.length > 4096)
                Verdict(true, "Command exceeds the 4096-character safety limit.")
            else Verdict(false)
        }

        if (FORK_BOMB.containsMatchIn(trimmed)) {
            return Verdict(true, "This looks like a fork bomb (self-replicating background function).")
        }
        if (KILL_ALL.containsMatchIn(trimmed)) {
            return Verdict(true, "kill -1 signals every process this app owns, including the terminal itself.")
        }

        // Evaluate each simple command in the pipeline/list independently.
        for (segment in trimmed.split(';', '|', '&')) {
            val tokens = segment.trim().split(Regex("""\s+""")).filter { it.isNotEmpty() }
            if (tokens.isEmpty()) continue
            val cmd = tokens[0].substringAfterLast('/')

            when (cmd) {
                "rm" -> {
                    val flags = tokens.drop(1).filter { it.startsWith("-") }.joinToString("")
                    val recursive = flags.contains('r') || flags.contains('R')
                    val forced = flags.contains('f')
                    val targets = tokens.drop(1).filter { !it.startsWith("-") }
                    if ((recursive || forced) && targets.any { it in WIPE_TARGETS }) {
                        return Verdict(
                            true,
                            "rm with ${if (recursive) "recursive" else "force"} flags targets " +
                                    "your entire home or filesystem root."
                        )
                    }
                }
                "mkfs", "mkfs.ext4", "mkfs.vfat", "mke2fs" ->
                    return Verdict(true, "Filesystem formatting commands are destructive by definition.")
                "dd" -> {
                    if (tokens.any { it.startsWith("of=/dev/") }) {
                        return Verdict(true, "dd writing directly to a device node can destroy data.")
                    }
                }
                "chmod", "chown" -> {
                    val recursive = tokens.any { it == "-R" || it == "-r" }
                    if (recursive && tokens.any { it in WIPE_TARGETS }) {
                        return Verdict(
                            true,
                            "Recursive permission change over home/root can make everything inaccessible."
                        )
                    }
                }
            }

            // Redirection straight into a block device.
            if (segment.contains(Regex(""">\s*/dev/block/"""))) {
                return Verdict(true, "Redirecting output into a block device can destroy data.")
            }
        }
        return Verdict(false)
    }
}
