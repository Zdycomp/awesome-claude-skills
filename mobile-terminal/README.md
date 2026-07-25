# SecureTerm — a hardened, sandbox-respecting mobile terminal for Android

SecureTerm is a native Android terminal emulator that runs a real shell
**inside the app's own sandbox** — no root, no privilege escalation, no
attempt to break Android's security model. It is designed the way Termux
operates on a stock, non-rooted device: everything the shell can touch is
either app-private storage or a folder you explicitly hand it through the
system file picker.

It was built to a strict secure-by-design brief: input is never trusted,
memory is handled safely, errors never leak internals, and the app holds
the **absolute minimum** privilege (in fact, **zero** Android permissions).

---

## The security boundary (read this first)

The real, load-bearing security boundary is **the Android application
sandbox** — per-app UID isolation plus SELinux (`untrusted_app` domain).
Every process this app starts runs as the app's own unprivileged UID.
That means:

- The shell **cannot** read another app's data, the system partition is
  read-only to it, and it has no special device access.
- Worst realistic case for a hostile or mistaken command is damage to
  **this app's own private files** — which you can wipe by clearing app
  data or reinstalling.

Everything else in this project (the destructive-command guard, the escape
sequence limits, the encrypted history) is **defense in depth layered on
top of that boundary** — seatbelts against accidents and against hostile
*content* (a booby-trapped file you `cat`, a malicious clipboard paste).
None of it is claimed to contain a determined attacker who already has code
execution; the OS sandbox is what does that. This honesty is deliberate:
overstating a guarantee is itself a security anti-pattern.

There is **no code here that attempts to gain root, defeat SELinux, or
escape the sandbox**, by design.

---

## Architecture

```
┌──────────────────────────────────────────────┐
│  MainActivity  (only exported component;       │
│  accepts no data-bearing intents)              │
└───────┬───────────────────────┬────────────────┘
        │ raw chars              │ screen state
┌───────▼────────┐      ┌────────▼───────────────┐
│  InputRouter    │      │  TerminalView (render, │
│  (security)     │      │  gestures, IME, keys)  │
│  - shadow line  │      └────────┬───────────────┘
│  - CommandGuard │               │ append(text)
│  - paste vetting│      ┌────────▼───────────────┐
└───────┬────────┘      │  TerminalEmulator       │
        │ vetted bytes   │  (bounded VT100 parser) │
        │                └────────┬───────────────┘
┌───────▼─────────────────────────▼──────────────┐
│           TerminalSession                        │
│  (env construction, UTF-8 decode, bounded        │
│   write queue, lifecycle)                        │
└───────┬──────────────────────────────────────────┘
        │ JNI
┌───────▼──────────────────────────────────────────┐
│  Pty  ->  termexec.c  (forkpty, rlimits, fd       │
│  hygiene, explicit env, generic errors)           │
└───────────────────────────────────────────────────┘

Side modules:
  SecureHistoryStore  — AES-256-GCM, Android Keystore key, encrypted at rest
  StorageBridge       — Storage Access Framework import, path-traversal safe
  ShellBootstrap      — only ever execs /system shell (read-only, integrity)
```

### Module responsibilities

| Module | Responsibility | Key defenses |
|---|---|---|
| `termexec.c` / `Pty` | Fork the shell on a PTY | `rlimit` caps (no core dumps, ≤512 fds, ≤256 procs, ≤16 GiB file), close all inherited fds >stderr, reset signals, explicit `execve` env, generic `IOException` only |
| `TerminalSession` | Own one shell process | Minimal explicit environment (never inherits app env), REPLACE-on-malformed UTF-8 decoder, bounded drop-on-full write queue, single fd owner |
| `TerminalEmulator` | Parse output into a screen | Strict state machine; hard caps on params (16), param value (9999), OSC length (2048), title (128), scrollback (2000 lines); **no OSC 52 clipboard write, no mouse reporting, no answerback** |
| `TerminalView` | Render + input | `TYPE_NULL` IME (no silent autocorrect rewrites), one-way input, reads state on main thread only |
| `InputRouter` | Gate input | Shadow-line tracking, `CommandGuard` vetting at Enter, kill-line on refusal, control-char stripping on paste |
| `CommandGuard` | Flag destructive lines | Bounded tokenized scan for `rm -rf /|~`, fork bombs, `mkfs`, `dd of=/dev/*`, recursive chmod/chown on root, block-device redirects |
| `SecureHistoryStore` | Persist history | AES-256-GCM, non-exportable Keystore key, per-record random IV, length-capped records, fail-closed on tamper |
| `StorageBridge` | External file exchange | SAF (no storage permission), filename sanitization, path-traversal check, 512 MiB import cap |
| `ShellBootstrap` | Prepare runtime | Execs only a read-only `/system` shell — never a binary from writable storage |

---

## Threat model

| # | Attacker goal | Vector | Defense in this codebase |
|---|---|---|---|
| 1 | Escape sandbox / get root | Abuse exec path | No escalation code exists; child runs at app UID under SELinux; only `/system` shell is executed; no setuid, no capabilities |
| 2 | Command injection via *our* code | String-built command lines | The launcher uses `execve(argv[])` arrays — never shell-string concatenation. Nothing we construct is passed through a shell interpreter |
| 3 | Escape-sequence exploitation | Booby-trapped file output / program output containing ANSI/OSC | Bounded parser; unimplemented/oversized sequences dropped; **no clipboard-write, title-only OSC stripped of control chars, no synthetic input** |
| 4 | Malicious clipboard paste | Hidden control chars / newlines auto-executing | Paste stripped to printable+`\n\t`, vetted line-by-line by `CommandGuard`, bracketed-paste honored so the shell treats it as literal text |
| 5 | Resource exhaustion / DoS | Fork bomb, runaway output, huge writes | `rlimit` NPROC/NOFILE/FSIZE in child; capped scrollback; bounded write queue drops instead of OOM; fork-bomb pattern prompts first |
| 6 | Data exfiltration at rest | Another app / backup reads history | AES-256-GCM with hardware-backed non-exportable Keystore key; excluded from cloud backup and device transfer |
| 7 | Data exfiltration over network | Shell phones home | App declares **no `INTERNET` permission** — the process cannot open a socket to the internet |
| 8 | IPC command injection | Another app sends an Intent | All components non-exported except launcher; launcher accepts only `MAIN`/`LAUNCHER`, no data URIs |
| 9 | Path traversal on import | `../../` in a chosen filename | Filenames sanitized (separators stripped), destination canonicalized and confirmed inside sandbox home |
| 10 | Info leak via errors | errno / paths / stack traces on screen | Native layer throws only generic messages; Kotlin catches are silent or generic; nothing internal is surfaced |
| 11 | Accidental self-destruction | Typo'd `rm -rf ~` | `CommandGuard` prompts before send and kill-lines on refusal (accident seatbelt, per boundary note above) |

---

## Building

There is **no Gradle wrapper committed** (the wrapper `.jar` can't be
generated without the Android SDK present, and shipping a broken one is
worse than none). Build one of two ways:

### Option 0 — Let GitHub build it for you (no local setup)

A CI workflow (`.github/workflows/secureterm-android.yml`) builds the APK on
every push that touches `mobile-terminal/`. To get an installable APK:

1. Push to (or open a PR against) this branch — or trigger it manually:
   GitHub → **Actions** tab → **Build SecureTerm APK** → **Run workflow**.
2. Open the finished run and download the **`secureterm-debug-apk`** artifact
   (a zip containing `app-debug.apk`).
3. Copy the APK to your phone, tap it, and allow "install from unknown
   sources" when prompted. Done — no SDK, NDK, or Android Studio on your side.

### Option A — Android Studio (recommended for development)
1. Open the `mobile-terminal/` folder in Android Studio (Ladybug / AGP 8.7+).
2. Let it sync — it will generate the Gradle wrapper and prompt to install
   the matching **SDK 35**, **NDK**, and **CMake** if missing.
3. Run on a device or emulator (min SDK 26, Android 8.0+).

### Option B — command line
Requires: JDK 17, Android SDK 35, NDK, CMake, and Gradle 8.7+.
```bash
cd mobile-terminal
echo "sdk.dir=/path/to/Android/sdk" > local.properties
gradle assembleDebug        # or: gradle wrapper && ./gradlew assembleDebug
# output: app/build/outputs/apk/debug/app-debug.apk
```
Install the sideloaded APK: `adb install app/build/outputs/apk/debug/app-debug.apk`.

---

## Deliberate non-features (and why)

- **No OSC 52 clipboard write** — a classic escape-sequence exfiltration
  channel; a file you `cat` could otherwise silently overwrite your clipboard.
- **No mouse reporting** — avoids a program synthesizing input events.
- **No network permission** — removes the exfiltration channel entirely.
- **No download-and-exec package manager** — running an interpreter fetched
  into writable storage is a code-integrity hole. If added later, it must
  verify signatures/checksums over HTTPS before anything is executed.

---

## Status

All five planned phases are implemented with complete, non-placeholder
logic: terminal UI, PTY process execution, resource-guard hardening,
SAF storage bridge, and encrypted session history. Native C
syntax-verified with `-Wall -Wextra`. Requires the Android SDK/NDK to
compile to an APK (see Building).
