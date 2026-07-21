package com.zdycomp.secureterm.security

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import java.io.File
import java.io.IOException

/**
 * Bridges user-chosen external folders into the sandbox WITHOUT holding any
 * storage permission.
 *
 * How it stays least-privilege:
 *  - Access is granted per-tree by the user through the system folder
 *    picker (Storage Access Framework). The app requests no
 *    READ/WRITE_EXTERNAL_STORAGE permission at all.
 *  - The granted URI permission is persisted so it survives restarts, but
 *    the user can revoke it any time from system settings.
 *  - Import/export copies files into/out of the sandbox home explicitly.
 *    The shell never operates directly on the external tree, so a runaway
 *    command cannot traverse the user's whole SD card — only the single
 *    file the user chose to import.
 *  - Destination paths are canonicalized and confirmed to stay within the
 *    sandbox home before any write (path-traversal defense).
 */
class StorageBridge(private val homeDir: File) {

    /** Build the intent that opens the system folder picker. */
    fun openTreeIntent(): Intent =
        Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                        Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                        Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
            )
        }

    fun persistPermission(resolver: ContentResolver, uri: Uri) {
        resolver.takePersistableUriPermission(
            uri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        )
    }

    /**
     * Copy one document from the granted tree into the sandbox home.
     * @return the sandbox path written, or null if the copy was refused.
     */
    @Throws(IOException::class)
    fun importInto(
        resolver: ContentResolver,
        source: Uri,
        context: android.content.Context,
        subdir: String = "imported"
    ): String? {
        val docName = DocumentFile.fromSingleUri(context, source)?.name
        val name = sanitizeName(docName ?: queryName(resolver, source) ?: "import.bin")
        val destDir = File(homeDir, sanitizeName(subdir)).apply { mkdirs() }
        val dest = File(destDir, name)

        // Path-traversal guard: the resolved destination must remain inside home.
        val canonicalHome = homeDir.canonicalPath
        if (!dest.canonicalPath.startsWith(canonicalHome + File.separator)) {
            return null
        }

        resolver.openInputStream(source)?.use { input ->
            dest.outputStream().use { output ->
                val buf = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    // Hard cap: a single import cannot exceed 512 MiB, so a
                    // huge file can't silently fill the sandbox.
                    if (total > 512L * 1024 * 1024) {
                        output.flush()
                        dest.delete()
                        throw IOException("import exceeds size limit")
                    }
                    output.write(buf, 0, n)
                }
            }
        } ?: return null
        return dest.absolutePath
    }

    private fun queryName(resolver: ContentResolver, uri: Uri): String? =
        resolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        }

    /** Strip any path separators / traversal tokens from a filename. */
    private fun sanitizeName(raw: String): String {
        val base = raw.substringAfterLast('/').substringAfterLast('\\')
        val cleaned = base.filter { it.isLetterOrDigit() || it in "._- " }.trim().take(200)
        return cleaned.ifEmpty { "file" }
    }
}
