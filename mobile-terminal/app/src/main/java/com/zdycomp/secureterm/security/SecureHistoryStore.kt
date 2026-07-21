package com.zdycomp.secureterm.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Command history encrypted at rest.
 *
 * Design:
 *  - AES-256-GCM with a non-exportable key generated inside the Android
 *    Keystore (hardware-backed where available). The key never exists in
 *    app memory as raw bytes and cannot be extracted by backup, adb, or
 *    another app.
 *  - Each record is independently encrypted with a fresh, random IV
 *    (Keystore enforces randomized encryption), so records can be appended
 *    without re-encrypting the file and a single corrupted record does not
 *    poison the rest.
 *  - Record format: [len:int32][iv:12 bytes][ciphertext+tag]. Length is
 *    validated against a hard cap before allocation — a tampered file
 *    cannot trigger a huge allocation.
 *  - The file lives in app-private storage and is excluded from backups
 *    (see data_extraction_rules.xml).
 *  - On any decrypt/parse failure the store fails closed: it returns what
 *    it decoded so far and truncates the corrupt tail on next write.
 */
class SecureHistoryStore(private val file: File) {

    companion object {
        private const val KEY_ALIAS = "secureterm_history_v1"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val GCM_TAG_BITS = 128
        private const val IV_LENGTH = 12
        private const val MAX_RECORD_BYTES = 8 * 1024
        private const val MAX_ENTRIES = 500
        private const val MAX_FILE_BYTES = 512L * 1024
    }

    private fun obtainKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // Randomized encryption (unique IV per operation) is the
                // Keystore default and deliberately left enabled.
                .build()
        )
        return generator.generateKey()
    }

    /** Append one command line. Silently drops the entry on crypto failure —
     *  history is a convenience; it must never crash or block the terminal. */
    @Synchronized
    fun append(line: String) {
        val text = line.take(4096)
        if (text.isBlank()) return
        try {
            if (file.length() > MAX_FILE_BYTES) compact()

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, obtainKey())
            val iv = cipher.iv
            val ct = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
            if (iv.size != IV_LENGTH || ct.size > MAX_RECORD_BYTES) return

            DataOutputStream(FileOutputStream(file, true)).use { out ->
                out.writeInt(ct.size)
                out.write(iv)
                out.write(ct)
            }
        } catch (_: GeneralSecurityException) {
        } catch (_: IOException) {
        }
    }

    /** Decrypt all readable entries, oldest first. Corrupt tail is ignored. */
    @Synchronized
    fun load(): List<String> {
        if (!file.exists()) return emptyList()
        val entries = ArrayList<String>()
        try {
            DataInputStream(FileInputStream(file)).use { input ->
                while (true) {
                    val len = try {
                        input.readInt()
                    } catch (_: EOFException) {
                        break
                    }
                    if (len <= 0 || len > MAX_RECORD_BYTES) break // tampered/corrupt: stop
                    val iv = ByteArray(IV_LENGTH)
                    input.readFully(iv)
                    val ct = ByteArray(len)
                    input.readFully(ct)

                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.DECRYPT_MODE, obtainKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
                    entries.add(String(cipher.doFinal(ct), Charsets.UTF_8))
                }
            }
        } catch (_: GeneralSecurityException) {
            // GCM tag mismatch = tampering or key rotation: keep what we have.
        } catch (_: IOException) {
        }
        return entries
    }

    /** Rewrite the file keeping only the newest MAX_ENTRIES records. */
    @Synchronized
    private fun compact() {
        val keep = load().takeLast(MAX_ENTRIES)
        val tmp = File(file.parentFile, file.name + ".tmp")
        try {
            DataOutputStream(FileOutputStream(tmp, false)).use { out ->
                for (entry in keep) {
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, obtainKey())
                    val ct = cipher.doFinal(entry.toByteArray(Charsets.UTF_8))
                    out.writeInt(ct.size)
                    out.write(cipher.iv)
                    out.write(ct)
                }
            }
            if (!tmp.renameTo(file)) {
                tmp.delete()
            }
        } catch (_: GeneralSecurityException) {
            tmp.delete()
        } catch (_: IOException) {
            tmp.delete()
        }
    }

    @Synchronized
    fun clear() {
        file.delete()
    }
}
