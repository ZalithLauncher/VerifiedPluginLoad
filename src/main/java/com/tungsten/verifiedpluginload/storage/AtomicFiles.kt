package com.tungsten.verifiedpluginload.storage

import java.io.File
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

internal object AtomicFiles {
    fun readBounded(file: File, maxBytes: Int): ByteArray? {
        if (!file.isFile || file.length() !in 1..maxBytes.toLong()) return null
        return try {
            FileInputStream(file).use { input ->
                val output = ByteArrayOutputStream(file.length().toInt())
                val buffer = ByteArray(8_192)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size() + count > maxBytes) return null
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
        } catch (_: IOException) {
            null
        }
    }

    fun write(file: File, bytes: ByteArray) {
        val parent = file.parentFile ?: throw IOException("File has no parent directory")
        if (!parent.exists() && !parent.mkdirs()) throw IOException("Cannot create ${parent.absolutePath}")
        val temporary = File(parent, "${file.name}.write-tmp")
        FileOutputStream(temporary).use { output ->
            output.write(bytes)
            output.fd.sync()
        }
        moveReplace(temporary, file)
    }

    fun moveReplace(source: File, target: File) {
        try {
            Files.move(
                source.toPath(),
                target.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE
            )
        } catch (_: Exception) {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }

    fun deleteQuietly(file: File) {
        try {
            Files.deleteIfExists(file.toPath())
        } catch (_: IOException) {
        }
    }
}
