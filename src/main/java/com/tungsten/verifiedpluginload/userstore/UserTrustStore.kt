package com.tungsten.verifiedpluginload.userstore

import android.util.Log
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.google.gson.stream.JsonWriter
import com.tungsten.verifiedpluginload.model.KeyHash
import com.tungsten.verifiedpluginload.model.UserTrustSnapshot
import com.tungsten.verifiedpluginload.model.normalizeUuid
import com.tungsten.verifiedpluginload.storage.AtomicFiles
import java.io.File
import java.io.StringReader
import java.io.StringWriter
import java.time.Instant

internal data class UserTrustData(
    val authorUuids: Set<String>,
    val keyHashes: Set<KeyHash>,
    val updatedAt: String
)

internal class UserTrustStore(private val directory: File) {
    private companion object {
        const val TAG = "VerifiedPluginLoad"
    }
    private val currentFile = File(directory, "user-trust.json")
    private val previousFile = File(directory, "user-trust.previous.json")
    private val temporaryFile = File(directory, "user-trust.json.tmp")
    private var recoveredFromCorruption = false

    fun load(): UserTrustData {
        read(currentFile)?.let { return it }
        if (currentFile.exists()) {
            recoveredFromCorruption = true
            Log.w(TAG, "Current user trust file is invalid; attempting recovery")
        }
        read(previousFile)?.let { previous ->
            Log.w(TAG, "Recovered user trust data from the previous valid snapshot")
            try {
                AtomicFiles.write(currentFile, serialize(previous).toByteArray(Charsets.UTF_8))
            } catch (e: Exception) {
                // The recovered in-memory snapshot remains safe even when the directory cannot be repaired.
                Log.w(TAG, "Could not repair the current user trust snapshot", e)
            }
            return previous
        }
        return UserTrustData(emptySet(), emptySet(), Instant.now().toString())
    }

    fun snapshot(): UserTrustSnapshot {
        val value = load()
        return UserTrustSnapshot(value.authorUuids, value.keyHashes, value.updatedAt, recoveredFromCorruption)
    }

    fun trustAuthor(uuid: String): UserTrustSnapshot = update { current ->
        current.copy(authorUuids = current.authorUuids + uuid, updatedAt = Instant.now().toString())
    }

    fun revokeAuthor(uuid: String): UserTrustSnapshot = update { current ->
        current.copy(authorUuids = current.authorUuids - uuid, updatedAt = Instant.now().toString())
    }

    fun trustKey(hash: KeyHash): UserTrustSnapshot = update { current ->
        current.copy(keyHashes = current.keyHashes + hash, updatedAt = Instant.now().toString())
    }

    fun revokeKey(hash: KeyHash): UserTrustSnapshot = update { current ->
        current.copy(keyHashes = current.keyHashes - hash, updatedAt = Instant.now().toString())
    }

    private fun update(transform: (UserTrustData) -> UserTrustData): UserTrustSnapshot {
        val current = load()
        val next = transform(current)
        if (!directory.exists() && !directory.mkdirs()) throw IllegalStateException("Cannot create VPL storage directory")
        AtomicFiles.deleteQuietly(temporaryFile)
        AtomicFiles.write(temporaryFile, serialize(next).toByteArray(Charsets.UTF_8))
        if (read(temporaryFile) == null) throw IllegalStateException("Cannot validate staged user trust file")
        if (read(currentFile) != null) AtomicFiles.moveReplace(currentFile, previousFile)
        AtomicFiles.moveReplace(temporaryFile, currentFile)
        return snapshot()
    }

    private fun read(file: File): UserTrustData? {
        val bytes = AtomicFiles.readBounded(file, 256 * 1024) ?: return null
        return try {
            JsonReader(StringReader(bytes.toString(Charsets.UTF_8))).use { reader ->
                reader.isLenient = false
                val result = parse(reader)
                if (reader.peek() != JsonToken.END_DOCUMENT) null else result
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun parse(reader: JsonReader): UserTrustData {
        if (reader.peek() != JsonToken.BEGIN_OBJECT) throw IllegalArgumentException("Expected object")
        var formatVersion: Long? = null
        var authors: Set<String>? = null
        var hashes: Set<KeyHash>? = null
        var updatedAt: String? = null
        val seen = HashSet<String>()
        reader.beginObject()
        while (reader.hasNext()) {
            when (val name = reader.nextName()) {
                "format_version" -> {
                    if (!seen.add(name)) throw IllegalArgumentException("Duplicate format_version")
                    formatVersion = readInteger(reader)
                }
                "trusted_author_uuids" -> {
                    if (!seen.add(name)) throw IllegalArgumentException("Duplicate trusted_author_uuids")
                    authors = readAuthors(reader)
                }
                "trusted_key_hashes" -> {
                    if (!seen.add(name)) throw IllegalArgumentException("Duplicate trusted_key_hashes")
                    hashes = readHashes(reader)
                }
                "updated_at" -> {
                    if (!seen.add(name)) throw IllegalArgumentException("Duplicate updated_at")
                    updatedAt = readTimestamp(reader)
                }
                else -> throw IllegalArgumentException("Unknown field $name")
            }
        }
        reader.endObject()
        if (formatVersion != 1L || authors == null || hashes == null || updatedAt == null) {
            throw IllegalArgumentException("Missing or unsupported user-trust fields")
        }
        return UserTrustData(authors, hashes, updatedAt)
    }

    private fun readAuthors(reader: JsonReader): Set<String> {
        if (reader.peek() != JsonToken.BEGIN_ARRAY) throw IllegalArgumentException("trusted_author_uuids must be an array")
        val result = LinkedHashSet<String>()
        reader.beginArray()
        while (reader.hasNext()) {
            if (result.size >= 2_048 || reader.peek() != JsonToken.STRING) throw IllegalArgumentException("Invalid author UUID")
            val value = reader.nextString()
            val normalized = normalizeUuid(value) ?: throw IllegalArgumentException("Invalid author UUID")
            if (value != normalized || !result.add(value)) throw IllegalArgumentException("Duplicate or noncanonical author UUID")
        }
        reader.endArray()
        return result
    }

    private fun readHashes(reader: JsonReader): Set<KeyHash> {
        if (reader.peek() != JsonToken.BEGIN_ARRAY) throw IllegalArgumentException("trusted_key_hashes must be an array")
        val result = LinkedHashSet<KeyHash>()
        reader.beginArray()
        while (reader.hasNext()) {
            if (result.size >= 4_096 || reader.peek() != JsonToken.STRING) throw IllegalArgumentException("Invalid key hash")
            val value = reader.nextString()
            val hash = KeyHash.parseCanonical(value) ?: throw IllegalArgumentException("Invalid key hash")
            if (!result.add(hash)) throw IllegalArgumentException("Duplicate key hash")
        }
        reader.endArray()
        return result
    }

    private fun readInteger(reader: JsonReader): Long {
        if (reader.peek() != JsonToken.NUMBER) throw IllegalArgumentException("Expected integer")
        val raw = reader.nextString()
        if (!Regex("0|[1-9][0-9]*").matches(raw)) throw IllegalArgumentException("Invalid integer")
        return raw.toLongOrNull() ?: throw IllegalArgumentException("Integer out of range")
    }

    private fun readTimestamp(reader: JsonReader): String {
        if (reader.peek() != JsonToken.STRING) throw IllegalArgumentException("updated_at must be a string")
        val value = reader.nextString()
        Instant.parse(value)
        return value
    }

    private fun serialize(data: UserTrustData): String = StringWriter().use { out ->
        JsonWriter(out).use { writer ->
            writer.beginObject()
            writer.name("format_version").value(1)
            writer.name("trusted_author_uuids").beginArray()
            data.authorUuids.sorted().forEach(writer::value)
            writer.endArray()
            writer.name("trusted_key_hashes").beginArray()
            data.keyHashes.map(KeyHash::value).sorted().forEach(writer::value)
            writer.endArray()
            writer.name("updated_at").value(data.updatedAt)
            writer.endObject()
        }
        out.toString()
    }
}
