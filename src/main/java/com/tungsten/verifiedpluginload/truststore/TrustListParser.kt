package com.tungsten.verifiedpluginload.truststore

import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.tungsten.verifiedpluginload.model.AuthorType
import com.tungsten.verifiedpluginload.model.KeyHash
import com.tungsten.verifiedpluginload.model.KeyState
import com.tungsten.verifiedpluginload.model.TrustedAuthorInfo
import com.tungsten.verifiedpluginload.model.normalizeUuid
import java.io.StringReader
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.time.Instant

internal data class TrustKey(
    val hash: KeyHash,
    val state: KeyState,
    val description: String?,
    val bannedAt: String?
)

internal data class TrustAuthor(
    val info: TrustedAuthorInfo,
    val hashes: List<TrustKey>
)

internal data class TrustList(
    val listVersion: Long,
    val generatedAt: String,
    val expiresAt: String,
    val authors: List<TrustAuthor>
) {
    private val keysByHash: Map<KeyHash, Pair<TrustAuthor, TrustKey>> = authors
        .flatMap { author -> author.hashes.map { key -> key.hash to (author to key) } }
        .toMap()

    fun find(hash: KeyHash): Pair<TrustAuthor, TrustKey>? = keysByHash[hash]

    fun activeAuthor(authorUuid: String): TrustAuthor? = authors.firstOrNull { it.info.uuid == authorUuid }
}

internal class TrustListParseException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Strict schema parser. Unknown or duplicate fields are rejected to avoid ambiguous trust data. */
internal object TrustListParser {
    private const val MAX_LIST_BYTES = 4_194_304
    private const val MAX_AUTHORS = 2_048
    private const val MAX_KEYS_PER_AUTHOR = 128
    private const val MAX_STRING = 4_096

    fun parse(bytes: ByteArray, maxBytes: Int = MAX_LIST_BYTES): TrustList {
        if (maxBytes !in 1..MAX_LIST_BYTES || bytes.isEmpty() || bytes.size > maxBytes) {
            throw TrustListParseException("Trust list has an invalid size")
        }
        val text = decodeUtf8(bytes)
        try {
            JsonReader(StringReader(text)).use { reader ->
                reader.isLenient = false
                val list = readRoot(reader)
                if (reader.peek() != JsonToken.END_DOCUMENT) {
                    throw TrustListParseException("Trailing JSON data")
                }
                return list
            }
        } catch (e: TrustListParseException) {
            throw e
        } catch (e: Exception) {
            throw TrustListParseException("Invalid trust-list JSON", e)
        }
    }

    private fun readRoot(reader: JsonReader): TrustList {
        var formatVersion: Long? = null
        var listVersion: Long? = null
        var generatedAt: String? = null
        var expiresAt: String? = null
        var authors: List<TrustAuthor>? = null
        readObject(reader, setOf("format_version", "list_version", "generated_at", "expires_at", "keys")) { name ->
            when (name) {
                "format_version" -> formatVersion = readPositiveInteger(reader, name)
                "list_version" -> listVersion = readPositiveInteger(reader, name)
                "generated_at" -> generatedAt = readTimestamp(reader, name)
                "expires_at" -> expiresAt = readTimestamp(reader, name)
                "keys" -> authors = readAuthors(reader)
            }
        }
        if (formatVersion != 1L) throw TrustListParseException("Unsupported format_version")
        val version = listVersion ?: throw TrustListParseException("Missing list_version")
        val generated = generatedAt ?: throw TrustListParseException("Missing generated_at")
        val expires = expiresAt ?: throw TrustListParseException("Missing expires_at")
        if (Instant.parse(expires).isBefore(Instant.parse(generated))) {
            throw TrustListParseException("expires_at precedes generated_at")
        }
        return TrustList(version, generated, expires, authors ?: throw TrustListParseException("Missing keys"))
    }

    private fun readAuthors(reader: JsonReader): List<TrustAuthor> {
        requireToken(reader, JsonToken.BEGIN_ARRAY, "keys must be an array")
        val result = ArrayList<TrustAuthor>()
        val uuids = HashSet<String>()
        val hashes = HashSet<KeyHash>()
        reader.beginArray()
        while (reader.hasNext()) {
            if (result.size >= MAX_AUTHORS) throw TrustListParseException("Too many authors")
            val author = readAuthor(reader)
            if (!uuids.add(author.info.uuid)) throw TrustListParseException("Duplicate author UUID")
            author.hashes.forEach { key ->
                if (!hashes.add(key.hash)) throw TrustListParseException("Duplicate certificate hash")
            }
            result += author
        }
        reader.endArray()
        return result
    }

    private fun readAuthor(reader: JsonReader): TrustAuthor {
        var uuid: String? = null
        var name: String? = null
        var type: AuthorType? = null
        var confidence: Long? = null
        var description: String? = null
        var web: String? = null
        var hashes: List<TrustKey>? = null
        readObject(reader, setOf("uuid", "name", "type", "confidence", "description", "web", "hashes")) { field ->
            when (field) {
                "uuid" -> uuid = readUuid(reader)
                "name" -> name = readString(reader, field, 256)
                "type" -> type = when (readString(reader, field, 16)) {
                    "person" -> AuthorType.PERSON
                    "org" -> AuthorType.ORG
                    else -> throw TrustListParseException("Invalid author type")
                }
                "confidence" -> confidence = readNonNegativeInteger(reader, field)
                "description" -> description = readNullableString(reader, field, MAX_STRING)
                "web" -> web = readNullableWebUrl(reader)
                "hashes" -> hashes = readHashes(reader)
            }
        }
        val confidenceValue = confidence ?: throw TrustListParseException("Missing confidence")
        if (confidenceValue !in 0L..2L) throw TrustListParseException("Invalid confidence")
        return TrustAuthor(
            TrustedAuthorInfo(
                uuid = uuid ?: throw TrustListParseException("Missing uuid"),
                name = name ?: throw TrustListParseException("Missing name"),
                type = type ?: throw TrustListParseException("Missing type"),
                confidence = confidenceValue.toInt(),
                description = description,
                web = web
            ),
            hashes ?: throw TrustListParseException("Missing hashes")
        )
    }

    private fun readHashes(reader: JsonReader): List<TrustKey> {
        requireToken(reader, JsonToken.BEGIN_ARRAY, "hashes must be an array")
        val result = ArrayList<TrustKey>()
        val seen = HashSet<KeyHash>()
        reader.beginArray()
        while (reader.hasNext()) {
            if (result.size >= MAX_KEYS_PER_AUTHOR) throw TrustListParseException("Too many certificate hashes")
            val key = readHash(reader)
            if (!seen.add(key.hash)) throw TrustListParseException("Duplicate certificate hash")
            result += key
        }
        reader.endArray()
        if (result.isEmpty()) throw TrustListParseException("An author must declare at least one certificate hash")
        return result
    }

    private fun readHash(reader: JsonReader): TrustKey {
        var value: KeyHash? = null
        var state: KeyState? = null
        var description: String? = null
        var bannedAt: String? = null
        readObject(reader, setOf("value", "state", "description", "banned_at")) { field ->
            when (field) {
                "value" -> {
                    val raw = readString(reader, field, 256)
                    value = KeyHash.parseCanonical(raw)
                        ?: throw TrustListParseException("Certificate hash is not canonical")
                }
                "state" -> state = when (readString(reader, field, 16)) {
                    "active" -> KeyState.ACTIVE
                    "banned" -> KeyState.BANNED
                    else -> throw TrustListParseException("Invalid certificate state")
                }
                "description" -> description = readNullableString(reader, field, MAX_STRING)
                "banned_at" -> bannedAt = readNullableTimestamp(reader, field)
            }
        }
        val keyState = state ?: throw TrustListParseException("Missing certificate state")
        if (keyState == KeyState.ACTIVE && bannedAt != null) {
            throw TrustListParseException("active certificate cannot include banned_at")
        }
        return TrustKey(
            value ?: throw TrustListParseException("Missing certificate value"),
            keyState,
            description,
            bannedAt
        )
    }

    private fun readObject(reader: JsonReader, allowed: Set<String>, readField: (String) -> Unit) {
        requireToken(reader, JsonToken.BEGIN_OBJECT, "Expected object")
        val seen = HashSet<String>()
        reader.beginObject()
        while (reader.hasNext()) {
            val name = reader.nextName()
            if (name !in allowed) throw TrustListParseException("Unknown field: $name")
            if (!seen.add(name)) throw TrustListParseException("Duplicate field: $name")
            readField(name)
        }
        reader.endObject()
    }

    private fun readUuid(reader: JsonReader): String {
        val raw = readString(reader, "uuid", 64)
        val normalized = normalizeUuid(raw) ?: throw TrustListParseException("Invalid UUID")
        if (raw != normalized) throw TrustListParseException("UUID must be canonical lowercase")
        return normalized
    }

    private fun readTimestamp(reader: JsonReader, field: String): String {
        val value = readString(reader, field, 64)
        return try {
            Instant.parse(value)
            value
        } catch (e: Exception) {
            throw TrustListParseException("Invalid timestamp for $field", e)
        }
    }

    private fun readNullableTimestamp(reader: JsonReader, field: String): String? =
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull()
            null
        } else {
            readTimestamp(reader, field)
        }

    private fun readNullableWebUrl(reader: JsonReader): String? {
        val value = readNullableString(reader, "web", 2_048) ?: return null
        if (!Regex("https://[^\\s]+", RegexOption.IGNORE_CASE).matches(value)) {
            throw TrustListParseException("web must be an HTTPS URL")
        }
        return value
    }

    private fun readNullableString(reader: JsonReader, field: String, maxLength: Int): String? =
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull()
            null
        } else {
            readString(reader, field, maxLength)
        }

    private fun readString(reader: JsonReader, field: String, maxLength: Int): String {
        requireToken(reader, JsonToken.STRING, "$field must be a string")
        val value = reader.nextString()
        if (value.isBlank() || value.length > maxLength) throw TrustListParseException("Invalid $field length")
        return value
    }

    private fun readPositiveInteger(reader: JsonReader, field: String): Long {
        val value = readNonNegativeInteger(reader, field)
        if (value <= 0L) throw TrustListParseException("$field must be positive")
        return value
    }

    private fun readNonNegativeInteger(reader: JsonReader, field: String): Long {
        requireToken(reader, JsonToken.NUMBER, "$field must be an integer")
        val raw = reader.nextString()
        if (!Regex("0|[1-9][0-9]*").matches(raw)) throw TrustListParseException("$field must be an integer")
        return raw.toLongOrNull() ?: throw TrustListParseException("$field is outside supported range")
    }

    private fun requireToken(reader: JsonReader, expected: JsonToken, message: String) {
        if (reader.peek() != expected) throw TrustListParseException(message)
    }

    private fun decodeUtf8(bytes: ByteArray): String = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (e: CharacterCodingException) {
        throw TrustListParseException("Trust list is not valid UTF-8", e)
    }
}
