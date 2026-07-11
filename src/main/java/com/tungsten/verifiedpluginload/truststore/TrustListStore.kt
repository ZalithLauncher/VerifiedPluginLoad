package com.tungsten.verifiedpluginload.truststore

import android.content.Context
import android.util.Log
import com.google.gson.JsonParser
import com.google.gson.stream.JsonWriter
import com.tungsten.verifiedpluginload.api.VerifiedPluginLoadConfig
import com.tungsten.verifiedpluginload.model.TrustListSource
import com.tungsten.verifiedpluginload.storage.AtomicFiles
import java.io.File
import java.io.StringWriter
import java.time.Instant

internal data class LoadedTrustList(
    val trustList: TrustList,
    val source: TrustListSource,
    val payload: ByteArray,
    val signature: ByteArray
)

internal data class TrustListMetadata(
    val listVersion: Long?,
    val etag: String?,
    val lastSuccessfulUpdate: String?
)

internal class TrustListSignatureException(message: String) : Exception(message)
internal class TrustListRollbackException(message: String) : Exception(message)

internal class TrustListStore(
    private val context: Context,
    private val config: VerifiedPluginLoadConfig,
    private val verifier: TrustListSignatureVerifier = Ed25519Verifier
) {
    private companion object {
        const val TAG = "VerifiedPluginLoad"
    }
    private val directory = config.storageDirectory
    private val currentJson = File(directory, "trusted-authors.json")
    private val currentSignature = File(directory, "trusted-authors.json.sig")
    private val previousJson = File(directory, "trusted-authors.previous.json")
    private val previousSignature = File(directory, "trusted-authors.previous.json.sig")
    private val metadataFile = File(directory, "trusted-authors.meta.json")
    private val temporaryJson = File(directory, "trusted-authors.json.tmp")
    private val temporarySignature = File(directory, "trusted-authors.json.sig.tmp")

    fun loadOrCreate(): LoadedTrustList {
        if (!ensureDirectory()) {
            Log.w(TAG, "VPL storage directory is unavailable; using the built-in trust list")
            return readBuiltin()
        }
        readPair(currentJson, currentSignature, TrustListSource.CURRENT)?.let { return it }

        if (currentJson.exists() || currentSignature.exists()) {
            Log.w(TAG, "Current trust list is invalid; attempting recovery")
        }

        readPair(previousJson, previousSignature, TrustListSource.PREVIOUS)?.let { previous ->
            Log.w(TAG, "Recovered trust list from the previous valid snapshot")
            try {
                restoreCurrent(previous)
            } catch (e: Exception) {
                // Returning the verified snapshot is still safe when the directory cannot be repaired.
                Log.w(TAG, "Could not repair the current trust-list snapshot", e)
            }
            return previous
        }

        Log.w(TAG, "Using the built-in trust list after local trust-list recovery failed")
        val builtin = readBuiltin()
        try {
            installInitial(builtin)
        } catch (e: Exception) {
            // A signed in-memory fallback is preferable to failing initialization or trusting data.
            Log.w(TAG, "Could not persist the built-in trust list", e)
        }
        return builtin
    }

    fun installDownloaded(payload: ByteArray, signatureBytes: ByteArray, etag: String?): LoadedTrustList {
        if (!ensureDirectory()) throw IllegalStateException("VPL storage directory is unavailable")
        val signature = verifier.decodeSignature(signatureBytes)
            ?: throw TrustListSignatureException("The downloaded signature is malformed")
        val candidate = validate(payload, signature, TrustListSource.CURRENT)
        val current = loadOrCreate()
        if (candidate.trustList.listVersion < current.trustList.listVersion) {
            throw TrustListRollbackException("Downloaded trust list is older than the active list")
        }

        AtomicFiles.deleteQuietly(temporaryJson)
        AtomicFiles.deleteQuietly(temporarySignature)
        AtomicFiles.write(temporaryJson, payload)
        AtomicFiles.write(temporarySignature, signature)
        // Read the staged files back through the normal verification path before replacement.
        readPair(temporaryJson, temporarySignature, TrustListSource.CURRENT)
            ?: throw TrustListSignatureException("The staged trust list could not be verified")

        readPair(currentJson, currentSignature, TrustListSource.CURRENT)?.let { active ->
            // Preserve a complete valid pair before touching either active file. A crash while
            // replacing the pair can then always recover from previous.
            AtomicFiles.write(previousJson, active.payload)
            AtomicFiles.write(previousSignature, active.signature)
        }
        AtomicFiles.moveReplace(temporaryJson, currentJson)
        AtomicFiles.moveReplace(temporarySignature, currentSignature)
        writeMetadata(candidate.trustList.listVersion, etag)
        return candidate
    }

    fun readMetadata(): TrustListMetadata {
        val bytes = AtomicFiles.readBounded(metadataFile, 16 * 1024) ?: return TrustListMetadata(null, null, null)
        return try {
            val root = JsonParser.parseString(bytes.toString(Charsets.UTF_8)).asJsonObject
            if (root.get("format_version")?.asInt != 1) return TrustListMetadata(null, null, null)
            TrustListMetadata(
                listVersion = root.get("list_version")?.takeIf { it.isJsonPrimitive }?.asLong,
                etag = root.get("etag")?.takeIf { it.isJsonPrimitive }?.asString?.takeIf { it.length <= 512 },
                lastSuccessfulUpdate = root.get("last_successful_update")?.takeIf { it.isJsonPrimitive }?.asString
            )
        } catch (_: Exception) {
            TrustListMetadata(null, null, null)
        }
    }

    fun isExpired(loaded: LoadedTrustList): Boolean = try {
        Instant.parse(loaded.trustList.expiresAt).isBefore(Instant.now())
    } catch (_: Exception) {
        true
    }

    private fun ensureDirectory(): Boolean = try {
        (directory.exists() || directory.mkdirs()) && directory.isDirectory
    } catch (_: SecurityException) {
        false
    }

    private fun readBuiltin(): LoadedTrustList {
        val payload = context.assets.open("trusted-authors.json").use { input ->
            input.readBytes().also {
                if (it.size !in 1..config.maxTrustListBytes) throw TrustListParseException("Invalid builtin list size")
            }
        }
        val signatureRaw = context.assets.open("trusted-authors.json.sig").use { it.readBytes() }
        val signature = verifier.decodeSignature(signatureRaw)
            ?: throw TrustListSignatureException("Builtin signature is malformed")
        return validate(payload, signature, TrustListSource.BUILTIN)
    }

    private fun readPair(json: File, signatureFile: File, source: TrustListSource): LoadedTrustList? {
        val payload = AtomicFiles.readBounded(json, config.maxTrustListBytes) ?: return null
        val signature = AtomicFiles.readBounded(signatureFile, 1_024)?.let(verifier::decodeSignature) ?: return null
        return try {
            validate(payload, signature, source)
        } catch (_: Exception) {
            null
        }
    }

    private fun validate(payload: ByteArray, signature: ByteArray, source: TrustListSource): LoadedTrustList {
        if (!verifier.verify(payload, signature)) {
            throw TrustListSignatureException("Trust-list signature verification failed")
        }
        return LoadedTrustList(TrustListParser.parse(payload, config.maxTrustListBytes), source, payload, signature)
    }

    private fun installInitial(builtin: LoadedTrustList) {
        AtomicFiles.write(currentJson, builtin.payload)
        AtomicFiles.write(currentSignature, builtin.signature)
        if (!metadataFile.exists()) writeMetadata(builtin.trustList.listVersion, null)
    }

    private fun restoreCurrent(previous: LoadedTrustList) {
        AtomicFiles.write(currentJson, previous.payload)
        AtomicFiles.write(currentSignature, previous.signature)
    }

    private fun writeMetadata(listVersion: Long, etag: String?) {
        val content = StringWriter().use { out ->
            JsonWriter(out).use { writer ->
                writer.beginObject()
                writer.name("format_version").value(1)
                writer.name("list_version").value(listVersion)
                writer.name("last_successful_update").value(Instant.now().toString())
                if (etag == null) writer.name("etag").nullValue() else writer.name("etag").value(etag.take(512))
                writer.endObject()
            }
            out.toString()
        }
        AtomicFiles.write(metadataFile, content.toByteArray(Charsets.UTF_8))
    }
}
