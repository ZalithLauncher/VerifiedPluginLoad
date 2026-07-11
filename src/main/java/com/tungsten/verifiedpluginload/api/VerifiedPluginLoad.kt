package com.tungsten.verifiedpluginload.api

import android.content.Context
import com.tungsten.verifiedpluginload.internal.VerifiedPluginLoadImpl
import com.tungsten.verifiedpluginload.model.InitializationResult
import com.tungsten.verifiedpluginload.model.KeyHash
import com.tungsten.verifiedpluginload.model.PluginVerificationResult
import com.tungsten.verifiedpluginload.model.TrustActionResult
import com.tungsten.verifiedpluginload.model.TrustedAuthorInfo
import com.tungsten.verifiedpluginload.model.TrustListRefreshResult
import com.tungsten.verifiedpluginload.model.UserTrustSnapshot
import java.io.File
import java.net.URI
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine

data class VerifiedPluginLoadConfig(
    val storageDirectory: File,
    val trustListUrlPrefixes: List<String> = emptyList(),
    val trustListJsonSuffix: String? = null,
    val trustListSignatureSuffix: String? = null,
    val networkTimeoutMillis: Int = 5_000,
    val maxTrustListBytes: Int = 1_048_576
) {
    internal val trustListMirrors: List<TrustListMirror>

    init {
        require(networkTimeoutMillis in 1_000..30_000) { "networkTimeoutMillis must be between 1 and 30 seconds" }
        require(maxTrustListBytes in 1_024..4_194_304) { "maxTrustListBytes is outside the supported range" }
        val hasPrefixes = trustListUrlPrefixes.isNotEmpty()
        require(hasPrefixes == (trustListJsonSuffix != null && trustListSignatureSuffix != null)) {
            "trustListUrlPrefixes, trustListJsonSuffix, and trustListSignatureSuffix must be configured together"
        }

        trustListMirrors = if (!hasPrefixes) {
            emptyList()
        } else {
            require(trustListUrlPrefixes.size <= MAX_TRUST_LIST_MIRRORS) {
                "At most $MAX_TRUST_LIST_MIRRORS trust-list URL prefixes are supported"
            }
            val prefixes = trustListUrlPrefixes.map(::normalizePrefix)
            require(prefixes.toSet().size == prefixes.size) { "Trust-list URL prefixes must be unique" }
            val jsonSuffix = normalizeSuffix(trustListJsonSuffix!!, "trustListJsonSuffix")
            val signatureSuffix = normalizeSuffix(trustListSignatureSuffix!!, "trustListSignatureSuffix")
            prefixes.map { prefix ->
                TrustListMirror(
                    prefix = prefix,
                    listUrl = toHttpsUrl("$prefix/$jsonSuffix"),
                    signatureUrl = toHttpsUrl("$prefix/$signatureSuffix")
                )
            }
        }
    }

    internal val isTrustListRemoteConfigured: Boolean
        get() = trustListMirrors.isNotEmpty()

    private fun normalizePrefix(value: String): String {
        val normalized = value.trim().trimEnd('/')
        require(normalized.isNotEmpty()) { "Trust-list URL prefix must not be blank" }
        val uri = parseHttpsUri(normalized, "Trust-list URL prefix")
        require(uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) {
            "Trust-list URL prefixes cannot contain credentials, queries, or fragments"
        }
        return normalized
    }

    private fun normalizeSuffix(value: String, name: String): String {
        val normalized = value.trim().trimStart('/')
        require(normalized.isNotEmpty()) { "$name must not be blank" }
        val uri = try {
            URI(normalized)
        } catch (e: Exception) {
            throw IllegalArgumentException("$name is malformed", e)
        }
        require(!uri.isAbsolute && uri.rawAuthority == null && !uri.path.isNullOrEmpty()) {
            "$name must be a relative path"
        }
        require(uri.rawFragment == null) { "$name cannot contain a fragment" }
        require(uri.path.split('/').none { it == "." || it == ".." }) {
            "$name cannot contain dot path segments"
        }
        return normalized
    }

    private fun toHttpsUrl(value: String): URL = parseHttpsUri(value, "Trust-list URL").toURL()

    private fun parseHttpsUri(value: String, label: String): URI {
        val uri = try {
            URI(value)
        } catch (e: Exception) {
            throw IllegalArgumentException("$label is malformed", e)
        }
        require(uri.scheme?.equals("https", ignoreCase = true) == true && !uri.host.isNullOrBlank()) {
            "Trust-list downloads must use HTTPS"
        }
        return uri
    }

    private companion object {
        const val MAX_TRUST_LIST_MIRRORS = 8
    }
}

internal data class TrustListMirror(
    val prefix: String,
    val listUrl: URL,
    val signatureUrl: URL
)

interface VerifiedPluginLoad {
    suspend fun initialize(): InitializationResult

    suspend fun refreshTrustList(): TrustListRefreshResult

    fun inspectInstalledPackage(packageName: String): PluginVerificationResult

    fun inspectApkFile(apkFile: File): PluginVerificationResult

    suspend fun trustAuthor(authorUuid: String): TrustActionResult

    suspend fun revokeAuthorTrust(authorUuid: String): TrustActionResult

    suspend fun trustKeyHash(keyHash: String): TrustActionResult

    suspend fun revokeKeyHashTrust(keyHash: String): TrustActionResult

    fun getTrustedAuthors(): List<TrustedAuthorInfo>

    fun getUserTrustSnapshot(): UserTrustSnapshot
}

object VerifiedPluginLoadFactory {
    @JvmStatic
    fun create(context: Context, config: VerifiedPluginLoadConfig): VerifiedPluginLoad =
        VerifiedPluginLoadImpl(context.applicationContext, config)
}

/**
 * Lets a host configure one process-wide VPL instance. The final native-load guard uses this
 * registry, preventing a legacy launcher path from silently constructing a differently scoped store.
 */
object VerifiedPluginLoadRegistry {
    @Volatile
    private var configured: VerifiedPluginLoad? = null

    @JvmStatic
    fun configure(context: Context, config: VerifiedPluginLoadConfig): VerifiedPluginLoad = synchronized(this) {
        VerifiedPluginLoadFactory.create(context, config).also { configured = it }
    }

    @JvmStatic
    fun get(context: Context): VerifiedPluginLoad = configured ?: synchronized(this) {
        configured ?: VerifiedPluginLoadFactory.create(
            context,
            VerifiedPluginLoadConfig(File(context.filesDir, "verified-plugin-load"))
        ).also { configured = it }
    }

    @JvmStatic
    fun clearForTests() {
        configured = null
    }
}

/** Java-friendly bridge for hosts whose task framework is not coroutine based. */
object VerifiedPluginLoadBlocking {
    @JvmStatic
    fun initialize(vpl: VerifiedPluginLoad): InitializationResult = runSuspending { vpl.initialize() }

    @JvmStatic
    fun refreshTrustList(vpl: VerifiedPluginLoad): TrustListRefreshResult = runSuspending { vpl.refreshTrustList() }

    @JvmStatic
    fun trustAuthor(vpl: VerifiedPluginLoad, authorUuid: String): TrustActionResult =
        runSuspending { vpl.trustAuthor(authorUuid) }

    @JvmStatic
    fun revokeAuthorTrust(vpl: VerifiedPluginLoad, authorUuid: String): TrustActionResult =
        runSuspending { vpl.revokeAuthorTrust(authorUuid) }

    @JvmStatic
    fun trustKeyHash(vpl: VerifiedPluginLoad, keyHash: String): TrustActionResult =
        runSuspending { vpl.trustKeyHash(keyHash) }

    @JvmStatic
    fun revokeKeyHashTrust(vpl: VerifiedPluginLoad, keyHash: String): TrustActionResult =
        runSuspending { vpl.revokeKeyHashTrust(keyHash) }

    private fun <T> runSuspending(block: suspend () -> T): T {
        val latch = CountDownLatch(1)
        val completion = AtomicReference<Result<T>>()
        block.startCoroutine(object : Continuation<T> {
            override val context = EmptyCoroutineContext

            override fun resumeWith(result: Result<T>) {
                completion.set(result)
                latch.countDown()
            }
        })
        latch.await()
        return completion.get().getOrThrow()
    }
}
