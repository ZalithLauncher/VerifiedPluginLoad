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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine

data class VerifiedPluginLoadConfig(
    val storageDirectory: File,
    val trustListUrl: String? = null,
    val trustListSignatureUrl: String? = null,
    val networkTimeoutMillis: Int = 5_000,
    val maxTrustListBytes: Int = 1_048_576
) {
    init {
        require(networkTimeoutMillis in 1_000..30_000) { "networkTimeoutMillis must be between 1 and 30 seconds" }
        require(maxTrustListBytes in 1_024..4_194_304) { "maxTrustListBytes is outside the supported range" }
        require((trustListUrl == null) == (trustListSignatureUrl == null)) {
            "trustListUrl and trustListSignatureUrl must be configured together"
        }
        trustListUrl?.let(::requireHttpsUrl)
        trustListSignatureUrl?.let(::requireHttpsUrl)
    }

    private fun requireHttpsUrl(value: String) {
        val uri = try {
            URI(value)
        } catch (e: Exception) {
            throw IllegalArgumentException("Trust-list URL is malformed", e)
        }
        require(uri.scheme == "https" && !uri.host.isNullOrBlank()) { "Trust-list downloads must use HTTPS" }
    }
}

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
