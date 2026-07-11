package com.tungsten.verifiedpluginload.internal

import android.content.Context
import com.tungsten.verifiedpluginload.api.VerifiedPluginLoad
import com.tungsten.verifiedpluginload.api.VerifiedPluginLoadConfig
import com.tungsten.verifiedpluginload.model.InitializationResult
import com.tungsten.verifiedpluginload.model.KeyHash
import com.tungsten.verifiedpluginload.model.KeyState
import com.tungsten.verifiedpluginload.model.PluginVerificationResult
import com.tungsten.verifiedpluginload.model.TrustActionResult
import com.tungsten.verifiedpluginload.model.TrustActionStatus
import com.tungsten.verifiedpluginload.model.TrustedAuthorInfo
import com.tungsten.verifiedpluginload.model.TrustListRefreshResult
import com.tungsten.verifiedpluginload.model.TrustListRefreshStatus
import com.tungsten.verifiedpluginload.model.TrustListSource
import com.tungsten.verifiedpluginload.model.UserTrustSnapshot
import com.tungsten.verifiedpluginload.model.VerificationDiagnostic
import com.tungsten.verifiedpluginload.signature.ApkSignatureReader
import com.tungsten.verifiedpluginload.truststore.LoadedTrustList
import com.tungsten.verifiedpluginload.truststore.TrustListStore
import com.tungsten.verifiedpluginload.update.TrustListUpdater
import com.tungsten.verifiedpluginload.userstore.UserTrustStore
import com.tungsten.verifiedpluginload.verification.PluginVerifier
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal class VerifiedPluginLoadImpl(
    context: Context,
    private val config: VerifiedPluginLoadConfig
) : VerifiedPluginLoad {
    private val lock = ReentrantLock()
    private val store = TrustListStore(context, config)
    private val userStore = UserTrustStore(config.storageDirectory)
    private val signatureReader = ApkSignatureReader(context)
    private val updater = TrustListUpdater(config, store)
    private val refreshExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "VerifiedPluginLoad-refresh").apply { isDaemon = true }
    }

    @Volatile
    private var refreshScheduled = false

    @Volatile
    private var lastUpdateFailed = false

    override suspend fun initialize(): InitializationResult {
        val initial = lock.withLock {
            initializationResult(store.loadOrCreate(), userStore.snapshot())
        }

        if (!config.isTrustListRemoteConfigured) return initial

        // A recovery path waits for a bounded update attempt; an already valid local list does not.
        return if (initial.trustListSource != TrustListSource.CURRENT) {
            val refresh = refreshInternal(forceFullDownload = true)
            lock.withLock {
                initializationResult(store.loadOrCreate(), userStore.snapshot(), refresh)
            }
        } else {
            scheduleBackgroundRefresh()
            initial
        }
    }

    override suspend fun refreshTrustList(): TrustListRefreshResult = refreshInternal()

    override fun inspectInstalledPackage(packageName: String): PluginVerificationResult = lock.withLock {
        val loaded = store.loadOrCreate()
        val user = userStore.snapshot()
        val signatures = signatureReader.inspectInstalled(packageName)
        PluginVerifier.verify(
            packageInfo = signatures.packageInfo,
            signatures = signatures.signatures,
            signatureDiagnostic = signatures.diagnostic,
            trustList = loaded.trustList,
            trustListSource = loaded.source,
            trustListExpired = store.isExpired(loaded),
            userTrust = user,
            updateFailed = lastUpdateFailed
        )
    }

    override fun inspectApkFile(apkFile: File): PluginVerificationResult = lock.withLock {
        val loaded = store.loadOrCreate()
        val user = userStore.snapshot()
        val signatures = signatureReader.inspectArchive(apkFile)
        PluginVerifier.verify(
            packageInfo = signatures.packageInfo,
            signatures = signatures.signatures,
            signatureDiagnostic = signatures.diagnostic,
            trustList = loaded.trustList,
            trustListSource = loaded.source,
            trustListExpired = store.isExpired(loaded),
            userTrust = user,
            updateFailed = lastUpdateFailed
        )
    }

    override suspend fun trustAuthor(authorUuid: String): TrustActionResult = lock.withLock {
        val normalized = com.tungsten.verifiedpluginload.model.normalizeUuid(authorUuid)
            ?: return@withLock action(TrustActionStatus.INVALID_AUTHOR_UUID)
        val author = store.loadOrCreate().trustList.activeAuthor(normalized)
            ?: return@withLock action(TrustActionStatus.AUTHOR_NOT_REGISTERED)
        if (author.info.confidence == 0 || author.hashes.none { it.state == KeyState.ACTIVE }) {
            return@withLock action(TrustActionStatus.AUTHOR_NOT_TRUSTABLE)
        }
        try {
            TrustActionResult(TrustActionStatus.SUCCESS, userStore.trustAuthor(normalized))
        } catch (_: Exception) {
            action(TrustActionStatus.STORAGE_ERROR)
        }
    }

    override suspend fun revokeAuthorTrust(authorUuid: String): TrustActionResult = lock.withLock {
        val normalized = com.tungsten.verifiedpluginload.model.normalizeUuid(authorUuid)
            ?: return@withLock action(TrustActionStatus.INVALID_AUTHOR_UUID)
        val snapshot = userStore.snapshot()
        if (normalized !in snapshot.trustedAuthorUuids) return@withLock TrustActionResult(TrustActionStatus.NOT_FOUND, snapshot)
        try {
            TrustActionResult(TrustActionStatus.SUCCESS, userStore.revokeAuthor(normalized))
        } catch (_: Exception) {
            action(TrustActionStatus.STORAGE_ERROR)
        }
    }

    override suspend fun trustKeyHash(keyHash: String): TrustActionResult = lock.withLock {
        val parsed = KeyHash.parse(keyHash) ?: return@withLock action(TrustActionStatus.INVALID_KEY_HASH)
        if (store.loadOrCreate().trustList.find(parsed)?.second?.state == KeyState.BANNED) {
            return@withLock action(TrustActionStatus.KEY_BANNED)
        }
        try {
            TrustActionResult(TrustActionStatus.SUCCESS, userStore.trustKey(parsed))
        } catch (_: Exception) {
            action(TrustActionStatus.STORAGE_ERROR)
        }
    }

    override suspend fun revokeKeyHashTrust(keyHash: String): TrustActionResult = lock.withLock {
        val parsed = KeyHash.parse(keyHash) ?: return@withLock action(TrustActionStatus.INVALID_KEY_HASH)
        val snapshot = userStore.snapshot()
        if (parsed !in snapshot.trustedKeyHashes) return@withLock TrustActionResult(TrustActionStatus.NOT_FOUND, snapshot)
        try {
            TrustActionResult(TrustActionStatus.SUCCESS, userStore.revokeKey(parsed))
        } catch (_: Exception) {
            action(TrustActionStatus.STORAGE_ERROR)
        }
    }

    override fun getTrustedAuthors(): List<TrustedAuthorInfo> = lock.withLock {
        store.loadOrCreate().trustList.authors.map { it.info }
    }

    override fun getUserTrustSnapshot(): UserTrustSnapshot = lock.withLock { userStore.snapshot() }

    private fun refreshInternal(forceFullDownload: Boolean = false): TrustListRefreshResult = lock.withLock {
        val result = updater.refresh(forceFullDownload)
        lastUpdateFailed = result.status !in setOf(
            TrustListRefreshStatus.UPDATED,
            TrustListRefreshStatus.NOT_MODIFIED,
            TrustListRefreshStatus.NOT_CONFIGURED
        )
        result
    }

    private fun scheduleBackgroundRefresh() {
        if (refreshScheduled) return
        synchronized(this) {
            if (refreshScheduled) return
            refreshScheduled = true
            refreshExecutor.execute {
                try {
                    refreshInternal()
                } finally {
                    refreshScheduled = false
                }
            }
        }
    }

    private fun initializationResult(
        loaded: LoadedTrustList,
        userTrust: UserTrustSnapshot,
        refresh: TrustListRefreshResult? = null
    ): InitializationResult {
        val diagnostic = when {
            refresh != null && refresh.status !in setOf(TrustListRefreshStatus.UPDATED, TrustListRefreshStatus.NOT_MODIFIED) ->
                VerificationDiagnostic.TRUST_LIST_UPDATE_FAILED
            store.isExpired(loaded) -> VerificationDiagnostic.TRUST_LIST_EXPIRED
            loaded.source == TrustListSource.BUILTIN -> VerificationDiagnostic.TRUST_LIST_FALLBACK_TO_BUILTIN
            userTrust.recoveredFromCorruption -> VerificationDiagnostic.USER_TRUST_STORE_RECOVERED
            else -> VerificationDiagnostic.NONE
        }
        return InitializationResult(
            trustListSource = loaded.source,
            trustListVersion = loaded.trustList.listVersion,
            diagnostic = diagnostic,
            userTrustRecoveredFromCorruption = userTrust.recoveredFromCorruption
        )
    }

    private fun action(status: TrustActionStatus): TrustActionResult = TrustActionResult(status, userStore.snapshot())
}
