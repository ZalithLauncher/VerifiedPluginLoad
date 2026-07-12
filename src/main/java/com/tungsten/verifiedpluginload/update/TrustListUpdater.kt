package com.tungsten.verifiedpluginload.update

import com.tungsten.verifiedpluginload.api.VerifiedPluginLoadConfig
import com.tungsten.verifiedpluginload.api.TrustListMirror
import com.tungsten.verifiedpluginload.model.TrustListRefreshResult
import com.tungsten.verifiedpluginload.model.TrustListRefreshStatus
import com.tungsten.verifiedpluginload.truststore.TrustListParseException
import com.tungsten.verifiedpluginload.truststore.TrustListRollbackException
import com.tungsten.verifiedpluginload.truststore.TrustListSignatureException
import com.tungsten.verifiedpluginload.truststore.TrustListStore
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

internal class TrustListUpdater(
    private val config: VerifiedPluginLoadConfig,
    private val store: TrustListStore
) {
    fun refresh(forceFullDownload: Boolean = false): TrustListRefreshResult {
        val mirrors = config.trustListMirrors
        if (mirrors.isEmpty()) return TrustListRefreshResult(TrustListRefreshStatus.NOT_CONFIGURED, null)
        val active = store.loadOrCreate()
        // ETags are scoped to an origin. With multiple mirrors, always fetch content so a 304
        // from one source cannot hide newer content from another source. Never send an old ETag
        // after recovering from a damaged current file either.
        val etag = if (
            mirrors.size == 1 &&
            !forceFullDownload &&
            active.source == com.tungsten.verifiedpluginload.model.TrustListSource.CURRENT
        ) {
            store.readMetadata().etag
        } else {
            null
        }
        return try {
            ParallelMirrorRace.firstSuccessful(
                mirrors = mirrors,
                download = { mirror -> downloadFromMirror(mirror, etag) },
                accept = { response ->
                    when (response) {
                        is MirrorDownload.NotModified -> TrustListRefreshResult(
                            TrustListRefreshStatus.NOT_MODIFIED,
                            store.loadOrCreate().trustList.listVersion
                        )
                        is MirrorDownload.Content -> {
                            val installed = store.installDownloaded(response.payload, response.signature, response.etag)
                            TrustListRefreshResult(TrustListRefreshStatus.UPDATED, installed.trustList.listVersion)
                        }
                    }
                }
            )
        } catch (e: MirrorRaceException) {
            resultForMirrorFailures(e.failures)
        } catch (e: TrustListSignatureException) {
            TrustListRefreshResult(TrustListRefreshStatus.REJECTED_SIGNATURE, null, e.message)
        } catch (e: TrustListParseException) {
            TrustListRefreshResult(TrustListRefreshStatus.REJECTED_SCHEMA, null, e.message)
        } catch (e: TrustListRollbackException) {
            TrustListRefreshResult(TrustListRefreshStatus.REJECTED_ROLLBACK, null, e.message)
        } catch (e: IOException) {
            TrustListRefreshResult(TrustListRefreshStatus.NETWORK_ERROR, null, e.message)
        } catch (e: Exception) {
            TrustListRefreshResult(TrustListRefreshStatus.STORAGE_ERROR, null, e.message)
        }
    }

    private fun downloadFromMirror(mirror: TrustListMirror, etag: String?): MirrorDownload {
        return when (val listResponse = download(mirror.listUrl, etag, config.maxTrustListBytes)) {
            is DownloadResult.NotModified -> MirrorDownload.NotModified
            is DownloadResult.Content -> {
                val signatureResponse = download(mirror.signatureUrl, null, 1_024)
                if (signatureResponse !is DownloadResult.Content) {
                    throw IOException("Signature endpoint at ${mirror.prefix} did not return content")
                }
                MirrorDownload.Content(listResponse.bytes, signatureResponse.bytes, listResponse.etag)
            }
        }
    }

    private fun resultForMirrorFailures(failures: List<Exception>): TrustListRefreshResult {
        val failure = failures.lastOrNull { it is TrustListRollbackException }
            ?: failures.lastOrNull { it is TrustListSignatureException }
            ?: failures.lastOrNull { it is TrustListParseException }
            ?: failures.lastOrNull()
        return when (failure) {
            is TrustListRollbackException -> TrustListRefreshResult(TrustListRefreshStatus.REJECTED_ROLLBACK, null, failure.message)
            is TrustListSignatureException -> TrustListRefreshResult(TrustListRefreshStatus.REJECTED_SIGNATURE, null, failure.message)
            is TrustListParseException -> TrustListRefreshResult(TrustListRefreshStatus.REJECTED_SCHEMA, null, failure.message)
            null, is IOException -> TrustListRefreshResult(
                TrustListRefreshStatus.NETWORK_ERROR,
                null,
                failure?.message ?: "No trust-list mirror returned a usable response"
            )
            else -> TrustListRefreshResult(TrustListRefreshStatus.STORAGE_ERROR, null, failure.message)
        }
    }

    private fun download(url: URL, etag: String?, maxBytes: Int): DownloadResult {
        val connection = (url.openConnection() as? HttpURLConnection)
            ?: throw IOException("Unsupported trust-list URL protocol")
        connection.instanceFollowRedirects = false
        connection.connectTimeout = config.networkTimeoutMillis
        connection.readTimeout = config.networkTimeoutMillis
        connection.requestMethod = "GET"
        connection.setRequestProperty("Accept", "application/json, application/octet-stream;q=0.9")
        etag?.let { connection.setRequestProperty("If-None-Match", it) }
        return try {
            when (val responseCode = connection.responseCode) {
                HttpURLConnection.HTTP_NOT_MODIFIED -> DownloadResult.NotModified
                HttpURLConnection.HTTP_OK -> {
                    val contentLength = connection.contentLengthLong
                    if (contentLength > maxBytes) throw IOException("Trust-list response exceeds configured limit")
                    val bytes = BufferedInputStream(connection.inputStream).use { input ->
                        val out = ByteArrayOutputStream()
                        val buffer = ByteArray(8_192)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            if (out.size() + count > maxBytes) throw IOException("Trust-list response exceeds configured limit")
                            out.write(buffer, 0, count)
                        }
                        out.toByteArray()
                    }
                    DownloadResult.Content(bytes, connection.getHeaderField("ETag")?.take(512))
                }
                else -> throw IOException("Trust-list server returned HTTP $responseCode")
            }
        } finally {
            connection.disconnect()
        }
    }

    private sealed interface DownloadResult {
        data class Content(val bytes: ByteArray, val etag: String?) : DownloadResult
        data object NotModified : DownloadResult
    }

    private sealed interface MirrorDownload {
        data class Content(val payload: ByteArray, val signature: ByteArray, val etag: String?) : MirrorDownload
        data object NotModified : MirrorDownload
    }
}
