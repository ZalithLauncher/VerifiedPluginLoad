package com.tungsten.verifiedpluginload.update

import com.tungsten.verifiedpluginload.api.VerifiedPluginLoadConfig
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
        val listUrl = config.trustListUrl ?: return TrustListRefreshResult(TrustListRefreshStatus.NOT_CONFIGURED, null)
        val signatureUrl = config.trustListSignatureUrl ?: return TrustListRefreshResult(TrustListRefreshStatus.NOT_CONFIGURED, null)
        val active = store.loadOrCreate()
        // Never send an old ETag after recovering from a damaged current file: a 304 response
        // must not prevent the recovery path from obtaining a fresh signed payload.
        val etag = if (!forceFullDownload && active.source == com.tungsten.verifiedpluginload.model.TrustListSource.CURRENT) {
            store.readMetadata().etag
        } else {
            null
        }
        return try {
            when (val listResponse = download(URL(listUrl), etag, config.maxTrustListBytes)) {
                is DownloadResult.NotModified -> TrustListRefreshResult(
                    TrustListRefreshStatus.NOT_MODIFIED,
                    store.loadOrCreate().trustList.listVersion
                )
                is DownloadResult.Content -> {
                    val signatureResponse = download(URL(signatureUrl), null, 1_024)
                    if (signatureResponse !is DownloadResult.Content) {
                        TrustListRefreshResult(TrustListRefreshStatus.NETWORK_ERROR, null, "Signature endpoint did not return content")
                    } else {
                        val installed = store.installDownloaded(listResponse.bytes, signatureResponse.bytes, listResponse.etag)
                        TrustListRefreshResult(TrustListRefreshStatus.UPDATED, installed.trustList.listVersion)
                    }
                }
            }
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
}
