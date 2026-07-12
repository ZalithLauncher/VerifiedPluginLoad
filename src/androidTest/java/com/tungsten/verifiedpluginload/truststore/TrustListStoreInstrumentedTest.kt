package com.tungsten.verifiedpluginload.truststore

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.tungsten.verifiedpluginload.api.VerifiedPluginLoadConfig
import com.tungsten.verifiedpluginload.model.TrustListSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class TrustListStoreInstrumentedTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun bundledTrustListHasValidSignatureAndStrictSchema() {
        val payload = context.assets.open("trusted-authors.json").use { it.readBytes() }
        val signature = context.assets.open("trusted-authors.json.sig").use { raw ->
            Ed25519Verifier.decodeSignature(raw.readBytes())
        }

        assertNotNull("Bundled trust-list signature must be a valid 64-byte Ed25519 signature", signature)
        assertTrue(Ed25519Verifier.verify(payload, signature!!))
        val trustList = TrustListParser.parse(payload)
        assertTrue(trustList.listVersion > 0)
        assertTrue("Bundled trust list must not be an empty bootstrap list", trustList.authors.isNotEmpty())
    }

    @Test
    fun invalidSignatureCannotReplaceCurrentTrustList() {
        val store = newStore("invalid-signature")
        store.installDownloaded(payload(2), TEST_SIGNATURE, null)

        try {
            store.installDownloaded(payload(3), ByteArray(64), null)
            fail("An invalid signature must be rejected")
        } catch (_: TrustListSignatureException) {
        }

        assertEquals(2, store.loadOrCreate().trustList.listVersion)
    }

    @Test
    fun listVersionRollbackIsRejected() {
        val store = newStore("rollback")
        store.installDownloaded(payload(3), TEST_SIGNATURE, null)

        try {
            store.installDownloaded(payload(2), TEST_SIGNATURE, null)
            fail("A lower list version must be rejected")
        } catch (_: TrustListRollbackException) {
        }

        assertEquals(3, store.loadOrCreate().trustList.listVersion)
    }

    @Test
    fun corruptedCurrentListRecoversPreviousVerifiedSnapshot() {
        val directory = uniqueDirectory("previous")
        val store = TrustListStore(context, VerifiedPluginLoadConfig(directory), testVerifier)
        store.installDownloaded(payload(2), TEST_SIGNATURE, null)
        store.installDownloaded(payload(3), TEST_SIGNATURE, null)
        File(directory, "trusted-authors.json").writeText("{")

        val recovered = store.loadOrCreate()

        assertEquals(TrustListSource.PREVIOUS, recovered.source)
        assertEquals(2, recovered.trustList.listVersion)
    }

    private fun newStore(name: String): TrustListStore = TrustListStore(
        context,
        VerifiedPluginLoadConfig(uniqueDirectory(name)),
        testVerifier
    )

    private fun uniqueDirectory(name: String): File =
        File(context.cacheDir, "vpl-store-$name-${System.nanoTime()}")

    private fun payload(version: Int): ByteArray = """
        {"format_version":1,"list_version":$version,"generated_at":"2026-01-01T00:00:00Z","expires_at":"2036-01-01T00:00:00Z","keys":[]}
    """.trimIndent().toByteArray()

    private companion object {
        private val TEST_SIGNATURE = ByteArray(64) { 0x5A.toByte() }
        private val testVerifier = object : TrustListSignatureVerifier {
            override fun verify(payload: ByteArray, signature: ByteArray): Boolean =
                signature.contentEquals(TEST_SIGNATURE) || Ed25519Verifier.verify(payload, signature)

            override fun decodeSignature(raw: ByteArray): ByteArray? = Ed25519Verifier.decodeSignature(raw)
        }
    }
}
