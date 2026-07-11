package com.tungsten.verifiedpluginload.verification

import com.tungsten.verifiedpluginload.model.AuthorType
import com.tungsten.verifiedpluginload.model.KeyHash
import com.tungsten.verifiedpluginload.model.KeyState
import com.tungsten.verifiedpluginload.model.PluginPackageInfo
import com.tungsten.verifiedpluginload.model.PluginTrustStatus
import com.tungsten.verifiedpluginload.model.SignatureInfo
import com.tungsten.verifiedpluginload.model.TrustListSource
import com.tungsten.verifiedpluginload.model.TrustSource
import com.tungsten.verifiedpluginload.model.TrustedAuthorInfo
import com.tungsten.verifiedpluginload.model.UserTrustSnapshot
import com.tungsten.verifiedpluginload.model.VerificationDiagnostic
import com.tungsten.verifiedpluginload.truststore.TrustAuthor
import com.tungsten.verifiedpluginload.truststore.TrustKey
import com.tungsten.verifiedpluginload.truststore.TrustList
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test

class PluginVerifierTest {
    private val packageInfo = PluginPackageInfo("example.plugin", "Example", "1.0", 1, "/data/app/example/base.apk", null)
    private val keyA = hash('A')
    private val keyB = hash('B')

    @Test
    fun `key hash input is normalized but malformed input is rejected`() {
        val lower = keyA.value.lowercase()
        assertEquals(keyA, KeyHash.parse(lower))
        assertEquals(null, KeyHash.parse("sha256:bad|sha1:bad"))
    }

    @Test
    fun `certificate fingerprints use canonical unsigned uppercase hex`() {
        val hash = KeyHash.fromCertificate("abc".toByteArray())

        assertEquals(
            "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD|sha1:A9993E364706816ABA3E25717850C26C9CD0D89D",
            hash.value
        )
    }

    @Test
    fun `banned key wins over explicit user key trust`() {
        val result = verify(
            listOf(author(keyA, KeyState.BANNED)),
            signatures = listOf(keyA),
            trustedKeys = setOf(keyA)
        )

        assertEquals(PluginTrustStatus.BANNED, result.status)
        assertEquals(KeyState.BANNED, result.keyState)
    }

    @Test
    fun `banned key wins over explicit author trust`() {
        val owner = author(keyA, KeyState.BANNED)
        val result = verify(
            listOf(owner),
            signatures = listOf(keyA),
            trustedAuthors = setOf(owner.info.uuid)
        )

        assertEquals(PluginTrustStatus.BANNED, result.status)
    }

    @Test
    fun `a banned signer wins in a multi signed package`() {
        val trustedOwner = author(keyA, KeyState.ACTIVE)
        val bannedOwner = TrustAuthor(
            trustedOwner.info.copy(uuid = "22222222-2222-2222-2222-222222222222"),
            listOf(TrustKey(keyB, KeyState.BANNED, "Revoked", "2026-01-02T00:00:00Z"))
        )

        val result = verify(
            listOf(trustedOwner, bannedOwner),
            signatures = listOf(keyA, keyB),
            trustedAuthors = setOf(trustedOwner.info.uuid)
        )

        assertEquals(PluginTrustStatus.BANNED, result.status)
        assertEquals(keyB, result.matchedSignature)
    }

    @Test
    fun `trusted author accepts an active registered key`() {
        val owner = author(keyA, KeyState.ACTIVE)
        val result = verify(
            listOf(owner),
            signatures = listOf(keyA),
            trustedAuthors = setOf(owner.info.uuid)
        )

        assertEquals(PluginTrustStatus.TRUSTED, result.status)
        assertEquals(TrustSource.AUTHOR, result.trustSource)
        assertNotNull(result.toLoadAuthorization())
    }

    @Test
    fun `active registered key awaits explicit author trust`() {
        val result = verify(listOf(author(keyA, KeyState.ACTIVE)), signatures = listOf(keyA))

        assertEquals(PluginTrustStatus.PENDING_TRUST, result.status)
    }

    @Test
    fun `unregistered user key is trusted explicitly`() {
        val result = verify(emptyList(), signatures = listOf(keyB), trustedKeys = setOf(keyB))

        assertEquals(PluginTrustStatus.TRUSTED, result.status)
        assertEquals(TrustSource.KEY, result.trustSource)
    }

    @Test
    fun `explicit key trust survives a later active author registration`() {
        val result = verify(
            listOf(author(keyA, KeyState.ACTIVE)),
            signatures = listOf(keyA),
            trustedKeys = setOf(keyA)
        )

        assertEquals(PluginTrustStatus.TRUSTED, result.status)
        assertEquals(TrustSource.KEY, result.trustSource)
    }

    @Test
    fun `unmatched signed plugin remains untrusted`() {
        val result = verify(emptyList(), signatures = listOf(keyB))

        assertEquals(PluginTrustStatus.UNTRUSTED, result.status)
    }

    @Test
    fun `historical certificate is retained for diagnostics but not used as direct key trust`() {
        val result = PluginVerifier.verify(
            packageInfo = packageInfo,
            signatures = listOf(SignatureInfo(keyB, false), SignatureInfo(keyA, true)),
            signatureDiagnostic = VerificationDiagnostic.NONE,
            trustList = listOf(author(keyA, KeyState.ACTIVE)).toTrustList(),
            trustListSource = TrustListSource.CURRENT,
            trustListExpired = false,
            userTrust = UserTrustSnapshot(emptySet(), setOf(keyA), null, false),
            updateFailed = false
        )

        assertEquals(PluginTrustStatus.UNTRUSTED, result.status)
        assertEquals(2, result.allSignatures.size)
    }

    @Test
    fun `missing current signature is a verification failure rather than an untrusted result`() {
        val result = PluginVerifier.verify(
            packageInfo = packageInfo,
            signatures = emptyList(),
            signatureDiagnostic = VerificationDiagnostic.APK_UNSIGNED,
            trustList = emptyList<TrustAuthor>().toTrustList(),
            trustListSource = TrustListSource.CURRENT,
            trustListExpired = false,
            userTrust = UserTrustSnapshot(emptySet(), emptySet(), null, false),
            updateFailed = false
        )

        assertEquals(PluginTrustStatus.VERIFICATION_FAILED, result.status)
        assertFalse(result.isLoadAllowed)
    }

    private fun verify(
        authors: List<TrustAuthor>,
        signatures: List<KeyHash>,
        trustedAuthors: Set<String> = emptySet(),
        trustedKeys: Set<KeyHash> = emptySet()
    ) = PluginVerifier.verify(
        packageInfo = packageInfo,
        signatures = signatures.map { SignatureInfo(it, false) },
        signatureDiagnostic = VerificationDiagnostic.NONE,
        trustList = authors.toTrustList(),
        trustListSource = TrustListSource.CURRENT,
        trustListExpired = false,
        userTrust = UserTrustSnapshot(trustedAuthors, trustedKeys, null, false),
        updateFailed = false
    )

    private fun List<TrustAuthor>.toTrustList() = TrustList(
        listVersion = 1,
        generatedAt = "2026-01-01T00:00:00Z",
        expiresAt = "2036-01-01T00:00:00Z",
        authors = this
    )

    private fun author(hash: KeyHash, state: KeyState) = TrustAuthor(
        TrustedAuthorInfo(
            uuid = "11111111-1111-1111-1111-111111111111",
            name = "Example Organization",
            type = AuthorType.ORG,
            confidence = 2,
            description = null,
            web = "https://example.invalid"
        ),
        listOf(TrustKey(hash, state, null, null))
    )

    private fun hash(character: Char): KeyHash {
        val sha256 = character.toString().repeat(64)
        val sha1 = character.toString().repeat(40)
        return KeyHash.parse("sha256:$sha256|sha1:$sha1")!!
    }
}
