package com.tungsten.verifiedpluginload.truststore

import com.tungsten.verifiedpluginload.model.KeyHash
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustListParserTest {
    private val hash = "sha256:${"A".repeat(64)}|sha1:${"B".repeat(40)}"

    @Test
    fun `strict parser accepts valid canonical trust list`() {
        val list = TrustListParser.parse(validJson().toByteArray())

        assertEquals(7, list.listVersion)
        assertEquals(1, list.authors.size)
        assertEquals(KeyHash.parse(hash), list.authors.single().hashes.single().hash)
    }

    @Test(expected = TrustListParseException::class)
    fun `strict parser rejects duplicate root fields`() {
        TrustListParser.parse(validJson().replace("\"list_version\":7", "\"list_version\":7,\"list_version\":8").toByteArray())
    }

    @Test(expected = TrustListParseException::class)
    fun `strict parser rejects duplicate global hashes`() {
        val duplicated = validJson().replace(
            "\"keys\":[",
            "\"keys\":[${authorJson("22222222-2222-2222-2222-222222222222")},"
        )
        TrustListParser.parse(duplicated.toByteArray())
    }

    @Test
    fun `signature verifier rejects invalid remote signature`() {
        assertFalse(Ed25519Verifier.verify(validJson().toByteArray(), ByteArray(64)))
    }

    @Test
    fun `signature verifier accepts RFC 8032 Ed25519 test vector`() {
        val publicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        val signature = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )

        assertTrue(Ed25519Verifier.verifyWithPublicKey(ByteArray(0), signature, publicKey))
    }

    @Test(expected = TrustListParseException::class)
    fun `strict parser rejects unsupported format version`() {
        TrustListParser.parse(validJson().replace("\"format_version\":1", "\"format_version\":2").toByteArray())
    }

    @Test(expected = TrustListParseException::class)
    fun `strict parser rejects truncated payload`() {
        TrustListParser.parse(validJson().dropLast(1).toByteArray())
    }

    @Test(expected = TrustListParseException::class)
    fun `strict parser rejects duplicate author UUID`() {
        val duplicated = validJson().replace(
            "\"keys\":[",
            "\"keys\":[${authorJson("11111111-1111-1111-1111-111111111111")},"
        )
        TrustListParser.parse(duplicated.toByteArray())
    }

    @Test(expected = TrustListParseException::class)
    fun `strict parser rejects noncanonical certificate hash`() {
        TrustListParser.parse(validJson().replace(hash, hash.lowercase()).toByteArray())
    }

    private fun validJson(): String = """
        {"format_version":1,"list_version":7,"generated_at":"2026-01-01T00:00:00Z","expires_at":"2036-01-01T00:00:00Z","keys":[${authorJson("11111111-1111-1111-1111-111111111111")}]}
    """.trimIndent()

    private fun authorJson(uuid: String): String = """
        {"uuid":"$uuid","name":"Example","type":"org","confidence":2,"description":"Example author","web":"https://example.invalid","hashes":[{"value":"$hash","state":"active"}]}
    """.trimIndent()

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
