package com.tungsten.verifiedpluginload.userstore

import com.tungsten.verifiedpluginload.model.KeyHash
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class UserTrustStoreTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `corrupt current user trust falls back to previous valid snapshot`() {
        val directory = temporaryFolder.newFolder("vpl")
        val first = hash('A')
        val second = hash('B')
        val store = UserTrustStore(directory)

        store.trustKey(first)
        store.trustKey(second) // This preserves the first snapshot as user-trust.previous.json.
        directory.resolve("user-trust.json").writeText("{truncated")

        val recovered = UserTrustStore(directory).snapshot()

        assertTrue(recovered.recoveredFromCorruption)
        assertEquals(setOf(first), recovered.trustedKeyHashes)
    }

    private fun hash(character: Char): KeyHash = KeyHash.parse(
        "sha256:${character.toString().repeat(64)}|sha1:${character.toString().repeat(40)}"
    )!!
}
