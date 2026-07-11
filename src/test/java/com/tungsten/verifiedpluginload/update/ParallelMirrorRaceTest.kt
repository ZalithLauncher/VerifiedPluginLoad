package com.tungsten.verifiedpluginload.update

import com.tungsten.verifiedpluginload.api.VerifiedPluginLoadConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException

class ParallelMirrorRaceTest {
    @Test
    fun `fastest successful mirror wins`() {
        val startedAt = System.nanoTime()
        val result = ParallelMirrorRace.firstSuccessful(
            mirrors = listOf("slow", "fast"),
            download = { mirror ->
                Thread.sleep(if (mirror == "slow") 500 else 20)
                mirror
            },
            accept = { it }
        )

        val elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000
        assertEquals("fast", result)
        assertTrue("Mirrors should be fetched concurrently", elapsedMillis < 300)
    }

    @Test
    fun `rejected fastest mirror falls back to another mirror`() {
        val result = ParallelMirrorRace.firstSuccessful(
            mirrors = listOf("invalid", "valid"),
            download = { mirror ->
                Thread.sleep(if (mirror == "invalid") 10 else 50)
                mirror
            },
            accept = { mirror ->
                if (mirror == "invalid") throw IOException("Invalid signed response")
                mirror
            }
        )

        assertEquals("valid", result)
    }

    @Test
    fun `config builds both endpoints from every shared prefix`() {
        val config = VerifiedPluginLoadConfig(
            storageDirectory = File("build/test-vpl-config"),
            trustListUrlPrefixes = listOf("https://mirror-one.example/vpl/", "https://mirror-two.example/vpl"),
            trustListJsonSuffix = "trusted-authors.json",
            trustListSignatureSuffix = "trusted-authors.json.sig"
        )

        assertEquals(
            listOf(
                "https://mirror-one.example/vpl/trusted-authors.json",
                "https://mirror-two.example/vpl/trusted-authors.json"
            ),
            config.trustListMirrors.map { it.listUrl.toString() }
        )
        assertEquals(
            listOf(
                "https://mirror-one.example/vpl/trusted-authors.json.sig",
                "https://mirror-two.example/vpl/trusted-authors.json.sig"
            ),
            config.trustListMirrors.map { it.signatureUrl.toString() }
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `config rejects an incomplete split URL`() {
        VerifiedPluginLoadConfig(
            storageDirectory = File("build/test-vpl-config"),
            trustListUrlPrefixes = listOf("https://mirror.example/vpl"),
            trustListJsonSuffix = "trusted-authors.json"
        )
    }
}
