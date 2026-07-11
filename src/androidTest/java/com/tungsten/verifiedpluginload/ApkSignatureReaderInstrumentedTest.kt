package com.tungsten.verifiedpluginload

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.tungsten.verifiedpluginload.api.VerifiedPluginLoadBlocking
import com.tungsten.verifiedpluginload.api.VerifiedPluginLoadConfig
import com.tungsten.verifiedpluginload.api.VerifiedPluginLoadFactory
import com.tungsten.verifiedpluginload.model.PluginTrustStatus
import com.tungsten.verifiedpluginload.model.TrustListSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class ApkSignatureReaderInstrumentedTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun readsInstalledPackageSigningCertificate() {
        val vpl = newVpl("installed")
        VerifiedPluginLoadBlocking.initialize(vpl)

        val result = vpl.inspectInstalledPackage(context.packageName)

        assertFalse(result.status == PluginTrustStatus.VERIFICATION_FAILED)
        assertTrue(result.currentSignatures.isNotEmpty())
        assertTrue(result.packageInfo.apkPath != null)
    }

    @Test
    fun readsArchiveSigningCertificate() {
        val source = File(context.applicationInfo.sourceDir)
        val archive = File(context.cacheDir, "vpl-test-archive.apk")
        source.copyTo(archive, overwrite = true)
        val vpl = newVpl("archive")

        val result = vpl.inspectApkFile(archive)

        assertFalse(result.status == PluginTrustStatus.VERIFICATION_FAILED)
        assertTrue(result.currentSignatures.isNotEmpty())
        assertEquals(archive.absolutePath, result.packageInfo.apkPath)
    }

    @Test
    fun unreadableArchiveIsNeverPresentedAsTrustable() {
        val vpl = newVpl("unreadable")
        val result = vpl.inspectApkFile(File(context.cacheDir, "missing.apk"))

        assertEquals(PluginTrustStatus.VERIFICATION_FAILED, result.status)
        assertFalse(result.isLoadAllowed)
    }

    @Test
    fun initializationAndInspectionAreSerializedAcrossConcurrentCallers() {
        val vpl = newVpl("concurrency")
        val executor = Executors.newFixedThreadPool(4)
        try {
            val futures = (0 until 8).map {
                executor.submit(Callable {
                    VerifiedPluginLoadBlocking.initialize(vpl)
                    vpl.inspectInstalledPackage(context.packageName).status
                })
            }
            futures.forEach { future ->
                assertTrue(future.get(15, TimeUnit.SECONDS) != PluginTrustStatus.VERIFICATION_FAILED)
            }
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun unavailableStorageFallsBackToSignedBuiltinList() {
        val storagePath = File(context.cacheDir, "vpl-not-a-directory-${System.nanoTime()}")
        storagePath.writeText("not a directory")
        val vpl = VerifiedPluginLoadFactory.create(context, VerifiedPluginLoadConfig(storagePath))

        val initialization = VerifiedPluginLoadBlocking.initialize(vpl)

        assertEquals(TrustListSource.BUILTIN, initialization.trustListSource)
        assertFalse(vpl.inspectInstalledPackage(context.packageName).status == PluginTrustStatus.VERIFICATION_FAILED)
    }

    private fun newVpl(name: String) = VerifiedPluginLoadFactory.create(
        context,
        VerifiedPluginLoadConfig(File(context.cacheDir, "vpl-instrumentation-$name"))
    )
}
