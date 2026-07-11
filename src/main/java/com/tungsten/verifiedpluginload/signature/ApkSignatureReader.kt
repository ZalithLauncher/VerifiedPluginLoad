package com.tungsten.verifiedpluginload.signature

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import com.tungsten.verifiedpluginload.model.KeyHash
import com.tungsten.verifiedpluginload.model.PluginPackageInfo
import com.tungsten.verifiedpluginload.model.SignatureInfo
import com.tungsten.verifiedpluginload.model.VerificationDiagnostic
import java.io.File

internal data class SignatureReadResult(
    val packageInfo: PluginPackageInfo,
    val signatures: List<SignatureInfo>,
    val diagnostic: VerificationDiagnostic
)

internal class ApkSignatureReader(private val context: Context) {
    private val packageManager: PackageManager = context.packageManager

    fun inspectInstalled(packageName: String): SignatureReadResult {
        if (packageName.isBlank()) return failure(null, VerificationDiagnostic.PACKAGE_NOT_FOUND)
        return try {
            val info = getInstalledPackageInfo(packageName)
            toResult(info, installerPackageName(packageName))
        } catch (_: PackageManager.NameNotFoundException) {
            failure(PluginPackageInfo(packageName, null, null, null, null, null), VerificationDiagnostic.PACKAGE_NOT_FOUND)
        } catch (_: SecurityException) {
            failure(PluginPackageInfo(packageName, null, null, null, null, null), VerificationDiagnostic.SIGNATURE_EXTRACTION_FAILED)
        } catch (_: Exception) {
            failure(PluginPackageInfo(packageName, null, null, null, null, null), VerificationDiagnostic.SIGNATURE_EXTRACTION_FAILED)
        }
    }

    fun inspectArchive(apkFile: File): SignatureReadResult {
        if (!apkFile.isFile || !apkFile.canRead()) {
            return failure(
                PluginPackageInfo(null, null, null, null, apkFile.absolutePath, null),
                VerificationDiagnostic.APK_UNREADABLE
            )
        }
        return try {
            val archive = getArchivePackageInfo(apkFile.absolutePath)
                ?: return failure(
                    PluginPackageInfo(null, null, null, null, apkFile.absolutePath, null),
                    VerificationDiagnostic.APK_UNREADABLE
                )
            archive.applicationInfo?.apply {
                sourceDir = apkFile.absolutePath
                publicSourceDir = apkFile.absolutePath
            }
            toResult(archive, null)
        } catch (_: SecurityException) {
            failure(
                PluginPackageInfo(null, null, null, null, apkFile.absolutePath, null),
                VerificationDiagnostic.APK_UNREADABLE
            )
        } catch (_: Exception) {
            failure(
                PluginPackageInfo(null, null, null, null, apkFile.absolutePath, null),
                VerificationDiagnostic.SIGNATURE_EXTRACTION_FAILED
            )
        }
    }

    private fun toResult(info: PackageInfo, installer: String?): SignatureReadResult {
        val applicationInfo = info.applicationInfo
        val packageInfo = PluginPackageInfo(
            packageName = info.packageName,
            applicationLabel = applicationInfo?.let { runCatching { it.loadLabel(packageManager).toString() }.getOrNull() },
            versionName = info.versionName,
            versionCode = versionCode(info),
            apkPath = applicationInfo?.sourceDir,
            installerPackageName = installer,
            nativeLibraryDirectory = applicationInfo?.nativeLibraryDir
        )
        val signatures = extractSignatures(info)
        return if (signatures.isEmpty()) {
            failure(packageInfo, VerificationDiagnostic.APK_UNSIGNED)
        } else {
            SignatureReadResult(packageInfo, signatures, VerificationDiagnostic.NONE)
        }
    }

    private fun extractSignatures(info: PackageInfo): List<SignatureInfo> {
        val current = ArrayList<SignatureInfo>()
        val historical = ArrayList<SignatureInfo>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = info.signingInfo ?: return emptyList()
            signingInfo.apkContentsSigners.orEmpty().forEach { signature ->
                current += SignatureInfo(KeyHash.fromCertificate(signature.toByteArray()), historical = false)
            }
            if (!signingInfo.hasMultipleSigners() && signingInfo.hasPastSigningCertificates()) {
                val currentHashes = current.mapTo(HashSet()) { it.keyHash }
                signingInfo.signingCertificateHistory.orEmpty().forEach { signature ->
                    val hash = KeyHash.fromCertificate(signature.toByteArray())
                    if (hash !in currentHashes) historical += SignatureInfo(hash, historical = true)
                }
            }
        } else {
            @Suppress("DEPRECATION")
            info.signatures.orEmpty().forEach { signature: Signature ->
                current += SignatureInfo(KeyHash.fromCertificate(signature.toByteArray()), historical = false)
            }
        }
        return (current + historical).distinctBy { it.keyHash }
    }

    private fun getInstalledPackageInfo(packageName: String): PackageInfo = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> packageManager.getPackageInfo(
            packageName,
            PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
        )
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        }
        else -> {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        }
    }

    private fun getArchivePackageInfo(apkPath: String): PackageInfo? = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> packageManager.getPackageArchiveInfo(
            apkPath,
            PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
        )
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
            @Suppress("DEPRECATION")
            packageManager.getPackageArchiveInfo(apkPath, PackageManager.GET_SIGNING_CERTIFICATES)
        }
        else -> {
            @Suppress("DEPRECATION")
            packageManager.getPackageArchiveInfo(apkPath, PackageManager.GET_SIGNATURES)
        }
    }

    private fun installerPackageName(packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstallerPackageName(packageName)
        }
    } catch (_: Exception) {
        null
    }

    private fun versionCode(packageInfo: PackageInfo): Long = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        packageInfo.longVersionCode
    } else {
        @Suppress("DEPRECATION")
        packageInfo.versionCode.toLong()
    }

    private fun failure(packageInfo: PluginPackageInfo?, diagnostic: VerificationDiagnostic): SignatureReadResult =
        SignatureReadResult(
            packageInfo ?: PluginPackageInfo(null, null, null, null, null, null),
            emptyList(),
            diagnostic
        )
}
