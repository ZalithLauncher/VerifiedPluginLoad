package com.tungsten.verifiedpluginload.model

import java.security.MessageDigest
import java.util.Locale
import java.util.UUID

/** A canonical, complete SHA-256 and SHA-1 certificate fingerprint pair. */
class KeyHash private constructor(val value: String) {
    val sha256: String = value.substringAfter("sha256:").substringBefore("|sha1:")
    val sha1: String = value.substringAfter("|sha1:")

    override fun toString(): String = value

    override fun equals(other: Any?): Boolean = other is KeyHash && value == other.value

    override fun hashCode(): Int = value.hashCode()

    companion object {
        private val CANONICAL_PATTERN = Regex("sha256:[0-9A-F]{64}\\|sha1:[0-9A-F]{40}")

        fun fromCertificate(encodedCertificate: ByteArray): KeyHash = KeyHash(
            "sha256:${digestHex("SHA-256", encodedCertificate)}|sha1:${digestHex("SHA-1", encodedCertificate)}"
        )

        /**
         * Normalizes a user-supplied fingerprint. Stored and published trust-list values must
         * already be canonical; this method is intentionally only used for explicit user input.
         */
        fun parse(value: String): KeyHash? {
            val normalized = value.trim().lowercase(Locale.ROOT)
            val match = Regex("sha256:([0-9a-f]{64})\\|sha1:([0-9a-f]{40})").matchEntire(normalized)
                ?: return null
            return KeyHash("sha256:${match.groupValues[1].uppercase(Locale.ROOT)}|sha1:${match.groupValues[2].uppercase(Locale.ROOT)}")
        }

        internal fun parseCanonical(value: String): KeyHash? =
            if (CANONICAL_PATTERN.matches(value)) KeyHash(value) else null

        private fun digestHex(algorithm: String, bytes: ByteArray): String =
            MessageDigest.getInstance(algorithm).digest(bytes).joinToString("") { "%02X".format(it.toInt() and 0xFF) }
    }
}

enum class PluginTrustStatus {
    TRUSTED,
    PENDING_TRUST,
    UNTRUSTED,
    BANNED,
    VERIFICATION_FAILED
}

enum class KeyState { ACTIVE, BANNED }

enum class TrustSource { AUTHOR, KEY }

enum class TrustListSource { CURRENT, PREVIOUS, BUILTIN, UNAVAILABLE }

enum class VerificationDiagnostic {
    NONE,
    PACKAGE_NOT_FOUND,
    APK_UNREADABLE,
    APK_UNSIGNED,
    SIGNATURE_EXTRACTION_FAILED,
    TRUST_LIST_FALLBACK_TO_BUILTIN,
    TRUST_LIST_UPDATE_FAILED,
    TRUST_LIST_EXPIRED,
    USER_TRUST_STORE_RECOVERED,
    NOT_INITIALIZED
}

enum class AuthorType { PERSON, ORG }

data class TrustedAuthorInfo(
    val uuid: String,
    val name: String,
    val type: AuthorType,
    val confidence: Int,
    val description: String?,
    val web: String?
)

data class SignatureInfo(
    val keyHash: KeyHash,
    val historical: Boolean
)

data class PluginPackageInfo(
    val packageName: String?,
    val applicationLabel: String?,
    val versionName: String?,
    val versionCode: Long?,
    val apkPath: String?,
    val installerPackageName: String?,
    val nativeLibraryDirectory: String? = null
)

data class PluginVerificationResult(
    val status: PluginTrustStatus,
    val packageInfo: PluginPackageInfo,
    val matchedSignature: KeyHash?,
    val allSignatures: List<KeyHash>,
    val currentSignatures: List<KeyHash>,
    val signatureDetails: List<SignatureInfo>,
    val author: TrustedAuthorInfo?,
    val keyState: KeyState?,
    val keyDescription: String?,
    val trustSource: TrustSource?,
    val trustListSource: TrustListSource,
    val trustListVersion: Long?,
    val diagnostic: VerificationDiagnostic
) {
    val isLoadAllowed: Boolean
        get() = status == PluginTrustStatus.TRUSTED

    /** Creates the immutable snapshot consumed by the final native-load guard. */
    fun toLoadAuthorization(): PluginLoadAuthorization? {
        if (!isLoadAllowed || packageInfo.packageName == null || packageInfo.apkPath == null || currentSignatures.isEmpty()) {
            return null
        }
        return PluginLoadAuthorization(
            packageName = packageInfo.packageName,
            apkPath = packageInfo.apkPath,
            versionCode = packageInfo.versionCode,
            currentSignatures = currentSignatures.toSet()
        )
    }
}

/**
 * A verification snapshot. The launcher re-verifies this snapshot immediately before loading
 * native code, so this is not a substitute for a fresh signature check.
 */
class PluginLoadAuthorization internal constructor(
    val packageName: String,
    val apkPath: String,
    val versionCode: Long?,
    val currentSignatures: Set<KeyHash>
) {
    override fun equals(other: Any?): Boolean = other is PluginLoadAuthorization &&
        packageName == other.packageName &&
        apkPath == other.apkPath &&
        versionCode == other.versionCode &&
        currentSignatures == other.currentSignatures

    override fun hashCode(): Int = arrayOf(packageName, apkPath, versionCode, currentSignatures).contentHashCode()
}

data class UserTrustSnapshot(
    val trustedAuthorUuids: Set<String>,
    val trustedKeyHashes: Set<KeyHash>,
    val updatedAt: String?,
    val recoveredFromCorruption: Boolean
)

enum class TrustActionStatus {
    SUCCESS,
    NOT_FOUND,
    INVALID_AUTHOR_UUID,
    INVALID_KEY_HASH,
    AUTHOR_NOT_REGISTERED,
    AUTHOR_NOT_TRUSTABLE,
    KEY_BANNED,
    STORAGE_ERROR
}

data class TrustActionResult(
    val status: TrustActionStatus,
    val snapshot: UserTrustSnapshot
)

data class InitializationResult(
    val trustListSource: TrustListSource,
    val trustListVersion: Long?,
    val diagnostic: VerificationDiagnostic,
    val userTrustRecoveredFromCorruption: Boolean
)

enum class TrustListRefreshStatus {
    UPDATED,
    NOT_MODIFIED,
    NOT_CONFIGURED,
    REJECTED_SIGNATURE,
    REJECTED_SCHEMA,
    REJECTED_ROLLBACK,
    NETWORK_ERROR,
    STORAGE_ERROR
}

data class TrustListRefreshResult(
    val status: TrustListRefreshStatus,
    val trustListVersion: Long?,
    val message: String? = null
)

internal fun normalizeUuid(value: String): String? = try {
    UUID.fromString(value).toString()
} catch (_: IllegalArgumentException) {
    null
}
