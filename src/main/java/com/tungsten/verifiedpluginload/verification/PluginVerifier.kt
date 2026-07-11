package com.tungsten.verifiedpluginload.verification

import com.tungsten.verifiedpluginload.model.KeyState
import com.tungsten.verifiedpluginload.model.PluginPackageInfo
import com.tungsten.verifiedpluginload.model.PluginTrustStatus
import com.tungsten.verifiedpluginload.model.PluginVerificationResult
import com.tungsten.verifiedpluginload.model.SignatureInfo
import com.tungsten.verifiedpluginload.model.TrustListSource
import com.tungsten.verifiedpluginload.model.TrustSource
import com.tungsten.verifiedpluginload.model.UserTrustSnapshot
import com.tungsten.verifiedpluginload.model.VerificationDiagnostic
import com.tungsten.verifiedpluginload.truststore.TrustAuthor
import com.tungsten.verifiedpluginload.truststore.TrustKey
import com.tungsten.verifiedpluginload.truststore.TrustList

internal object PluginVerifier {
    fun verify(
        packageInfo: PluginPackageInfo,
        signatures: List<SignatureInfo>,
        signatureDiagnostic: VerificationDiagnostic,
        trustList: TrustList,
        trustListSource: TrustListSource,
        trustListExpired: Boolean,
        userTrust: UserTrustSnapshot,
        updateFailed: Boolean
    ): PluginVerificationResult {
        val all = signatures.map { it.keyHash }
        val current = signatures.filterNot { it.historical }.map { it.keyHash }
        val contextualDiagnostic = when {
            signatureDiagnostic != VerificationDiagnostic.NONE -> signatureDiagnostic
            trustListExpired -> VerificationDiagnostic.TRUST_LIST_EXPIRED
            updateFailed -> VerificationDiagnostic.TRUST_LIST_UPDATE_FAILED
            trustListSource == TrustListSource.BUILTIN -> VerificationDiagnostic.TRUST_LIST_FALLBACK_TO_BUILTIN
            userTrust.recoveredFromCorruption -> VerificationDiagnostic.USER_TRUST_STORE_RECOVERED
            else -> VerificationDiagnostic.NONE
        }
        if (signatureDiagnostic != VerificationDiagnostic.NONE || current.isEmpty()) {
            return result(
                PluginTrustStatus.VERIFICATION_FAILED,
                packageInfo,
                null,
                all,
                current,
                signatures,
                null,
                null,
                null,
                trustListSource,
                trustList.listVersion,
                contextualDiagnostic
            )
        }

        // A current global revocation always wins over author and direct-key user trust.
        current.forEach { hash ->
            val match = trustList.find(hash)
            if (match?.second?.state == KeyState.BANNED) {
                return result(
                    PluginTrustStatus.BANNED,
                    packageInfo,
                    hash,
                    all,
                    current,
                    signatures,
                    match.first,
                    match.second,
                    null,
                    trustListSource,
                    trustList.listVersion,
                    contextualDiagnostic
                )
            }
        }

        val activeMatches = current.mapNotNull { hash ->
            trustList.find(hash)?.takeIf { it.second.state == KeyState.ACTIVE }?.let { Triple(hash, it.first, it.second) }
        }
        activeMatches.firstOrNull { (_, author, _) ->
            author.info.confidence > 0 && author.info.uuid in userTrust.trustedAuthorUuids
        }?.let { (hash, author, key) ->
            return result(
                PluginTrustStatus.TRUSTED,
                packageInfo,
                hash,
                all,
                current,
                signatures,
                author,
                key,
                TrustSource.AUTHOR,
                trustListSource,
                trustList.listVersion,
                contextualDiagnostic
            )
        }

        // A user may have explicitly trusted this certificate before a later trust-list update
        // associated it with an author. That concrete key decision must remain stable; only a
        // global ban can supersede it.
        current.firstOrNull { it in userTrust.trustedKeyHashes }?.let { hash ->
            return result(
                PluginTrustStatus.TRUSTED,
                packageInfo,
                hash,
                all,
                current,
                signatures,
                null,
                null,
                TrustSource.KEY,
                trustListSource,
                trustList.listVersion,
                contextualDiagnostic
            )
        }

        activeMatches.firstOrNull()?.let { (hash, author, key) ->
            return result(
                PluginTrustStatus.PENDING_TRUST,
                packageInfo,
                hash,
                all,
                current,
                signatures,
                author,
                key,
                null,
                trustListSource,
                trustList.listVersion,
                contextualDiagnostic
            )
        }

        return result(
            PluginTrustStatus.UNTRUSTED,
            packageInfo,
            null,
            all,
            current,
            signatures,
            null,
            null,
            null,
            trustListSource,
            trustList.listVersion,
            contextualDiagnostic
        )
    }

    private fun result(
        status: PluginTrustStatus,
        packageInfo: PluginPackageInfo,
        matchedSignature: com.tungsten.verifiedpluginload.model.KeyHash?,
        allSignatures: List<com.tungsten.verifiedpluginload.model.KeyHash>,
        currentSignatures: List<com.tungsten.verifiedpluginload.model.KeyHash>,
        signatureDetails: List<SignatureInfo>,
        author: TrustAuthor?,
        key: TrustKey?,
        trustSource: TrustSource?,
        trustListSource: TrustListSource,
        trustListVersion: Long,
        diagnostic: VerificationDiagnostic
    ) = PluginVerificationResult(
        status = status,
        packageInfo = packageInfo,
        matchedSignature = matchedSignature,
        allSignatures = allSignatures,
        currentSignatures = currentSignatures,
        signatureDetails = signatureDetails,
        author = author?.info,
        keyState = key?.state,
        keyDescription = key?.description,
        trustSource = trustSource,
        trustListSource = trustListSource,
        trustListVersion = trustListVersion,
        diagnostic = diagnostic
    )
}
