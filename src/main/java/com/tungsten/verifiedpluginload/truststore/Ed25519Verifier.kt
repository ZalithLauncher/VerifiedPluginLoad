package com.tungsten.verifiedpluginload.truststore

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.util.Base64

internal interface TrustListSignatureVerifier {
    fun verify(payload: ByteArray, signature: ByteArray): Boolean

    fun decodeSignature(raw: ByteArray): ByteArray?
}

internal object Ed25519Verifier : TrustListSignatureVerifier {
    // This key is compiled into the library and is never replaced by downloaded content.
    private const val VPL_TRUST_LIST_ROOT_PUBLIC_KEY = "xGnt0ttamxQLXQGLasD4u3ifcnQzUARm2nQMvFOJXeo="

    override fun verify(payload: ByteArray, signature: ByteArray): Boolean {
        val publicKey = try {
            Base64.getDecoder().decode(VPL_TRUST_LIST_ROOT_PUBLIC_KEY)
        } catch (_: IllegalArgumentException) {
            return false
        }
        return verifyWithPublicKey(payload, signature, publicKey)
    }

    internal fun verifyWithPublicKey(payload: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        if (signature.size != 64 || publicKey.size != 32) return false
        return try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            verifier.update(payload, 0, payload.size)
            verifier.verifySignature(signature)
        } catch (_: Exception) {
            false
        }
    }

    override fun decodeSignature(raw: ByteArray): ByteArray? {
        if (raw.size == 64) return raw
        return try {
            Base64.getMimeDecoder().decode(raw.toString(Charsets.US_ASCII).trim())
                .takeIf { it.size == 64 }
        } catch (_: IllegalArgumentException) {
            null
        }
    }
}
