/*
 * #%L
 * ZETA-Client
 * %%
 * (C) EY Strategy & Transactions GmbH, 2025, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

package de.gematik.zeta.sdk.network.http.client.config.tls

import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaCertificateValidator.ZetaCertificateAlgorithms.ALLOWED_CURVES_NORMALIZED
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaCertificateValidator.ZetaCertificateAlgorithms.MIN_EC_KEY_BITS

public data class CertificateValidationResult(
    val isValid: Boolean,
    val errors: List<String>,
    val warnings: List<String>,
)

public data class ZetaCertInfo(
    val subjectDN: String,
    val sigAlgName: String,
    val keyAlgorithm: String,
    val keySize: Int,
    val curveName: String? = null,
    val notBefore: Long,
    val notAfter: Long,
    val san: List<String> = emptyList(),
)

public object ZetaCertificateValidator {
    public object ZetaCertificateAlgorithms {
        public val ALLOWED_SIGNATURE_ALGORITHMS: Set<String> = setOf(
            "SHA256WITHECDSA",
            "SHA384WITHECDSA",
        )
        public val FORBIDDEN_SIGNATURE_ALGORITHMS: Set<String> = setOf(
            "SHA1WITHECDSA",
            "SHA1WITHRSA",
            "MD5WITHRSA",
            "MD2WITHRSA",
        )
        internal val ALLOWED_CURVES_NORMALIZED: Set<String> =
            ZetaTlsCurves.ALLOWED.map { it.normalize() }.toSet()

        public const val EC_P256_KEY_SIZE_BITS: Int = 256
        public const val EC_P384_KEY_SIZE_BITS: Int = 384
        public const val MIN_EC_KEY_BITS: Int = EC_P256_KEY_SIZE_BITS
    }

    public fun validate(
        cert: ZetaCertInfo,
        nowEpochSeconds: Long,
        host: String? = null,
        isLeaf: Boolean = true,
    ): CertificateValidationResult {
        val errors = buildList {
            addAll(validateSignatureAlgorithm(cert, isLeaf))
            addAll(validateKeyAlgorithm(cert, isLeaf))
            addAll(validateValidity(cert, nowEpochSeconds))
            if (host != null) addAll(validateSan(cert, host))
        }
        return CertificateValidationResult(errors.isEmpty(), errors, emptyList())
    }

    private fun validateSignatureAlgorithm(cert: ZetaCertInfo, isLeaf: Boolean): List<String> {
        val sigAlg = cert.sigAlgName.normalize()
        return when {
            sigAlg in ZetaCertificateAlgorithms.FORBIDDEN_SIGNATURE_ALGORITHMS ->
                listOf("Forbidden signature algorithm '${cert.sigAlgName}' in cert: ${cert.subjectDN}")
            isLeaf && sigAlg !in ZetaCertificateAlgorithms.ALLOWED_SIGNATURE_ALGORITHMS ->
                listOf("Signature algorithm '${cert.sigAlgName}' is not allowed")
            else -> emptyList()
        }
    }

    private fun validateKeyAlgorithm(cert: ZetaCertInfo, isLeaf: Boolean): List<String> =
        when (cert.keyAlgorithm.uppercase()) {
            "EC" -> validateEcKey(cert)
            else -> if (isLeaf) listOf("Key algorithm '${cert.keyAlgorithm}' is not allowed") else emptyList()
        }

    private fun validateEcKey(cert: ZetaCertInfo): List<String> = buildList {
        if (cert.keySize < MIN_EC_KEY_BITS) {
            add("EC key too small: ${cert.keySize} (min: $MIN_EC_KEY_BITS)")
        }
        when (cert.curveName) {
            null -> add("EC certificate has no named curve")
            else -> if (cert.curveName.normalize() !in ALLOWED_CURVES_NORMALIZED) {
                add("EC curve '${cert.curveName}' is not allowed")
            }
        }
    }

    private fun validateValidity(cert: ZetaCertInfo, nowEpochSeconds: Long): List<String> = buildList {
        if (nowEpochSeconds < cert.notBefore) add("Certificate not yet valid: ${cert.subjectDN}")
        if (nowEpochSeconds > cert.notAfter) add("Certificate has expired: ${cert.subjectDN}")
    }

    private fun validateSan(cert: ZetaCertInfo, host: String): List<String> =
        if (cert.san.none { sanMatchesHost(it, host) }) {
            listOf("Certificate SAN does not match host '$host': ${cert.san}")
        } else {
            emptyList()
        }

    public fun validateChain(
        chain: List<ZetaCertInfo>,
        nowEpochSeconds: Long,
    ): CertificateValidationResult {
        val results = chain.mapIndexed { index, cert ->
            validate(
                cert = cert,
                nowEpochSeconds = nowEpochSeconds,
                isLeaf = index == 0,
            )
        }
        return CertificateValidationResult(
            isValid = results.all { it.isValid },
            errors = results.flatMap { it.errors },
            warnings = results.flatMap { it.warnings },
        )
    }

    private fun String.normalize() = uppercase().replace("-", "").replace("_", "")
}
