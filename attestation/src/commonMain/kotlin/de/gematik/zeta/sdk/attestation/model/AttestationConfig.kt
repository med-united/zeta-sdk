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

package de.gematik.zeta.sdk.attestation.model

import de.gematik.zeta.sdk.attestation.AttestationService
import de.gematik.zeta.sdk.attestation.AttestationServiceApi
import de.gematik.zeta.sdk.attestation.TpmAttestationServiceConfig
import de.gematik.zeta.sdk.network.http.client.ZetaHttpClient
import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic

sealed class AttestationConfig {
    abstract val type: AttestationType
    abstract val statusCallback: AttestationStatusCallback?

    internal abstract fun getAttestationService(zetaHttpClient: ZetaHttpClient): AttestationService?

    data object Software : AttestationConfig() {
        override val statusCallback: AttestationStatusCallback? = null
        override val type: AttestationType = AttestationType.SOFTWARE

        override fun getAttestationService(zetaHttpClient: ZetaHttpClient): AttestationService? = null
    }

    data class TpmHttp(
        val attestationEndpoint: String,
        val pcrSelection: List<Int> = listOf(23),
        val websocketEndpoint: String? = null,
        override val statusCallback: AttestationStatusCallback? = null,
    ) : AttestationConfig() {
        override val type: AttestationType = AttestationType.TPM2

        override fun getAttestationService(zetaHttpClient: ZetaHttpClient): AttestationService {
            val config = TpmAttestationServiceConfig(
                attestationEndpoint,
                pcrSelection,
                websocketEndpoint = websocketEndpoint,
                statusCallback = statusCallback,
            )
            return AttestationServiceApi(config, zetaHttpClient)
        }
    }

    data class TpmCustom(
        val service: AttestationService,
        override val statusCallback: AttestationStatusCallback? = null,
    ) : AttestationConfig() {
        override val type: AttestationType = AttestationType.TPM2
        override fun getAttestationService(zetaHttpClient: ZetaHttpClient): AttestationService = service
    }

    companion object {
        @JvmStatic
        fun software(): AttestationConfig = Software

        @JvmStatic
        @JvmOverloads
        fun tpmHttp(
            attestationEndpoint: String,
            pcrSelection: List<Int> = listOf(23),
            websocketEndpoint: String? = null,
            statusCallback: AttestationStatusCallback? = null,
        ): AttestationConfig = TpmHttp(
            attestationEndpoint, pcrSelection,
            websocketEndpoint = websocketEndpoint,
            statusCallback = statusCallback,
        )

        @JvmStatic
        @JvmOverloads
        fun tpmCustom(
            service: AttestationService,
            statusCallback: AttestationStatusCallback? = null,
        ): AttestationConfig = TpmCustom(service, statusCallback)
    }
}

fun interface AttestationStatusCallback {
    fun onStatusChange(status: AttestationStatus)
}

sealed class AttestationStatus {
    data object OK : AttestationStatus()
    data class Degraded(val reason: String) : AttestationStatus()
    data class KO(val reason: String) : AttestationStatus()
}
