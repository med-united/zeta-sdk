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

package de.gematik.zeta.sdk.attestation.tpm

import de.gematik.zeta.sdk.attestation.model.TpmQuoteResult

actual class TpmAccess actual constructor() {

    private val storage = mutableMapOf<Int, ByteArray>()

    actual fun generateQuote(
        attChallengeBytes: ByteArray,
        pcrSelection: List<Int>,
    ): TpmQuoteResult {
        return TpmQuoteResult(byteArrayOf(), byteArrayOf(), byteArrayOf())
    }

    actual fun readPCRs(pcrSelection: List<Int>): Map<Int, ByteArray> {
        return pcrSelection.mapNotNull { pcr ->
            storage[pcr]?.let { hash -> pcr to hash }
        }.toMap()
    }

    actual fun isAvailable(): Boolean {
        return true
    }

    actual fun extendPCR(pcrIndex: Int, data: ByteArray) {
        storage[pcrIndex] = data
    }

    actual fun resetPCR(pcrIndex: Int) {
        storage.clear()
    }

    actual fun removeAttestationKey() {
    }

    actual fun getEventLog(): ByteArray = byteArrayOf(0)
    actual fun getEKCertificateChain(): List<ByteArray> = emptyList()
    actual fun provisionAttestationKey(): ByteArray = byteArrayOf(0)
}
