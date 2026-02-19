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

@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")
package de.gematik.zeta.sdk.attestation.tpm

import kotlinx.cinterop.*
import platform.posix.memset
import tpm.*

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.buildPcrSelection(pcrs: List<Int>): TPML_PCR_SELECTION {
    val selection = alloc<TPML_PCR_SELECTION>()
    memset(selection.ptr, 0, sizeOf<TPML_PCR_SELECTION>().toULong())

    selection.count = 1u
    selection.pcrSelections[0].hash = TPM2_ALG_SHA256
    selection.pcrSelections[0].sizeofSelect = PCR_SELECTION_BYTES

    memset(selection.pcrSelections[0].pcrSelect, 0, PCR_SELECTION_BYTES.toULong())

    pcrs.forEach { pcr ->
        requirePcrIndex(pcr)
        val byteIndex = pcr / 8
        val bitIndex = pcr % 8
        val cur = selection.pcrSelections[0].pcrSelect[byteIndex].toInt() and 0xFF
        selection.pcrSelections[0].pcrSelect[byteIndex] = (cur or (1 shl bitIndex)).toUByte()
    }

    return selection
}

@OptIn(ExperimentalForeignApi::class)
internal fun extractPcrValues(digestList: CPointer<TPML_DIGEST>?, selectedPcrs: List<Int>): Map<Int, ByteArray> {
    val list = requireNotNull(digestList).pointed
    val result = mutableMapOf<Int, ByteArray>()

    val count = minOf(list.count.toInt(), selectedPcrs.size)
    for (i in 0 until count) {
        val digest = list.digests[i]
        val value = digest.buffer.readBytes(digest.size.toInt())
        result[selectedPcrs[i]] = value
    }

    return result
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.buildDigestValues(hash: ByteArray): CValue<TPML_DIGEST_VALUES> {
    return alloc<TPML_DIGEST_VALUES> {
        count = 1u
        digests[0].hashAlg = TPM2_ALG_SHA256

        hash.forEachIndexed { index, byte ->
            digests[0].digest.sha256[index] = byte.toUByte()
        }
    }.readValue()
}
