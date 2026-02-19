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

import de.gematik.zeta.sdk.attestation.service.TpmException
import kotlinx.cinterop.*
import platform.posix.memcpy
import platform.posix.memset
import tpm.*

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.createQuote(ctx: TpmContext, qualifying: TPM2B_DATA, pcrSel: TPML_PCR_SELECTION, ak: ESYS_TR): Pair<ByteArray, ByteArray> {
    val scheme = allocEcdsaSha256Scheme()

    val quoted = alloc<CPointerVar<TPM2B_ATTEST>>()
    val signature = alloc<CPointerVar<TPMT_SIGNATURE>>()

    val rcQuote = Esys_Quote(
        ctx.esys,
        ak,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        qualifying.ptr,
        scheme.ptr,
        pcrSel.ptr,
        quoted.ptr,
        signature.ptr,
    )

    if (rcQuote != TSS2_RC_SUCCESS) {
        throw TpmException("Failed to generate quote", rcQuote)
    }

    val quotedPtr = quoted.value
        ?: throw TpmException("Quote returned null attestation data", rcQuote)

    val sigPtr = signature.value
        ?: throw TpmException("Quote returned null signature", rcQuote)

    val quoteBytes = marshalAttest(quotedPtr)
    val signatureBytes = marshalSignatureEcdsa(sigPtr)

    Esys_Free(quoted.value)
    Esys_Free(signature.value)

    return quoteBytes to signatureBytes
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.allocQualifyingData(qualifyingData: ByteArray): TPM2B_DATA {
    val used = qualifyingData.size.coerceAtMost(MAX_QUALIFYING_DATA_BYTES)

    val data = alloc<TPM2B_DATA>()
    memset(data.ptr, 0, sizeOf<TPM2B_DATA>().toULong())

    data.size = used.toUShort()
    for (i in 0 until used) {
        data.buffer[i] = qualifyingData[i].toUByte()
    }

    return data
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.allocEcdsaSha256Scheme(): TPMT_SIG_SCHEME =
    alloc<TPMT_SIG_SCHEME>().apply {
        scheme = TPM2_ALG_ECDSA
        details.ecdsa.hashAlg = TPM2_ALG_SHA256
    }

@OptIn(ExperimentalForeignApi::class)
internal fun marshalAttest(attest: CPointer<TPM2B_ATTEST>): ByteArray {
    val a = attest.pointed
    return a.attestationData.readBytes(a.size.toInt())
}

@OptIn(ExperimentalForeignApi::class)
internal fun marshalSignatureEcdsa(sigPtr: CPointer<TPMT_SIGNATURE>): ByteArray {
    val sig = sigPtr.pointed
    if (sig.sigAlg != TPM2_ALG_ECDSA) {
        throw TpmException("Unsupported signature algorithm: ${sig.sigAlg}", 0u)
    }
    val ecdsa = sig.signature.ecdsa
    val rLen = ecdsa.signatureR.size.toInt()
    val sLen = ecdsa.signatureS.size.toInt()

    val r = ByteArray(rLen)
    val s = ByteArray(sLen)

    r.usePinned { out ->
        memcpy(out.addressOf(0), ecdsa.signatureR.buffer, rLen.convert())
    }
    s.usePinned { out ->
        memcpy(out.addressOf(0), ecdsa.signatureS.buffer, sLen.convert())
    }

    return r + s
}
