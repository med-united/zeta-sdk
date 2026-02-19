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
import tpm.*

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.hasPersistentHandle(
    esys: CPointer<cnames.structs.ESYS_CONTEXT>,
    persistentHandle: UInt,
): Boolean {
    val tr = alloc<ESYS_TRVar>()
    val rc = Esys_TR_FromTPMPublic(
        esys,
        persistentHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        tr.ptr,
    )

    if (rc == TSS2_RC_SUCCESS) {
        closeEsysHandle(esys, tr.value)
        return true
    }
    return false
}

@OptIn(ExperimentalForeignApi::class)
internal inline fun <R> MemScope.withPersistentHandle(
    esys: CPointer<cnames.structs.ESYS_CONTEXT>,
    persistentHandle: UInt,
    block: (ESYS_TR) -> R,
): R {
    val tr = loadPersistentAsEsys(esys, persistentHandle)
    try {
        return block(tr)
    } finally {
        closeEsysHandle(esys, tr)
    }
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.readPublicKeyFromTr(
    esys: CPointer<cnames.structs.ESYS_CONTEXT>,
    tr: ESYS_TR,
): ByteArray {
    val publicPtr = alloc<CPointerVar<TPM2B_PUBLIC>>()
    val rc = Esys_ReadPublic(
        esys,
        tr,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        publicPtr.ptr,
        null,
        null,
    )
    if (rc != TSS2_RC_SUCCESS) throw TpmException("Failed to read public key", rc)

    val key = extractPublicKey(publicPtr.value)
    Esys_Free(publicPtr.value)
    return key
}
