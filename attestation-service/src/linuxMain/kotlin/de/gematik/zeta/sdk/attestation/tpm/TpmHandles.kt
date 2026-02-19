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
import platform.posix.memset
import tpm.*

@OptIn(ExperimentalForeignApi::class)
internal fun setEmptyAuth(esys: CPointer<cnames.structs.ESYS_CONTEXT>, handle: ESYS_TR) = memScoped {
    val authValue = alloc<TPM2B_AUTH>()
    memset(authValue.ptr, 0, sizeOf<TPM2B_AUTH>().toULong())
    authValue.size = 0u

    val rc = Esys_TR_SetAuth(esys, handle, authValue.ptr)
    if (rc != TSS2_RC_SUCCESS) {
        throw TpmException("Failed to set auth", rc)
    }
}

@OptIn(ExperimentalForeignApi::class)
internal fun loadPersistentAsEsys(esys: CPointer<cnames.structs.ESYS_CONTEXT>, persistentHandle: UInt): ESYS_TR = memScoped {
    val esysHandle = alloc<ESYS_TRVar>()
    val rc = Esys_TR_FromTPMPublic(
        esys,
        persistentHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        esysHandle.ptr,
    )

    if (rc != TSS2_RC_SUCCESS) {
        throw TpmException("Failed to load persistent handle 0x${persistentHandle.toString(16)}", rc)
    }

    esysHandle.value
}

@OptIn(ExperimentalForeignApi::class)
internal fun closeEsysHandle(esys: CPointer<cnames.structs.ESYS_CONTEXT>, handle: ESYS_TR) = memScoped {
    if (handle == ESYS_TR_NONE) return@memScoped
    val h = alloc<ESYS_TRVar>()
    h.value = handle
    Esys_TR_Close(esys, h.ptr)
}

@OptIn(ExperimentalForeignApi::class)
internal fun flushTransient(esys: CPointer<cnames.structs.ESYS_CONTEXT>, handle: ESYS_TR) {
    if (handle == ESYS_TR_NONE) return
    Esys_FlushContext(esys, handle)
}
