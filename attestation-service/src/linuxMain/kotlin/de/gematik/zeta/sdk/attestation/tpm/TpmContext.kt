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

internal data class TpmContext @OptIn(ExperimentalForeignApi::class) constructor(
    val tcti: CPointerVar<TSS2_TCTI_CONTEXT>,
    val esys: CPointer<cnames.structs.ESYS_CONTEXT>,
)

@OptIn(ExperimentalForeignApi::class)
internal fun <R> MemScope.withTpmContext(block: (TpmContext) -> R): R {
    val ctx = initializeTpmContext()
    try {
        return block(ctx)
    } finally {
        cleanupContext(ctx)
    }
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.initializeTpmContext(): TpmContext {
    val tcti = alloc<CPointerVar<TSS2_TCTI_CONTEXT>>()
    val rcTcti = Tss2_TctiLdr_Initialize(null, tcti.ptr)
    if (rcTcti != TSS2_RC_SUCCESS) {
        throw TpmException("Failed to initialize TCTI", rcTcti)
    }

    val esys = alloc<CPointerVar<cnames.structs.ESYS_CONTEXT>>()
    val rcEsys = Esys_Initialize(esys.ptr, tcti.value, null)
    if (rcEsys != TSS2_RC_SUCCESS) {
        Tss2_TctiLdr_Finalize(tcti.ptr)
        throw TpmException("Failed to initialize ESYS", rcEsys)
    }

    val rcStartup = Esys_Startup(esys.value, TPM2_SU_CLEAR)
    val ok = rcStartup == TSS2_RC_SUCCESS || rcStartup == TPM2_RC_INITIALIZE
    if (!ok) {
        val esysPtr = alloc<CPointerVar<cnames.structs.ESYS_CONTEXT>>()
        esysPtr.value = esys.value
        Esys_Finalize(esysPtr.ptr)
        Tss2_TctiLdr_Finalize(tcti.ptr)
        throw TpmException("TPM startup failed", rcStartup)
    }

    return TpmContext(tcti, esys.value!!)
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.cleanupContext(context: TpmContext) {
    val esysPtr = alloc<CPointerVar<cnames.structs.ESYS_CONTEXT>>()
    esysPtr.value = context.esys
    Esys_Finalize(esysPtr.ptr)
    Tss2_TctiLdr_Finalize(context.tcti.ptr)
}
