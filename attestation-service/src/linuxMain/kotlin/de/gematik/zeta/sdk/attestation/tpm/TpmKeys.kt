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
internal fun MemScope.createPrimaryKey(esys: CPointer<cnames.structs.ESYS_CONTEXT>): ESYS_TR {
    val inSensitive = allocSensitiveCreate()
    val inPublic = allocPrimaryPublic()
    val outsideInfo = allocData()
    val creationPCR = allocPcrSelectionEmpty()
    val handle = alloc<ESYS_TRVar>()

    val rc = Esys_CreatePrimary(
        esys,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        inSensitive.ptr,
        inPublic.ptr,
        outsideInfo.ptr,
        creationPCR.ptr,
        handle.ptr,
        null, null, null, null,
    )

    if (rc != TSS2_RC_SUCCESS) {
        throw TpmException("Failed to create primary key", rc)
    }

    return handle.value
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.createAttestationKey(
    esys: CPointer<cnames.structs.ESYS_CONTEXT>,
    primary: ESYS_TR,
): Pair<ESYS_TR, ByteArray> {
    val inSensitive = allocSensitiveCreate()
    val inPublic = allocAttestationPublic()
    val outsideInfo = allocData()
    val creationPCR = allocPcrSelectionEmpty()

    val outPrivate = alloc<CPointerVar<TPM2B_PRIVATE>>()
    val outPublic = alloc<CPointerVar<TPM2B_PUBLIC>>()

    val rcCreate = Esys_Create(
        esys, primary,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        inSensitive.ptr, inPublic.ptr, outsideInfo.ptr, creationPCR.ptr,
        outPrivate.ptr, outPublic.ptr, null, null, null,
    )

    if (rcCreate != TSS2_RC_SUCCESS) {
        throw TpmException("Failed to create attestation key", rcCreate)
    }

    val ak = loadAttestationKey(esys, primary, outPrivate.value, outPublic.value)
    val publicKey = extractPublicKey(outPublic.value)

    Esys_Free(outPrivate.value)
    Esys_Free(outPublic.value)

    return ak to publicKey
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.loadAttestationKey(
    esys: CPointer<cnames.structs.ESYS_CONTEXT>,
    primary: ESYS_TR,
    privateBlob: CPointer<TPM2B_PRIVATE>?,
    publicBlob: CPointer<TPM2B_PUBLIC>?,
): ESYS_TR {
    val handle = alloc<ESYS_TRVar>()
    val rc = Esys_Load(
        esys, primary,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        privateBlob, publicBlob, handle.ptr,
    )

    if (rc != TSS2_RC_SUCCESS) {
        throw TpmException("Failed to load attestation key", rc)
    }

    return handle.value
}

@OptIn(ExperimentalForeignApi::class)
internal fun extractPublicKey(publicBlob: CPointer<TPM2B_PUBLIC>?): ByteArray {
    val pub = requireNotNull(publicBlob).pointed.publicArea
    require(pub.type == TPM2_ALG_ECC) { "AK is not ECC" }

    val xLen = pub.unique.ecc.x.size.toInt()
    val yLen = pub.unique.ecc.y.size.toInt()
    val x = ByteArray(xLen)
    val y = ByteArray(yLen)

    x.usePinned { out ->
        memcpy(out.addressOf(0), pub.unique.ecc.x.buffer, xLen.convert())
    }
    y.usePinned { out ->
        memcpy(out.addressOf(0), pub.unique.ecc.y.buffer, yLen.convert())
    }
    return x + y
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.allocSensitiveCreate(): TPM2B_SENSITIVE_CREATE {
    val sensitive = alloc<TPM2B_SENSITIVE_CREATE>()
    memset(sensitive.ptr, 0, sizeOf<TPM2B_SENSITIVE_CREATE>().toULong())
    sensitive.size = 4u
    sensitive.sensitive.userAuth.size = 0u
    sensitive.sensitive.data.size = 0u
    return sensitive
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.allocPrimaryPublic(): TPM2B_PUBLIC {
    val pub = alloc<TPM2B_PUBLIC>()
    memset(pub.ptr, 0, sizeOf<TPM2B_PUBLIC>().toULong())
    pub.size = sizeOf<TPMT_PUBLIC>().toUShort()

    with(pub.publicArea) {
        type = TPM2_ALG_ECC
        nameAlg = TPM2_ALG_SHA256
        objectAttributes = PRIMARY_OBJECT_ATTRIBUTES
        authPolicy.size = 0u

        with(parameters.eccDetail) {
            symmetric.algorithm = TPM2_ALG_AES
            symmetric.keyBits.aes = 128u
            symmetric.mode.aes = TPM2_ALG_CFB
            scheme.scheme = TPM2_ALG_NULL
            curveID = ECC_CURVE
            kdf.scheme = TPM2_ALG_NULL
        }
        unique.ecc.x.size = 0u
        unique.ecc.y.size = 0u
    }

    return pub
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.allocAttestationPublic(): TPM2B_PUBLIC {
    val pub = alloc<TPM2B_PUBLIC>()
    memset(pub.ptr, 0, sizeOf<TPM2B_PUBLIC>().toULong())
    pub.size = sizeOf<TPMT_PUBLIC>().toUShort()

    with(pub.publicArea) {
        type = TPM2_ALG_ECC
        nameAlg = HASH_ALG

        objectAttributes = ATTESTATION_OBJECT_ATTRIBUTES
        authPolicy.size = 0u
        with(parameters.eccDetail) {
            symmetric.algorithm = TPM2_ALG_NULL
            scheme.scheme = AK_SIG_SCHEME
            scheme.details.ecdsa.hashAlg = HASH_ALG
            curveID = ECC_CURVE
            kdf.scheme = TPM2_ALG_NULL
        }
        unique.ecc.x.size = 0u
        unique.ecc.y.size = 0u
    }

    return pub
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.allocData(): TPM2B_DATA {
    val data = alloc<TPM2B_DATA>()
    memset(data.ptr, 0, sizeOf<TPM2B_DATA>().toULong())
    data.size = 0u
    return data
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.allocPcrSelectionEmpty(): TPML_PCR_SELECTION {
    val pcr = alloc<TPML_PCR_SELECTION>()
    memset(pcr.ptr, 0, sizeOf<TPML_PCR_SELECTION>().toULong())
    pcr.count = 0u
    return pcr
}

@OptIn(ExperimentalForeignApi::class)
internal fun MemScope.ensureAkPersistent(
    esys: CPointer<cnames.structs.ESYS_CONTEXT>,
    persistentHandle: UInt,
): ByteArray {
    require(persistentHandle in PERSISTENT_HANDLE_MIN..PERSISTENT_HANDLE_MAX) {
        "Persistent handle must be in range 0x${PERSISTENT_HANDLE_MIN.toString(16)}-0x${PERSISTENT_HANDLE_MAX.toString(16)}"
    }
    if (hasPersistentHandle(esys, persistentHandle)) {
        return withPersistentHandle(esys, persistentHandle) { tr ->
            setEmptyAuth(esys, tr)
            readPublicKeyFromTr(esys, tr)
        }
    }

    val primary = createPrimaryKey(esys)
    var akTransient: ESYS_TR = ESYS_TR_NONE
    try {
        val created = createAttestationKey(esys, primary)
        akTransient = created.first
        val akPublic = created.second

        val outHandle = alloc<ESYS_TRVar>()
        val rc = Esys_EvictControl(
            esys,
            ESYS_TR_RH_OWNER,
            akTransient,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            persistentHandle,
            outHandle.ptr,
        )
        if (rc != TSS2_RC_SUCCESS) {
            throw TpmException("Failed to persist AK at 0x${persistentHandle.toString(16)}", rc)
        }

        return akPublic
    } finally {
        flushTransient(esys, akTransient)
        flushTransient(esys, primary)
    }
}
