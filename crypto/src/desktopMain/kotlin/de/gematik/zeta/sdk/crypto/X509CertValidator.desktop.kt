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

package de.gematik.zeta.sdk.crypto

import de.gematik.zeta.logging.Log
import de.gematik.zeta.sdk.crypto.openssl.ASN1_STRING_get0_data
import de.gematik.zeta.sdk.crypto.openssl.ASN1_STRING_length
import de.gematik.zeta.sdk.crypto.openssl.ASN1_TIME
import de.gematik.zeta.sdk.crypto.openssl.ASN1_TIME_compare
import de.gematik.zeta.sdk.crypto.openssl.ASN1_TIME_set
import de.gematik.zeta.sdk.crypto.openssl.EVP_PKEY_free
import de.gematik.zeta.sdk.crypto.openssl.GENERAL_NAME
import de.gematik.zeta.sdk.crypto.openssl.GEN_DNS
import de.gematik.zeta.sdk.crypto.openssl.NID_subject_alt_name
import de.gematik.zeta.sdk.crypto.openssl.OBJ_txt2obj
import de.gematik.zeta.sdk.crypto.openssl.OPENSSL_STACK
import de.gematik.zeta.sdk.crypto.openssl.OPENSSL_sk_free
import de.gematik.zeta.sdk.crypto.openssl.OPENSSL_sk_new_null
import de.gematik.zeta.sdk.crypto.openssl.OPENSSL_sk_num
import de.gematik.zeta.sdk.crypto.openssl.OPENSSL_sk_push
import de.gematik.zeta.sdk.crypto.openssl.OPENSSL_sk_value
import de.gematik.zeta.sdk.crypto.openssl.X509
import de.gematik.zeta.sdk.crypto.openssl.X509_EXTENSION_get_data
import de.gematik.zeta.sdk.crypto.openssl.X509_STORE_CTX_free
import de.gematik.zeta.sdk.crypto.openssl.X509_STORE_CTX_get_error
import de.gematik.zeta.sdk.crypto.openssl.X509_STORE_CTX_init
import de.gematik.zeta.sdk.crypto.openssl.X509_STORE_CTX_new
import de.gematik.zeta.sdk.crypto.openssl.X509_STORE_add_cert
import de.gematik.zeta.sdk.crypto.openssl.X509_STORE_free
import de.gematik.zeta.sdk.crypto.openssl.X509_STORE_new
import de.gematik.zeta.sdk.crypto.openssl.X509_free
import de.gematik.zeta.sdk.crypto.openssl.X509_get0_notAfter
import de.gematik.zeta.sdk.crypto.openssl.X509_get0_notBefore
import de.gematik.zeta.sdk.crypto.openssl.X509_get_ext
import de.gematik.zeta.sdk.crypto.openssl.X509_get_ext_by_OBJ
import de.gematik.zeta.sdk.crypto.openssl.X509_get_ext_d2i
import de.gematik.zeta.sdk.crypto.openssl.X509_get_pubkey
import de.gematik.zeta.sdk.crypto.openssl.X509_verify_cert
import de.gematik.zeta.sdk.crypto.openssl.X509_verify_cert_error_string
import de.gematik.zeta.sdk.crypto.openssl.d2i_X509
import de.gematik.zeta.sdk.crypto.openssl.i2d_PUBKEY
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.refTo
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.toKString
import kotlinx.cinterop.value
import platform.posix.time
import platform.posix.time_t
import kotlin.sequences.generateSequence

@OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
actual class X509CertValidator actual constructor() {
    private val oidAdmission = "1.3.36.8.3.3"
    val certificateParsingErrorMessage = "Failed to parse certificate"
    actual fun checkValidity(certDer: ByteArray) = memScoped {
        val pCert = alloc<CPointerVar<UByteVar>>()
        pCert.value = certDer.refTo(0).getPointer(this).reinterpret()
        val cert = d2i_X509(null, pCert.ptr, certDer.size.convert())
            ?: error(certificateParsingErrorMessage)

        try {
            val notBefore = X509_get0_notBefore(cert)
                ?: error("Failed to get notBefore")
            val notAfter = X509_get0_notAfter(cert)
                ?: error("Failed to get notAfter")

            val now = time(null)

            val cmpBefore = ASN1_TIME_compare(notBefore, createAsn1Time(now))
            require(cmpBefore <= 0) { "Certificate not yet valid" }

            val cmpAfter = ASN1_TIME_compare(notAfter, createAsn1Time(now))
            require(cmpAfter >= 0) { "Certificate has expired" }

            Log.i { "Certificate validity check passed" }
        } finally {
            X509_free(cert)
        }
    }

    actual fun getProfessionOids(certDer: ByteArray): List<String> = memScoped {
        val pCert = alloc<CPointerVar<UByteVar>>()
        pCert.value = certDer.refTo(0).getPointer(this).reinterpret()
        val cert = d2i_X509(null, pCert.ptr, certDer.size.convert())
            ?: error(certificateParsingErrorMessage)
        try {
            val admissionObj = OBJ_txt2obj(oidAdmission, 1)
                ?: run { Log.w { "getProfessionOids: failed to resolve OID $oidAdmission" }; return emptyList() }
            val idx = X509_get_ext_by_OBJ(cert, admissionObj, -1)
            if (idx < 0) {
                Log.w { "getProfessionOids: admission extension ($oidAdmission) not found in certificate" }
                return emptyList()
            }
            val ext = X509_get_ext(cert, idx)
                ?: run { Log.w { "getProfessionOids: X509_get_ext returned null at idx: $idx" }; return emptyList() }
            val octStr = X509_EXTENSION_get_data(ext)
                ?: run { Log.w { "getProfessionOids: X509_EXTENSION_get_data returned null" }; return emptyList() }
            val len = ASN1_STRING_length(octStr)
            if (len <= 0) {
                Log.w { "getProfessionOids: admission extension data is empty (len: $len)" }
                return emptyList()
            }
            val data = ASN1_STRING_get0_data(octStr)
                ?: run { Log.w { "getProfessionOids: ASN1_STRING_get0_data returned null" }; return emptyList() }
            val derBytes = data.reinterpret<ByteVar>().readBytes(len)
            parseAdmissionOids(derBytes).also { oids ->
                if (oids.isEmpty()) {
                    Log.w { "getProfessionOids: DER parsed successfully but no OIDs found (len: $len)" }
                } else {
                    Log.d { "getProfessionOids: found OIDs: $oids" }
                }
            }
        } finally {
            X509_free(cert)
        }
    }

    actual fun getPublicKey(certDer: ByteArray): ByteArray = memScoped {
        val pCert = alloc<CPointerVar<UByteVar>>()
        pCert.value = certDer.refTo(0).getPointer(this).reinterpret()
        val cert = d2i_X509(null, pCert.ptr, certDer.size.convert())
            ?: error(certificateParsingErrorMessage)

        try {
            val pubKey = X509_get_pubkey(cert)
                ?: error("Failed to get public key")

            try {
                val len = i2d_PUBKEY(pubKey, null)
                require(len > 0) { "Failed to get public key size" }

                val buffer = allocArray<UByteVar>(len)
                val pBuffer = alloc<CPointerVar<UByteVar>>()
                pBuffer.value = buffer

                i2d_PUBKEY(pubKey, pBuffer.ptr)

                buffer.readBytes(len)
            } finally {
                EVP_PKEY_free(pubKey)
            }
        } finally {
            X509_free(cert)
        }
    }

    actual fun validateCertChain(
        chainDer: List<ByteArray>,
        trustAnchorsDer: List<ByteArray>,
    ) = memScoped {
        require(chainDer.isNotEmpty()) { "Certificate chain is empty" }

        val store = X509_STORE_new()
            ?: error("Failed to create X509 store")

        try {
            for (anchorDer in trustAnchorsDer) {
                val pAnchor = alloc<CPointerVar<UByteVar>>()
                pAnchor.value = anchorDer.refTo(0).getPointer(this).reinterpret()
                val anchor = d2i_X509(null, pAnchor.ptr, anchorDer.size.convert())
                    ?: error("Failed to parse trust anchor")

                X509_STORE_add_cert(store, anchor)
                X509_free(anchor)
            }

            val pLeaf = alloc<CPointerVar<UByteVar>>()
            pLeaf.value = chainDer[0].refTo(0).getPointer(this).reinterpret()
            val leafCert = d2i_X509(null, pLeaf.ptr, chainDer[0].size.convert())
                ?: error("Failed to parse leaf certificate")

            try {
                val chain = OPENSSL_sk_new_null()
                    ?: error("Failed to create certificate chain")

                try {
                    for (i in 1 until chainDer.size) {
                        val pCert = alloc<CPointerVar<UByteVar>>()
                        pCert.value = chainDer[i].refTo(0).getPointer(this).reinterpret()
                        val cert = d2i_X509(null, pCert.ptr, chainDer[i].size.convert())
                            ?: error("Failed to parse intermediate certificate")

                        OPENSSL_sk_push(chain, cert)
                    }

                    val ctx = X509_STORE_CTX_new()
                        ?: error("Failed to create verification context")

                    try {
                        X509_STORE_CTX_init(ctx, store, leafCert, chain.reinterpret())

                        val result = X509_verify_cert(ctx)
                        if (result != 1) {
                            val error = X509_STORE_CTX_get_error(ctx)
                            val errorStr = X509_verify_cert_error_string(error.convert())?.toKString() ?: "Unknown error"
                            error("Certificate chain validation failed: $errorStr (code: $error)")
                        }

                        Log.i { "Certificate chain validation passed" }
                    } finally {
                        X509_STORE_CTX_free(ctx)
                    }
                } finally {
                    val num = OPENSSL_sk_num(chain)
                    for (i in 0 until num) {
                        val cert = OPENSSL_sk_value(chain, i)?.reinterpret<X509>()
                        X509_free(cert)
                    }
                    OPENSSL_sk_free(chain)
                }
            } finally {
                X509_free(leafCert)
            }
        } finally {
            X509_STORE_free(store)
        }
    }

    private fun createAsn1Time(timeT: time_t): CPointer<ASN1_TIME>? {
        return ASN1_TIME_set(null, timeT)
    }

    actual fun getSanDnsNames(certDer: ByteArray): List<String> = memScoped {
        val pCert = alloc<CPointerVar<UByteVar>>()
        pCert.value = certDer.refTo(0).getPointer(this).reinterpret()
        val cert = d2i_X509(null, pCert.ptr, certDer.size.convert())
            ?: error(certificateParsingErrorMessage)

        try {
            val sanExt = X509_get_ext_d2i(cert, NID_subject_alt_name, null, null)
                ?: return emptyList()

            val stack = sanExt.reinterpret<OPENSSL_STACK>()
            val num = OPENSSL_sk_num(stack)

            buildList {
                for (i in 0 until num) {
                    val generalName = OPENSSL_sk_value(stack, i)
                        ?.reinterpret<GENERAL_NAME>() ?: continue

                    if (generalName.pointed.type == GEN_DNS) {
                        val asn1Str = generalName.pointed.d.ia5 ?: continue
                        val len = asn1Str.pointed.length
                        val data = asn1Str.pointed.data ?: continue
                        add(data.readBytes(len).decodeToString())
                    }
                }
            }
        } finally {
            X509_free(cert)
        }
    }
}

private class DerReader(private val data: ByteArray, private var pos: Int = 0) {

    val hasMore get() = pos < data.size

    fun peekTag(): Int = data[pos].toInt() and 0xFF

    private fun readTag(): Int = data[pos++].toInt() and 0xFF

    private fun readLength(): Int {
        val first = data[pos++].toInt() and 0xFF
        return if (first < 0x80) {
            first
        } else {
            val numBytes = first and 0x7F
            var length = 0
            repeat(numBytes) { length = (length shl 8) or (data[pos++].toInt() and 0xFF) }
            length
        }
    }

    fun readSeqContent(): ByteArray {
        check(readTag() == 0x30) { "Expected SEQUENCE (0x30) at pos ${pos - 1}" }
        val len = readLength()
        return data.copyOfRange(pos, pos + len).also { pos += len }
    }

    fun skipOne() {
        readTag()
        pos += readLength()
    }

    fun readOid(): String {
        check(readTag() == 0x06) { "Expected OID (0x06) at pos ${pos - 1}" }
        val len = readLength()
        return decodeOidBytes(data.copyOfRange(pos, pos + len)).also { pos += len }
    }

    /** Skip context-tagged elements and anything else until the first plain SEQUENCE. */
    fun skipToFirstSeq(): ByteArray? {
        while (hasMore) {
            if (peekTag() == 0x30) return readSeqContent()
            skipOne()
        }
        return null
    }
}

private fun decodeOidBytes(bytes: ByteArray): String = buildString {
    val first = bytes[0].toInt() and 0xFF
    append(first / 40).append('.').append(first % 40)
    var value = 0L
    for (i in 1 until bytes.size) {
        val b = bytes[i].toInt() and 0xFF
        value = (value shl 7) or (b and 0x7F).toLong()
        if (b and 0x80 == 0) {
            append('.').append(value)
            value = 0
        }
    }
}
private fun extractOidsFromProfInfo(der: ByteArray): List<String> {
    val derOidTag = 0x06
    val derSequenceTag = 0x30
    val reader = DerReader(der)

    val secondSeq = generateSequence {
        if (reader.hasMore && reader.peekTag() == derSequenceTag) {
            reader.readSeqContent()
        } else { reader.skipOne(); null }
    }
        .drop(1)
        .firstOrNull() ?: return emptyList()

    val seqReader = DerReader(secondSeq)
    return buildList {
        while (seqReader.hasMore) {
            if (seqReader.peekTag() == derOidTag) {
                add(seqReader.readOid())
            } else {
                seqReader.skipOne()
            }
        }
    }
}

internal fun parseAdmissionOids(der: ByteArray): List<String> = try {
    val admSyntaxReader = DerReader(DerReader(der).readSeqContent())
    val contentsBytes = admSyntaxReader.skipToFirstSeq() ?: return emptyList()
    val contentsReader = DerReader(contentsBytes)

    buildList {
        while (contentsReader.hasMore) {
            if (contentsReader.peekTag() != 0x30) { contentsReader.skipOne(); continue }

            val admissionsReader = DerReader(contentsReader.readSeqContent())
            val profInfosBytes = admissionsReader.skipToFirstSeq() ?: continue
            val profInfosReader = DerReader(profInfosBytes)

            while (profInfosReader.hasMore) {
                if (profInfosReader.peekTag() != 0x30) { profInfosReader.skipOne(); continue }
                addAll(extractOidsFromProfInfo(profInfosReader.readSeqContent()))
            }
        }
    }
} catch (_: Exception) {
    emptyList()
}
