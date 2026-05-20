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

@file:OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)

package de.gematik.zeta.sdk.crypto

import de.gematik.zeta.sdk.crypto.openssl.ASN1_STRING_get0_data
import de.gematik.zeta.sdk.crypto.openssl.ASN1_STRING_length
import de.gematik.zeta.sdk.crypto.openssl.ASN1_TYPE
import de.gematik.zeta.sdk.crypto.openssl.ASN1_TYPE_free
import de.gematik.zeta.sdk.crypto.openssl.BIO_free
import de.gematik.zeta.sdk.crypto.openssl.BIO_new_mem_buf
import de.gematik.zeta.sdk.crypto.openssl.ERR_error_string
import de.gematik.zeta.sdk.crypto.openssl.ERR_get_error
import de.gematik.zeta.sdk.crypto.openssl.EVP_PKEY
import de.gematik.zeta.sdk.crypto.openssl.EVP_PKEY2PKCS8
import de.gematik.zeta.sdk.crypto.openssl.EVP_PKEY_free
import de.gematik.zeta.sdk.crypto.openssl.OBJ_txt2obj
import de.gematik.zeta.sdk.crypto.openssl.OPENSSL_sk_free
import de.gematik.zeta.sdk.crypto.openssl.OPENSSL_sk_num
import de.gematik.zeta.sdk.crypto.openssl.OPENSSL_sk_value
import de.gematik.zeta.sdk.crypto.openssl.PKCS12_free
import de.gematik.zeta.sdk.crypto.openssl.PKCS12_parse
import de.gematik.zeta.sdk.crypto.openssl.PKCS8_PRIV_KEY_INFO_free
import de.gematik.zeta.sdk.crypto.openssl.V_ASN1_OBJECT
import de.gematik.zeta.sdk.crypto.openssl.V_ASN1_PRINTABLESTRING
import de.gematik.zeta.sdk.crypto.openssl.V_ASN1_SEQUENCE
import de.gematik.zeta.sdk.crypto.openssl.X509
import de.gematik.zeta.sdk.crypto.openssl.X509_EXTENSION_get_data
import de.gematik.zeta.sdk.crypto.openssl.X509_free
import de.gematik.zeta.sdk.crypto.openssl.X509_get_ext
import de.gematik.zeta.sdk.crypto.openssl.X509_get_ext_by_OBJ
import de.gematik.zeta.sdk.crypto.openssl.d2i_ASN1_SEQUENCE_ANY
import de.gematik.zeta.sdk.crypto.openssl.d2i_ASN1_TYPE
import de.gematik.zeta.sdk.crypto.openssl.d2i_PKCS12_bio
import de.gematik.zeta.sdk.crypto.openssl.d2i_X509
import de.gematik.zeta.sdk.crypto.openssl.i2d_PKCS8_PRIV_KEY_INFO
import de.gematik.zeta.sdk.crypto.openssl.i2d_X509
import de.gematik.zeta.sdk.crypto.openssl.ossl_check_const_ASN1_TYPE_sk_type
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.refTo
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.io.IOException
import okio.FileSystem
import okio.Path.Companion.toPath
import okio.buffer
import okio.use

actual class X509PemReader {

    actual fun loadCertificateFromBytes(
        data: ByteArray,
        alias: String,
        password: String,
    ): ByteArray = memScoped {
        val bio = BIO_new_mem_buf(data.refTo(0), data.size)
        if (bio == null) throw IOException("BIO_new_mem_buf: bio == $bio")

        val p12 = d2i_PKCS12_bio(bio, null)
        BIO_free(bio)
        if (p12 == null) throw IOException("d2i_PKCS12_bio: p12 == $p12, ${getOpenSSLErrors()}")

        val certPtr = alloc<CPointerVar<X509>>()
        val keyPtr = alloc<CPointerVar<EVP_PKEY>>()
        val success = PKCS12_parse(p12, password, keyPtr.ptr, certPtr.ptr, null)
        PKCS12_free(p12)
        EVP_PKEY_free(keyPtr.value)
        if (success != 1) throw IOException("PKCS12_parse: success == $success, ${getOpenSSLErrors()}")

        val outPtrVar = alloc<CPointerVar<UByteVar>>()
        val len = i2d_X509(certPtr.value, outPtrVar.ptr)
        X509_free(certPtr.value)
        if (len <= 0) throw IOException("i2d_X509: len == $len ${getOpenSSLErrors()}")

        outPtrVar.value!!.readBytes(len)
    }

    actual fun loadCertificate(p12File: String, alias: String, password: String): ByteArray {
        val p12Bytes = FileSystem.SYSTEM.source(p12File.toPath()).use { it.buffer().readByteArray() }
        return loadCertificateFromBytes(p12Bytes, alias, password)
    }

    actual fun loadPrivateKeyFromBytes(data: ByteArray, alias: String, password: String): ByteArray = memScoped {
        val bio = BIO_new_mem_buf(data.refTo(0), data.size)
        if (bio == null) throw IOException("BIO_new_mem_buf: bio == $bio")

        val p12 = d2i_PKCS12_bio(bio, null)
        BIO_free(bio)
        if (p12 == null) throw IOException("d2i_PKCS12_bio: p12 == $p12, ${getOpenSSLErrors()}")

        val certPtr = alloc<CPointerVar<X509>>()
        val keyPtr = alloc<CPointerVar<EVP_PKEY>>()
        val success = PKCS12_parse(p12, password, keyPtr.ptr, certPtr.ptr, null)
        PKCS12_free(p12)
        X509_free(certPtr.value)
        if (success != 1) throw IOException("PKCS12_parse: success == $success, ${getOpenSSLErrors()}")

        val p8 = EVP_PKEY2PKCS8(keyPtr.value)
        EVP_PKEY_free(keyPtr.value)
        if (p8 == null) throw IOException("EVP_PKEY2PKCS8: p8 == $p8 ${getOpenSSLErrors()}")

        val outPtrVar = alloc<CPointerVar<UByteVar>>()
        outPtrVar.value = null
        val len = i2d_PKCS8_PRIV_KEY_INFO(p8, outPtrVar.ptr)
        PKCS8_PRIV_KEY_INFO_free(p8)
        if (len <= 0) throw IOException("i2d_PKCS8_PRIV_KEY_INFO: p8 == $p8 ${getOpenSSLErrors()}")

        outPtrVar.value!!.readBytes(len)
    }

    actual fun loadPrivateKey(p12File: String, alias: String, password: String): ByteArray {
        val p12Bytes = FileSystem.SYSTEM.source(p12File.toPath()).use { it.buffer().readByteArray() }
        return loadPrivateKeyFromBytes(p12Bytes, alias, password)
    }

    actual fun getRegistrationNumber(certificateBytes: ByteArray): String? = memScoped {
        val ptrVar = alloc<CPointerVar<UByteVar>>()
        certificateBytes.asUByteArray().usePinned { ptrVar.value = it.addressOf(0) }
        val cert = d2i_X509(null, ptrVar.ptr, certificateBytes.size.convert())
            ?: throw IOException("d2i_X509: cert is null, ${getOpenSSLErrors()}")

        val extOid = OBJ_txt2obj("1.3.36.8.3.3", 1)
            ?: throw IOException("OBJ_txt2obj: extOid is null")

        val extIndex = X509_get_ext_by_OBJ(cert, extOid, -1)
        if (extIndex < 0) return null // Extension not found

        val ext = X509_get_ext(cert, extIndex)
            ?: throw IOException("X509_get_ext: ext is null")

        val octet = X509_EXTENSION_get_data(ext)
            ?: throw IOException("X509_EXTENSION_get_data: octet is null")

        val der = ASN1_STRING_get0_data(octet)
            ?: throw IOException("ASN1_STRING_get0_data: der is null")

        val len = ASN1_STRING_length(octet)
        if (len <= 0) return null

        val pDer = alloc<CPointerVar<UByteVar>> { value = der }
        val asn1 = d2i_ASN1_TYPE(null, pDer.ptr, len.convert())
            ?: throw IOException("d2i_ASN1_TYPE: asn1 is null")

        val seqString = asn1.pointed.value.asn1_string
        val derPtr = ASN1_STRING_get0_data(seqString)
        val plen = ASN1_STRING_length(seqString)

        val ppDer = alloc<CPointerVar<UByteVar>> { value = derPtr }
        val childSeq = d2i_ASN1_SEQUENCE_ANY(null, ppDer.ptr, plen.convert())

        val result = findRegistrationNumberInSequence(childSeq)

        ASN1_TYPE_free(asn1)
        childSeq?.let { freeSequence(it) }

        result
    }

    private fun findRegistrationNumberInSequence(seq: CPointer<cnames.structs.stack_st_ASN1_TYPE>?): String? {
        if (seq == null) return null

        for (i in 0 until asn1TypeNum(seq)) {
            val node = asn1TypeValue(seq, i) ?: continue

            if (node.pointed.type == V_ASN1_PRINTABLESTRING) {
                // Found a PrintableString. Now, validate its context.
                if (isProfessionInfoContext(seq)) {
                    val ps = node.pointed.value.printablestring ?: continue
                    val data = ASN1_STRING_get0_data(ps) ?: continue
                    return data.readBytes(ASN1_STRING_length(ps)).toKString()
                }
            } else if (node.pointed.type == V_ASN1_SEQUENCE) {
                // It's a sequence, so recurse into it.
                val seqString = node.pointed.value.asn1_string ?: continue
                val derPtr = ASN1_STRING_get0_data(seqString)?.reinterpret<UByteVar>() ?: continue
                val result = memScoped {
                    val pDer = alloc<CPointerVar<UByteVar>> { value = derPtr }
                    val childSeq = d2i_ASN1_SEQUENCE_ANY(null, pDer.ptr, ASN1_STRING_length(seqString).convert())
                    val found = findRegistrationNumberInSequence(childSeq)
                    childSeq?.let { freeSequence(it) }
                    found
                }
                if (result != null) return result
            }
        }
        return null
    }

    /**
     * Checks if a given sequence is likely a `ProfessionInfo` block.
     * It does this by checking if one of its direct children is a sequence that contains an OBJECT IDENTIFIER (the role OID).
     */
    private fun isProfessionInfoContext(professionInfoSeq: CPointer<cnames.structs.stack_st_ASN1_TYPE>?): Boolean {
        if (professionInfoSeq == null) return false

        for (i in 0 until asn1TypeNum(professionInfoSeq)) {
            val node = asn1TypeValue(professionInfoSeq, i) ?: continue
            if (node.pointed.type == V_ASN1_SEQUENCE) {
                // Found a child sequence. Check if it contains an OID.
                val seqString = node.pointed.value.asn1_string ?: continue
                val derPtr = ASN1_STRING_get0_data(seqString)?.reinterpret<UByteVar>() ?: continue
                val hasOid = memScoped {
                    val pDer = alloc<CPointerVar<UByteVar>> { value = derPtr }
                    val childSeq = d2i_ASN1_SEQUENCE_ANY(null, pDer.ptr, ASN1_STRING_length(seqString).convert())
                    val found = containsObjectType(childSeq)
                    childSeq?.let { freeSequence(it) }
                    found
                }
                if (hasOid) return true
            }
        }
        return false
    }

    /**
     * Helper to check if a sequence contains a node of type V_ASN1_OBJECT.
     */
    private fun containsObjectType(seq: CPointer<cnames.structs.stack_st_ASN1_TYPE>?): Boolean {
        if (seq == null) return false
        for (i in 0 until asn1TypeNum(seq)) {
            val node = asn1TypeValue(seq, i) ?: continue
            if (node.pointed.type == V_ASN1_OBJECT) {
                return true
            }
        }
        return false
    }

    private fun freeSequence(seq: CPointer<cnames.structs.stack_st_ASN1_TYPE>) {
        for (k in 0 until asn1TypeNum(seq)) {
            asn1TypeValue(seq, k)?.let { ASN1_TYPE_free(it) }
        }
        asn1TypeFree(seq)
    }
}

fun getOpenSSLErrors(): String {
    val sb = StringBuilder()
    while (true) {
        val errCode = ERR_get_error()
        if (errCode.convert<ULong>() == 0UL) break
        val errStr = ERR_error_string(errCode, null)?.toKString()
        if (errStr != null) sb.append(errStr).append("\n")
    }
    return sb.toString()
}

@Suppress("UNCHECKED_CAST")
private fun asn1TypeNum(
    sk: CValuesRef<cnames.structs.stack_st_ASN1_TYPE>?,
): Int {
    return OPENSSL_sk_num(ossl_check_const_ASN1_TYPE_sk_type(sk))
}

@Suppress("UNCHECKED_CAST")
private fun asn1TypeValue(
    sk: CValuesRef<cnames.structs.stack_st_ASN1_TYPE>?,
    idx: Int,
): CPointer<ASN1_TYPE>? {
    return OPENSSL_sk_value(ossl_check_const_ASN1_TYPE_sk_type(sk), idx) as CPointer<ASN1_TYPE>?
}

@Suppress("UNCHECKED_CAST")
private fun asn1TypeFree(
    sk: CValuesRef<cnames.structs.stack_st_ASN1_TYPE>?,
) {
    return OPENSSL_sk_free(ossl_check_const_ASN1_TYPE_sk_type(sk))
}
