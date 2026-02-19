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

package de.gematik.zeta.sdk.asl.vau

import de.gematik.zeta.sdk.crypto.Kem
import de.gematik.zeta.sdk.crypto.KemEncapResult
import de.gematik.zeta.sdk.crypto.KeyPair
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

class Message1Test {
    @Test
    fun buildMessage1_throwsIllegalArgumentException_sec1Null() {
        // Arrange
        val mlKem = FakeKem(publicKey = ByteArray(32))
        val ecdhKem = FakeKem(publicKey = ByteArray(32), sec1 = null)

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            buildMessage1(mlKem, ecdhKem)
        }
    }

    @Test
    fun buildMessage1_returnsBundle_validKeys() {
        // Arrange
        val mlKemPub = ByteArray(32) { 1 }
        val ecdhSec1 = ByteArray(65) { 0x04.toByte() }
        ecdhSec1[0] = 0x04.toByte()
        val mlKem = FakeKem(publicKey = mlKemPub)
        val ecdhKem = FakeKem(publicKey = ByteArray(32), sec1 = ecdhSec1)

        // Act
        val result = buildMessage1(mlKem, ecdhKem)

        // Assert
        assertNotNull(result.encoded)
        assertNotNull(result.keys)
        assertEquals(mlKemPub, result.keys.ml768Key.skpi)
    }

    @Test
    fun getCid_returnsCid_validHeaders() {
        // Arrange
        val headers = HeadersBuilder().apply {
            append(HttpHeaders.ContentType, "application/cbor")
            append("zeta-asl-cid", "/ASL/test-123")
        }.build()

        // Act
        val result = getCid(headers)

        // Assert
        assertEquals("/ASL/test-123", result)
    }

    @Test
    fun getCid_returnsCid_contentTypeWithCharset() {
        // Arrange
        val headers = HeadersBuilder().apply {
            append(HttpHeaders.ContentType, "application/cbor; charset=utf-8")
            append("zeta-asl-cid", "/ASL/test")
        }.build()

        // Act
        val result = getCid(headers)

        // Assert
        assertEquals("/ASL/test", result)
    }

    @Test
    fun getCid_returnsCid_cidWithHyphens() {
        // Arrange
        val headers = HeadersBuilder().apply {
            append(HttpHeaders.ContentType, "application/cbor")
            append("zeta-asl-cid", "/ASL/test-abc-123-xyz")
        }.build()

        // Act
        val result = getCid(headers)

        // Assert
        assertEquals("/ASL/test-abc-123-xyz", result)
    }

    @Test
    fun getCid_returnsCid_cidWithSlashes() {
        // Arrange
        val headers = HeadersBuilder().apply {
            append(HttpHeaders.ContentType, "application/cbor")
            append("zeta-asl-cid", "/ASL/path/to/resource")
        }.build()

        // Act
        val result = getCid(headers)

        // Assert
        assertEquals("/ASL/path/to/resource", result)
    }

    @Test
    fun getCid_throwsIllegalArgumentException_missingContentType() {
        // Arrange
        val headers = HeadersBuilder().apply {
            append("zeta-asl-cid", "/ASL/test")
        }.build()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            getCid(headers)
        }
    }

    @Test
    fun getCid_throwsIllegalArgumentException_wrongContentType() {
        // Arrange
        val headers = HeadersBuilder().apply {
            append(HttpHeaders.ContentType, "application/json")
            append("zeta-asl-cid", "/ASL/test")
        }.build()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            getCid(headers)
        }
    }

    @Test
    fun getCid_throwsIllegalStateException_missingCidHeader() {
        // Arrange
        val headers = HeadersBuilder().apply {
            append(HttpHeaders.ContentType, "application/cbor")
        }.build()

        // Act & Assert
        assertFailsWith<IllegalStateException> {
            getCid(headers)
        }
    }

    @Test
    fun getCid_throwsIllegalArgumentException_cidTooLong() {
        // Arrange
        val longCid = "/" + "a".repeat(200)
        val headers = HeadersBuilder().apply {
            append(HttpHeaders.ContentType, "application/cbor")
            append("zeta-asl-cid", longCid)
        }.build()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            getCid(headers)
        }
    }

    @Test
    fun getCid_throwsIllegalArgumentException_cidDoesNotStartWithSlash() {
        // Arrange
        val headers = HeadersBuilder().apply {
            append(HttpHeaders.ContentType, "application/cbor")
            append("zeta-asl-cid", "ASL/test")
        }.build()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            getCid(headers)
        }
    }

    @Test
    fun getCid_throwsIllegalArgumentException_cidContainsInvalidChars() {
        // Arrange
        val headers = HeadersBuilder().apply {
            append(HttpHeaders.ContentType, "application/cbor")
            append("zeta-asl-cid", "/ASL/test@invalid")
        }.build()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            getCid(headers)
        }
    }

    @Test
    fun getCid_throwsIllegalArgumentException_cidContainsSpace() {
        // Arrange
        val headers = HeadersBuilder().apply {
            append(HttpHeaders.ContentType, "application/cbor")
            append("zeta-asl-cid", "/ASL/test with space")
        }.build()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            getCid(headers)
        }
    }

    @Test
    fun sec1ToXY_returnsXY_validSec1() {
        // Arrange
        val sec1 = ByteArray(65)
        sec1[0] = 0x04.toByte()
        for (i in 1..32) sec1[i] = i.toByte()
        for (i in 33..64) sec1[i] = (i + 100).toByte()

        // Act
        val (x, y) = sec1ToXY(sec1)

        // Assert
        assertEquals(32, x.size)
        assertEquals(32, y.size)
        assertContentEquals(sec1.copyOfRange(1, 33), x)
        assertContentEquals(sec1.copyOfRange(33, 65), y)
    }

    @Test
    fun sec1ToXY_throwsIllegalArgumentException_wrongSize() {
        // Arrange
        val sec1 = ByteArray(64)
        sec1[0] = 0x04.toByte()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            sec1ToXY(sec1)
        }
    }

    @Test
    fun sec1ToXY_throwsIllegalArgumentException_wrongFirstByte() {
        // Arrange
        val sec1 = ByteArray(65)
        sec1[0] = 0x03.toByte()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            sec1ToXY(sec1)
        }
    }

    @Test
    fun sec1ToXY_throwsIllegalArgumentException_tooLarge() {
        // Arrange
        val sec1 = ByteArray(66)
        sec1[0] = 0x04.toByte()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            sec1ToXY(sec1)
        }
    }

    private class FakeKem(
        private val publicKey: ByteArray,
        private val sec1: ByteArray? = null,
    ) : Kem {
        override fun generateKeys(): KeyPair {
            return KeyPair(
                skpi = publicKey,
                sec1 = sec1,
                privateKey = byteArrayOf(),
            )
        }

        override fun decapsulate(privateKeyRaw: ByteArray, ciphertext: ByteArray): ByteArray {
            return ByteArray(32)
        }

        override fun encapsulate(peerPublicKey: ByteArray): KemEncapResult {
            return KemEncapResult(byteArrayOf(), byteArrayOf())
        }
    }
}
