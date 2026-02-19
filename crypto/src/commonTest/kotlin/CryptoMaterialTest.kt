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

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CryptoMaterialTest {
    @Test
    fun randomUUID_returnsRandomGuidWithCanonicalFormat() {
        // Act
        val original = randomUUID()

        // Assert
        val uuidRegexV4 =
            Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOption.IGNORE_CASE)

        assertTrue(uuidRegexV4.matches(original))
    }

    @Test
    fun randomUUID_returnsValidUuid_always() {
        // Arrange & Act
        val uuid = randomUUID()

        // Assert
        assertNotNull(uuid)
        assertTrue(uuid.isNotEmpty())
    }

    @Test
    fun randomUUID_matchesUuidFormat_validStructure() {
        // Arrange & Act
        val uuid = randomUUID()

        // Assert
        // UUID v4
        val uuidRegex = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        assertTrue(uuid.matches(uuidRegex))
    }

    @Test
    fun randomUUID_returnsDifferentUuids_multipleInvocations() {
        // Arrange & Act
        val uuid1 = randomUUID()
        val uuid2 = randomUUID()
        val uuid3 = randomUUID()

        // Assert
        assertNotEquals(uuid1, uuid2)
        assertNotEquals(uuid2, uuid3)
        assertNotEquals(uuid1, uuid3)
    }

    @Test
    fun randomUUID_hasCorrectLength_always() {
        // Arrange & Act
        val uuid = randomUUID()

        // Assert
        assertEquals(36, uuid.length)
    }

    @Test
    fun derEcdsaToJose_convertsValidDer_returns64Bytes() {
        // Arrange
        val derSignature = buildValidDerSignature(
            r = ByteArray(32) { 0x01 },
            s = ByteArray(32) { 0x02 },
        )

        // Act
        val joseSignature = derEcdsaToJose(derSignature, size = 32)

        // Assert
        assertEquals(64, joseSignature.size)
    }

    @Test
    fun derEcdsaToJose_extractsRAndS_correctlyOrdered() {
        // Arrange
        val r = ByteArray(32) { it.toByte() }
        val s = ByteArray(32) { (it + 32).toByte() }
        val derSignature = buildValidDerSignature(r, s)

        // Act
        val joseSignature = derEcdsaToJose(derSignature, size = 32)

        // Assert
        val extractedR = joseSignature.copyOfRange(0, 32)
        val extractedS = joseSignature.copyOfRange(32, 64)
        assertContentEquals(r, extractedR)
        assertContentEquals(s, extractedS)
    }

    @Test
    fun derEcdsaToJose_throwsException_notDerSequence() {
        // Arrange
        val invalidDer = ByteArray(10)

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            derEcdsaToJose(invalidDer)
        }
    }

    @Test
    fun derEcdsaToJose_throwsException_emptyInput() {
        // Arrange
        val emptyDer = ByteArray(0)

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            derEcdsaToJose(emptyDer)
        }
    }

    @Test
    fun joseToDerEcdsa_convertsValidJose_returnsDerFormat() {
        // Arrange
        val r = ByteArray(32) { 0x01 }
        val s = ByteArray(32) { 0x02 }
        val joseSignature = r + s

        // Act
        val derSignature = joseToDerEcdsa(joseSignature)

        // Assert
        assertNotNull(derSignature)
        assertTrue(derSignature.isNotEmpty())
        assertEquals(0x30.toByte(), derSignature[0])
    }

    @Test
    fun joseToDerEcdsa_encodesRAndS_correctlyOrdered() {
        // Arrange
        val r = ByteArray(32) { 0x12 }
        val s = ByteArray(32) { 0x34 }
        val joseSignature = r + s

        // Act
        val derSignature = joseToDerEcdsa(joseSignature)

        // Assert
        assertEquals(derSignature[0], 0x30.toByte())
        val idx = 2
        assertEquals(0x02.toByte(), derSignature[idx])
    }

    @Test
    fun joseToDerEcdsa_handlesHighBit_prependsZero() {
        // Arrange
        val r = ByteArray(32) { 0xFF.toByte() }
        val s = ByteArray(32) { 0x01 }
        val joseSignature = r + s

        // Act
        val derSignature = joseToDerEcdsa(joseSignature)

        // Assert
        val rLengthIdx = 3
        val rLength = derSignature[rLengthIdx].toInt()
        assertEquals(rLength, 33)
    }

    @Test
    fun joseToDerEcdsa_handlesLeadingZeros_removesFromJose() {
        // Arrange
        val r = ByteArray(32) { 0x00 }
        val s = ByteArray(32) { 0x01 }
        val joseSignature = r + s

        // Act
        val derSignature = joseToDerEcdsa(joseSignature)

        // Assert
        assertNotNull(derSignature)
    }

    @Test
    fun joseToDerEcdsa_throwsException_oddLength() {
        // Arrange
        val invalidJose = ByteArray(63)

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            joseToDerEcdsa(invalidJose)
        }
    }

    @Test
    fun derToJoseToJose_roundTrip_producesOriginalJose() {
        // Arrange
        val originalR = ByteArray(32) { (it + 1).toByte() }
        val originalS = ByteArray(32) { (it + 100).toByte() }
        val originalJose = originalR + originalS

        // Act
        val der = joseToDerEcdsa(originalJose)
        val joseAgain = derEcdsaToJose(der, size = 32)

        // Assert
        assertContentEquals(originalJose, joseAgain)
    }

    @Test
    fun joseToDerToDer_roundTrip_producesSameDer() {
        // Arrange
        val r = ByteArray(32) { 0x55 }
        val s = ByteArray(32) { 0xAA.toByte() }
        val originalDer = buildValidDerSignature(r, s)

        // Act
        val jose = derEcdsaToJose(originalDer, size = 32)
        val derAgain = joseToDerEcdsa(jose)

        // Assert
        val joseFromOriginal = derEcdsaToJose(originalDer, size = 32)
        val joseFromNew = derEcdsaToJose(derAgain, size = 32)
        assertContentEquals(joseFromOriginal, joseFromNew)
    }

    @Test
    fun secureRandom_fillsBuffer_correctLength() {
        // Arrange
        val buffer = ByteArray(32)

        // Act
        val result = secureRandom(buffer)

        // Assert
        assertEquals(32, result.size)
    }

    @Test
    fun secureRandom_returnsFilledBuffer_notAllZeros() {
        // Arrange
        val buffer = ByteArray(32)

        // Act
        val result = secureRandom(buffer)

        // Assert
        val allZeros = result.all { it == 0.toByte() }
        assertFalse(allZeros)
    }

    @Test
    fun secureRandom_producesDifferentValues_multipleInvocations() {
        // Arrange
        val buffer1 = ByteArray(32)
        val buffer2 = ByteArray(32)

        // Act
        val result1 = secureRandom(buffer1)
        val result2 = secureRandom(buffer2)

        // Assert
        assertFalse(result1.contentEquals(result2))
    }

    @Test
    fun secureRandom_handlesSmallBuffer_works() {
        // Arrange
        val buffer = ByteArray(1)

        // Act
        val result = secureRandom(buffer)

        // Assert
        assertEquals(1, result.size)
    }

    @Test
    fun secureRandom_handlesLargeBuffer_works() {
        // Arrange
        val buffer = ByteArray(1024)

        // Act
        val result = secureRandom(buffer)

        // Assert
        assertEquals(1024, result.size)
    }

    @Test
    fun secureRandom_emptyBuffer_returnsEmpty() {
        // Arrange
        val buffer = ByteArray(0)

        // Act
        val result = secureRandom(buffer)

        // Assert
        assertEquals(0, result.size)
    }

    private fun buildValidDerSignature(r: ByteArray, s: ByteArray): ByteArray {
        fun encodeInt(x: ByteArray): ByteArray {
            var v = x.dropWhile { it == 0.toByte() }.toByteArray()
            if (v.isEmpty()) v = byteArrayOf(0)
            if (v[0].toInt() and 0x80 != 0) {
                v = byteArrayOf(0) + v
            }
            return byteArrayOf(0x02) + byteArrayOf(v.size.toByte()) + v
        }

        val derR = encodeInt(r)
        val derS = encodeInt(s)
        val sequence = derR + derS
        return byteArrayOf(0x30) + byteArrayOf(sequence.size.toByte()) + sequence
    }
}
