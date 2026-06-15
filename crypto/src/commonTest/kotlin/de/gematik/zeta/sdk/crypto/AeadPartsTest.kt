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

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AeadPartsTest {

    @Test
    fun `pack returns IV followed by cipherText followed by tag`() {
        // Arrange
        val iv = byteArrayOf(1, 2, 3)
        val cipherText = byteArrayOf(4, 5, 6, 7)
        val tag = byteArrayOf(8, 9)
        val aeadParts = AeadParts(iv, cipherText, tag)

        // Act
        val packed = aeadParts.pack()

        // Assert
        assertContentEquals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9), packed)
    }

    @Test
    fun `pack length equals sum of all parts`() {
        // Arrange
        val iv = ByteArray(12) { it.toByte() }
        val cipherText = ByteArray(32) { it.toByte() }
        val tag = ByteArray(16) { it.toByte() }
        val aeadParts = AeadParts(iv, cipherText, tag)

        // Act
        val packed = aeadParts.pack()

        // Assert
        assertEquals(iv.size + cipherText.size + tag.size, packed.size)
    }

    @Test
    fun `init throws when iv is empty`() {
        // Arrange
        val emptyIv = byteArrayOf()
        val cipherText = byteArrayOf(1, 2, 3)
        val tag = byteArrayOf(4, 5)

        // Act & Assert
        val ex = assertFailsWith<IllegalArgumentException> {
            AeadParts(emptyIv, cipherText, tag)
        }
        assertEquals("IV must not be empty", ex.message)
    }

    @Test
    fun `init throws when tag is empty`() {
        // Arrange
        val iv = byteArrayOf(1, 2)
        val cipherText = byteArrayOf(3, 4)
        val emptyTag = byteArrayOf()

        // Act & Assert
        val ex = assertFailsWith<IllegalArgumentException> {
            AeadParts(iv, cipherText, emptyTag)
        }
        assertEquals("TAG must not be empty", ex.message)
    }

    @Test
    fun `init throws when cipherText is empty`() {
        // Arrange
        val iv = byteArrayOf(1, 2)
        val emptyCipherText = byteArrayOf()
        val tag = byteArrayOf(3, 4)

        // Act & Assert
        val ex = assertFailsWith<IllegalArgumentException> {
            AeadParts(iv, emptyCipherText, tag)
        }
        assertEquals("Ciphertext must not be empty", ex.message)
    }
}

class UnpackAeadTest {

    @Test
    fun `unpackAead returns correct iv cipherText and tag with default lengths`() {
        // Arrange
        val iv = ByteArray(12) { (it + 1).toByte() }
        val cipherText = ByteArray(20) { (it + 100).toByte() }
        val tag = ByteArray(16) { (it + 50).toByte() }
        val blob = iv + cipherText + tag

        // Act
        val result = blob.unpackAead()

        // Assert
        assertContentEquals(iv, result.iv)
        assertContentEquals(cipherText, result.cipherText)
        assertContentEquals(tag, result.tag)
    }

    @Test
    fun `unpackAead returns correct parts with custom nonce and tag lengths`() {
        // Arrange
        val nonceLen = 8
        val tagLen = 4
        val iv = ByteArray(nonceLen) { it.toByte() }
        val cipherText = ByteArray(10) { (it + 20).toByte() }
        val tag = ByteArray(tagLen) { (it + 80).toByte() }
        val blob = iv + cipherText + tag

        // Act
        val result = blob.unpackAead(nonceLen = nonceLen, tagLen = tagLen)

        // Assert
        assertContentEquals(iv, result.iv)
        assertContentEquals(cipherText, result.cipherText)
        assertContentEquals(tag, result.tag)
    }

    @Test
    fun `unpackAead throws when blob is too short`() {
        // Arrange
        val tooShort = ByteArray(12 + 16) // exactly nonceLen + tagLen, no room for cipherText

        // Act & Assert
        val ex = assertFailsWith<IllegalArgumentException> {
            tooShort.unpackAead()
        }
        assertEquals("AEAD blob too short", ex.message)
    }

    @Test
    fun `unpackAead throws when blob is empty`() {
        // Arrange
        val empty = byteArrayOf()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            empty.unpackAead()
        }
    }

    @Test
    fun `pack and unpackAead are inverse operations`() {
        // Arrange
        val iv = ByteArray(12) { it.toByte() }
        val cipherText = ByteArray(25) { (it + 10).toByte() }
        val tag = ByteArray(16) { (it + 5).toByte() }
        val original = AeadParts(iv, cipherText, tag)

        // Act
        val repacked = original.pack().unpackAead()

        // Assert
        assertContentEquals(original.iv, repacked.iv)
        assertContentEquals(original.cipherText, repacked.cipherText)
        assertContentEquals(original.tag, repacked.tag)
    }
}
