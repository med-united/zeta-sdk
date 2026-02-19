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

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class Message3Test {
    @Test
    fun buildMessage3_createsMessage3_validInputs() {
        // Arrange
        val innerCipherText = byteArrayOf(1, 2, 3)
        val keyConfCipherText = byteArrayOf(4, 5, 6)

        // Act
        val result = buildMessage3(innerCipherText, keyConfCipherText)

        // Assert
        assertEquals("M3", result.type)
        assertContentEquals(innerCipherText, result.aeadCiphertext)
        assertContentEquals(keyConfCipherText, result.aeadConfirmationCiphertext)
    }

    @Test
    fun buildMessage3_setsTypeM3_validInputs() {
        // Arrange
        val innerCt = ByteArray(100) { 0xAA.toByte() }
        val keyConfCt = ByteArray(100) { 0xBB.toByte() }

        // Act
        val result = buildMessage3(innerCt, keyConfCt)

        // Assert
        assertEquals("M3", result.type)
    }

    @Test
    fun buildMessage3_preservesCiphertexts_validInputs() {
        // Arrange
        val innerCt = ByteArray(32) { it.toByte() }
        val keyConfCt = ByteArray(32) { (it + 100).toByte() }

        // Act
        val result = buildMessage3(innerCt, keyConfCt)

        // Assert
        assertContentEquals(innerCt, result.aeadCiphertext)
        assertContentEquals(keyConfCt, result.aeadConfirmationCiphertext)
    }

    @Test
    fun buildMessage3_handlesEmptyArrays_emptyInputs() {
        // Arrange
        val innerCt = ByteArray(0)
        val keyConfCt = ByteArray(0)

        // Act
        val result = buildMessage3(innerCt, keyConfCt)

        // Assert
        assertEquals("M3", result.type)
        assertEquals(0, result.aeadCiphertext.size)
        assertEquals(0, result.aeadConfirmationCiphertext.size)
    }
}
