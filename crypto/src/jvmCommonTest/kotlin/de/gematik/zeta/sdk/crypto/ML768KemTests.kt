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
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@Suppress("FunctionNaming")
class ML768KemTest {
    private val kem = ML768Kem()
    private val EXPECTED_PUBLIC_KEY_SIZE = 1184
    private val EXPECTED_PRIVATE_KEY_SIZE = 2400
    private val EXPECTED_CIPHERTEXT_SIZE = 1088
    private val EXPECTED_SHARED_SECRET_SIZE = 32

    @Test
    fun generateKeys_returnsValidKeyPair_always() {
        // Arrange & Act
        val keyPair = kem.generateKeys()

        // Assert
        assertNotNull(keyPair.skpi)
        assertNotNull(keyPair.privateKey)
        assertTrue(keyPair.skpi.isNotEmpty())
        assertTrue(keyPair.privateKey.isNotEmpty())
    }

    @Test
    fun generateKeys_returnsCorrectKeySizes_mlkem768() {
        // Arrange & Act
        val keyPair = kem.generateKeys()

        // Assert
        assertEquals(keyPair.skpi.size, EXPECTED_PUBLIC_KEY_SIZE)
        assertEquals(keyPair.privateKey.size, EXPECTED_PRIVATE_KEY_SIZE)
    }

    @Test
    fun generateKeys_returnsDifferentKeys_multipleInvocations() {
        // Arrange & Act
        val keyPair1 = kem.generateKeys()
        val keyPair2 = kem.generateKeys()

        // Assert
        assertFalse(keyPair1.privateKey.contentEquals(keyPair2.privateKey))
        assertFalse(keyPair1.skpi.contentEquals(keyPair2.skpi))
    }

    @Test
    fun generateKeys_sec1IsNull_mlkemDoesNotUseSec1() {
        // Arrange & Act
        val keyPair = kem.generateKeys()

        // Assert
        assertEquals(keyPair.sec1, null)
    }

    @Test
    fun encapsulate_returnsValidResult_validPublicKey() {
        // Arrange
        val receiverKeys = kem.generateKeys()

        // Act
        val result = kem.encapsulate(receiverKeys.skpi)

        // Assert
        assertNotNull(result.ciphertext)
        assertNotNull(result.sharedSecret)
        assertTrue(result.ciphertext.isNotEmpty())
        assertTrue(result.sharedSecret.isNotEmpty())
    }

    @Test
    fun encapsulate_returnsCorrectSizes_mlkem768() {
        // Arrange
        val receiverKeys = kem.generateKeys()

        // Act
        val result = kem.encapsulate(receiverKeys.skpi)

        // Assert
        assertEquals(result.ciphertext.size, EXPECTED_CIPHERTEXT_SIZE)
        assertEquals(result.sharedSecret.size, EXPECTED_SHARED_SECRET_SIZE)
    }

    @Test
    fun encapsulate_returnsDifferentCiphertext_multipleInvocations() {
        // Arrange
        val receiverKeys = kem.generateKeys()

        // Act
        val result1 = kem.encapsulate(receiverKeys.skpi)
        val result2 = kem.encapsulate(receiverKeys.skpi)

        // Assert
        assertFalse(result1.ciphertext.contentEquals(result2.ciphertext))
    }

    @Test
    fun encapsulate_returnsDifferentSharedSecret_multipleInvocations() {
        // Arrange
        val receiverKeys = kem.generateKeys()

        // Act
        val result1 = kem.encapsulate(receiverKeys.skpi)
        val result2 = kem.encapsulate(receiverKeys.skpi)

        // Assert
        assertFalse(result1.sharedSecret.contentEquals(result2.sharedSecret))
    }

    @Test
    fun decapsulate_returnsSharedSecret_validInputs() {
        // Arrange
        val receiverKeys = kem.generateKeys()
        val encapResult = kem.encapsulate(receiverKeys.skpi)

        // Act
        val sharedSecret = kem.decapsulate(receiverKeys.privateKey, encapResult.ciphertext)

        // Assert
        assertNotNull(sharedSecret)
        assertTrue(sharedSecret.isNotEmpty())
        assertContentEquals(encapResult.sharedSecret, sharedSecret)
    }

    @Test
    fun decapsulate_returnsCorrectSize_validInputs() {
        // Arrange
        val receiverKeys = kem.generateKeys()
        val encapResult = kem.encapsulate(receiverKeys.skpi)

        // Act
        val sharedSecret = kem.decapsulate(receiverKeys.privateKey, encapResult.ciphertext)

        // Assert
        assertEquals(sharedSecret.size, EXPECTED_SHARED_SECRET_SIZE)
    }

    @Test
    fun encapsulateAndDecapsulate_producesSameSharedSecret_validKeys() {
        // Arrange
        val receiverKeys = kem.generateKeys()

        // Act
        val encapResult = kem.encapsulate(receiverKeys.skpi)
        val decapsulatedSecret = kem.decapsulate(receiverKeys.privateKey, encapResult.ciphertext)

        // Assert
        assertContentEquals(encapResult.sharedSecret, decapsulatedSecret)
    }

    @Test
    fun encapsulateAndDecapsulate_producesDifferentSecrets_differentReceivers() {
        // Arrange
        val receiver1Keys = kem.generateKeys()
        val receiver2Keys = kem.generateKeys()

        // Act
        val encapResult = kem.encapsulate(receiver1Keys.skpi)
        val secret1 = kem.decapsulate(receiver1Keys.privateKey, encapResult.ciphertext)
        val secret2 = kem.decapsulate(receiver2Keys.privateKey, encapResult.ciphertext)

        // Assert
        assertFalse(secret1.contentEquals(secret2))
    }

    @Test
    fun encapsulateAndDecapsulate_multipleRoundTrips_allSucceed() {
        // Arrange
        val receiverKeys = kem.generateKeys()
        val iterations = 5

        // Act & Assert
        repeat(iterations) {
            val encapResult = kem.encapsulate(receiverKeys.skpi)
            val decapsulatedSecret = kem.decapsulate(receiverKeys.privateKey, encapResult.ciphertext)
            assertContentEquals(encapResult.sharedSecret, decapsulatedSecret)
        }
    }

    @Test
    fun encapsulateAndDecapsulate_differentKeysEachTime_allValid() {
        // Arrange
        val iterations = 3

        // Act & Assert
        repeat(iterations) {
            val keys = kem.generateKeys()
            val encapResult = kem.encapsulate(keys.skpi)
            val decapsulatedSecret = kem.decapsulate(keys.privateKey, encapResult.ciphertext)
            assertContentEquals(encapResult.sharedSecret, decapsulatedSecret)
        }
    }

    @Test
    fun decapsulate_producesDifferentSecrets_wrongPrivateKey() {
        // Arrange
        val receiver1Keys = kem.generateKeys()
        val receiver2Keys = kem.generateKeys()
        val encapResult = kem.encapsulate(receiver1Keys.skpi)

        // Act
        val correctSecret = kem.decapsulate(receiver1Keys.privateKey, encapResult.ciphertext)
        val wrongSecret = kem.decapsulate(receiver2Keys.privateKey, encapResult.ciphertext)

        // Assert
        assertFalse(correctSecret.contentEquals(wrongSecret))
    }

    @Test
    fun encapsulate_withMultipleRecipients_producesIndependentSecrets() {
        // Arrange
        val recipient1 = kem.generateKeys()
        val recipient2 = kem.generateKeys()
        val recipient3 = kem.generateKeys()

        // Act
        val encap1 = kem.encapsulate(recipient1.skpi)
        val encap2 = kem.encapsulate(recipient2.skpi)
        val encap3 = kem.encapsulate(recipient3.skpi)

        val secret1 = kem.decapsulate(recipient1.privateKey, encap1.ciphertext)
        val secret2 = kem.decapsulate(recipient2.privateKey, encap2.ciphertext)
        val secret3 = kem.decapsulate(recipient3.privateKey, encap3.ciphertext)

        // Assert
        assertContentEquals(encap1.sharedSecret, secret1)
        assertContentEquals(encap2.sharedSecret, secret2)
        assertContentEquals(encap3.sharedSecret, secret3)
        assertFalse(secret1.contentEquals(secret2))
        assertFalse(secret2.contentEquals(secret3))
        assertFalse(secret1.contentEquals(secret3))
    }
}
