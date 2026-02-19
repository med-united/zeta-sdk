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

import junit.framework.TestCase.assertNotNull
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Suppress("NullPointerException", "FunctionNaming", "UnsafeCallOnNullableType")
class EcdhP256KemTest {
    private val kem = EcdhP256Kem()

    @Test
    fun generateKeys_returnsValidKeyPair_always() {
        // Arrange & Act
        val keyPair = kem.generateKeys()

        // Assert
        assertNotNull(keyPair.skpi)
        assertNotNull(keyPair.sec1)
        assertNotNull(keyPair.privateKey)
        assertTrue(keyPair.skpi.isNotEmpty())
        assertTrue(keyPair.sec1!!.isNotEmpty())
        assertTrue(keyPair.privateKey.isNotEmpty())
    }

    @Test
    fun generateKeys_returnsSec1Format_65Bytes() {
        // Arrange & Act
        val keyPair = kem.generateKeys()

        // Assert
        assertNotNull(keyPair.sec1)
        assertEquals(65, keyPair.sec1!!.size)
        assertEquals(0x04.toByte(), keyPair.sec1[0])
    }

    @Test
    fun generateKeys_returnsDifferentKeys_multipleInvocations() {
        // Arrange & Act
        val keyPair1 = kem.generateKeys()
        val keyPair2 = kem.generateKeys()

        // Assert
        assertFalse(keyPair1.privateKey.contentEquals(keyPair2.privateKey))
        assertFalse(keyPair1.sec1!!.contentEquals(keyPair2.sec1!!))
    }

    @Test
    fun encapsulate_returnsValidResult_validPublicKey() {
        // Arrange
        val receiverKeys = kem.generateKeys()

        // Act
        val result = kem.encapsulate(receiverKeys.sec1!!)

        // Assert
        assertNotNull(result.ciphertext)
        assertNotNull(result.sharedSecret)
        assertEquals(65, result.ciphertext.size)
        assertEquals(0x04.toByte(), result.ciphertext[0])
        assertTrue(result.sharedSecret.isNotEmpty())
    }

    @Test
    fun encapsulate_returnsDifferentCiphertext_multipleInvocations() {
        // Arrange
        val receiverKeys = kem.generateKeys()

        // Act
        assertNotNull(receiverKeys.sec1)
        val result1 = kem.encapsulate(receiverKeys.sec1!!)
        val result2 = kem.encapsulate(receiverKeys.sec1)

        // Assert
        assertFalse(result1.ciphertext.contentEquals(result2.ciphertext))
    }

    @Test
    fun encapsulate_throwsException_invalidPublicKeySize() {
        // Arrange
        val invalidKey = ByteArray(64) // Wrong size

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            kem.encapsulate(invalidKey)
        }
    }

    @Test
    fun encapsulate_throwsException_invalidPublicKeyPrefix() {
        // Arrange
        val invalidKey = ByteArray(65) { 0x00 } // Wrong prefix

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            kem.encapsulate(invalidKey)
        }
    }

    @Test
    fun decapsulate_returnsSharedSecret_validInputs() {
        // Arrange
        val receiverKeys = kem.generateKeys()
        val encapResult = kem.encapsulate(receiverKeys.sec1!!)

        // Act
        val sharedSecret = kem.decapsulate(receiverKeys.privateKey, encapResult.ciphertext)

        // Assert
        assertNotNull(sharedSecret)
        assertTrue(sharedSecret.isNotEmpty())
        assertContentEquals(encapResult.sharedSecret, sharedSecret)
    }

    @Test
    fun decapsulate_throwsException_invalidCiphertextSize() {
        // Arrange
        val receiverKeys = kem.generateKeys()
        val invalidCiphertext = ByteArray(64)

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            kem.decapsulate(receiverKeys.privateKey, invalidCiphertext)
        }
    }

    @Test
    fun decapsulate_throwsException_invalidCiphertextPrefix() {
        // Arrange
        val receiverKeys = kem.generateKeys()
        val invalidCiphertext = ByteArray(65) { 0x00 }

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            kem.decapsulate(receiverKeys.privateKey, invalidCiphertext)
        }
    }

    @Test
    fun encapsulateAndDecapsulate_producesSameSharedSecret_validKeys() {
        // Arrange
        val receiverKeys = kem.generateKeys()

        // Act
        val encapResult = kem.encapsulate(receiverKeys.sec1!!)
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
        val encapResult = kem.encapsulate(receiver1Keys.sec1!!)
        val secret1 = kem.decapsulate(receiver1Keys.privateKey, encapResult.ciphertext)
        val secret2 = kem.decapsulate(receiver2Keys.privateKey, encapResult.ciphertext)

        // Assert
        assertFalse(secret1.contentEquals(secret2))
    }

    @Test
    fun toJwk_returnsValidJwk_validPublicKey() {
        // Arrange
        val keyPair = kem.generateKeys()

        // Act
        val jwk = kem.toJwk(keyPair.skpi)

        // Assert
        assertNotNull(jwk.kid)
        assertEquals("EC", jwk.kty)
        assertEquals("ES256", jwk.alg)
        assertEquals("sig", jwk.use)
        assertEquals("P-256", jwk.crv)
        assertNotNull(jwk.x)
        assertNotNull(jwk.y)
    }

    @Test
    fun toJwk_producesConsistentKid_samePublicKey() {
        // Arrange
        val keyPair = kem.generateKeys()

        // Act
        val jwk1 = kem.toJwk(keyPair.skpi)
        val jwk2 = kem.toJwk(keyPair.skpi)

        // Assert
        assertEquals(jwk1.kid, jwk2.kid)
    }

    @Test
    fun toJwk_producesBase64UrlEncodedCoordinates_validKey() {
        // Arrange
        val keyPair = kem.generateKeys()

        // Act
        val jwk = kem.toJwk(keyPair.skpi)

        // Assert
        assertNotNull(jwk.x)
        assertNotNull(jwk.y)
        assertFalse(jwk.x.contains("+"))
        assertFalse(jwk.x.contains("/"))
        assertFalse(jwk.x.contains("="))
        assertFalse(jwk.y.contains("+"))
        assertFalse(jwk.y.contains("/"))
        assertFalse(jwk.y.contains("="))
    }

    @Test
    fun toJwk_throwsException_nonP256Key() {
        // Arrange
        val keyPairGen = KeyPairGenerator.getInstance("EC")
        keyPairGen.initialize(ECGenParameterSpec("secp384r1"))
        val keyPair = keyPairGen.generateKeyPair()
        val publicKeyBytes = keyPair.public.encoded

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            kem.toJwk(publicKeyBytes)
        }
    }

    @Test
    fun loadKeys_returnsValidKeyPair_validInputs() {
        // Arrange
        val originalKeys = kem.generateKeys()

        // Act
        val loadedKeys = kem.loadKeys(originalKeys.privateKey, originalKeys.skpi)

        // Assert
        assertContentEquals(originalKeys.skpi, loadedKeys.skpi)
        assertContentEquals(originalKeys.sec1, loadedKeys.sec1)
        assertContentEquals(originalKeys.privateKey, loadedKeys.privateKey)
    }

    @Test
    fun loadKeys_producesSec1Format_validPublicKey() {
        // Arrange
        val originalKeys = kem.generateKeys()

        // Act
        val loadedKeys = kem.loadKeys(originalKeys.privateKey, originalKeys.skpi)

        // Assert
        assertNotNull(loadedKeys.sec1)
        assertEquals(65, loadedKeys.sec1!!.size)
        assertEquals(0x04.toByte(), loadedKeys.sec1[0])
    }

    @Test
    fun loadKeys_canBeUsedForEncapsulation_loadedKeys() {
        // Arrange
        val originalKeys = kem.generateKeys()
        val loadedKeys = kem.loadKeys(originalKeys.privateKey, originalKeys.skpi)

        // Act & Assert
        assertNotNull(loadedKeys.sec1)
        val encapResult = kem.encapsulate(loadedKeys.sec1!!)
        val sharedSecret = kem.decapsulate(loadedKeys.privateKey, encapResult.ciphertext)

        assertContentEquals(encapResult.sharedSecret, sharedSecret)
    }

    @Test
    fun hashWithSha256_returns32Bytes_anyInput() {
        // Arrange
        val input = "test data".encodeToByteArray()

        // Act
        val hash = hashWithSha256(input)

        // Assert
        assertEquals(32, hash.size)
    }

    @Test
    fun hashWithSha256_returnsConsistentHash_sameInput() {
        // Arrange
        val input = "test data".encodeToByteArray()

        // Act
        val hash1 = hashWithSha256(input)
        val hash2 = hashWithSha256(input)

        // Assert
        assertContentEquals(hash1, hash2)
    }

    @Test
    fun hashWithSha256_returnsDifferentHashes_differentInputs() {
        // Arrange
        val input1 = "test data 1".encodeToByteArray()
        val input2 = "test data 2".encodeToByteArray()

        // Act
        val hash1 = hashWithSha256(input1)
        val hash2 = hashWithSha256(input2)

        // Assert
        assertFalse(hash1.contentEquals(hash2))
    }

    @Test
    fun hashWithSha256_handlesEmptyInput_emptyByteArray() {
        // Arrange
        val input = ByteArray(0)

        // Act
        val hash = hashWithSha256(input)

        // Assert
        assertEquals(32, hash.size)
    }

    @Test
    fun hashWithSha256_handlesLargeInput_largeByteArray() {
        // Arrange
        val input = ByteArray(10_000) { it.toByte() }

        // Act
        val hash = hashWithSha256(input)

        // Assert
        assertEquals(32, hash.size)
    }
}
