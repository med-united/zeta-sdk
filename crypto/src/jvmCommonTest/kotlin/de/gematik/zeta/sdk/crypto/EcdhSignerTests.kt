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

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@Suppress("FunctionNaming")
class EcdhSignerTest {
    private val signer = EcdhSigner()

    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Test
    fun sign_returnsSignature_validPrivateKey() {
        // Arrange
        val keyPair = generateTestKeyPair()
        val privateKeyBytes = keyPair.private.encoded
        val data = "test data".encodeToByteArray()

        // Act
        val signature = signer.sign(privateKeyBytes, data)

        // Assert
        assertNotNull(signature)
        assertTrue(signature.isNotEmpty())
    }

    @Test
    fun sign_returnsDifferentSignatures_differentData() {
        // Arrange
        val keyPair = generateTestKeyPair()
        val privateKeyBytes = keyPair.private.encoded
        val data1 = "test data 1".encodeToByteArray()
        val data2 = "test data 2".encodeToByteArray()

        // Act
        val signature1 = signer.sign(privateKeyBytes, data1)
        val signature2 = signer.sign(privateKeyBytes, data2)

        // Assert
        assertFalse(signature1.contentEquals(signature2))
    }

    @Test
    fun verify_returnsTrue_validSignature() {
        // Arrange
        val keyPair = generateTestKeyPair()
        val privateKeyBytes = keyPair.private.encoded
        val publicKeyBytes = keyPair.public.encoded
        val data = "test data".encodeToByteArray()
        val signature = signer.sign(privateKeyBytes, data)

        // Act
        val result = signer.verify(publicKeyBytes, data, signature)

        // Assert
        assertTrue(result)
    }

    @Test
    fun verify_returnsFalse_tamperedData() {
        // Arrange
        val keyPair = generateTestKeyPair()
        val privateKeyBytes = keyPair.private.encoded
        val publicKeyBytes = keyPair.public.encoded
        val originalData = "test data".encodeToByteArray()
        val tamperedData = "tampered data".encodeToByteArray()
        val signature = signer.sign(privateKeyBytes, originalData)

        // Act
        val result = signer.verify(publicKeyBytes, tamperedData, signature)

        // Assert
        assertFalse(result)
    }

    @Test
    fun verify_returnsFalse_wrongPublicKey() {
        // Arrange
        val keyPair1 = generateTestKeyPair()
        val keyPair2 = generateTestKeyPair()
        val privateKeyBytes = keyPair1.private.encoded
        val wrongPublicKeyBytes = keyPair2.public.encoded
        val data = "test data".encodeToByteArray()
        val signature = signer.sign(privateKeyBytes, data)

        // Act
        val result = signer.verify(wrongPublicKeyBytes, data, signature)

        // Assert
        assertFalse(result)
    }

    @Test
    fun verify_returnsTrue_emptyData() {
        // Arrange
        val keyPair = generateTestKeyPair()
        val privateKeyBytes = keyPair.private.encoded
        val publicKeyBytes = keyPair.public.encoded
        val emptyData = ByteArray(0)
        val signature = signer.sign(privateKeyBytes, emptyData)

        // Act
        val result = signer.verify(publicKeyBytes, emptyData, signature)

        // Assert
        assertTrue(result)
    }

    @Test
    fun verify_returnsTrue_largeData() {
        // Arrange
        val keyPair = generateTestKeyPair()
        val privateKeyBytes = keyPair.private.encoded
        val publicKeyBytes = keyPair.public.encoded
        val largeData = ByteArray(10_000) { it.toByte() }
        val signature = signer.sign(privateKeyBytes, largeData)

        // Act
        val result = signer.verify(publicKeyBytes, largeData, signature)

        // Assert
        assertTrue(result)
    }

    @Test
    fun signAndVerify_roundTrip_multipleOperations() {
        // Arrange
        val keyPair = generateTestKeyPair()
        val privateKeyBytes = keyPair.private.encoded
        val publicKeyBytes = keyPair.public.encoded
        val testData = listOf(
            "data1".encodeToByteArray(),
            "data2".encodeToByteArray(),
            "data3".encodeToByteArray(),
        )

        // Act & Assert
        testData.forEach { data ->
            val signature = signer.sign(privateKeyBytes, data)
            assertTrue(signer.verify(publicKeyBytes, data, signature))
        }
    }

    @Test
    fun constructor_addsBouncyCastleProvider_providerNotPresent() {
        // Arrange
        Security.removeProvider("BC")

        // Act
        EcdhSigner()

        // Assert
        assertNotNull(Security.getProvider("BC"))
    }

    @Test
    fun constructor_doesNotDuplicateProvider_providerAlreadyPresent() {
        // Arrange
        val initialProviders = Security.getProviders().size

        // Act
        EcdhSigner()

        // Assert
        val finalProviders = Security.getProviders().size
        assertTrue(finalProviders >= initialProviders)
    }

    private fun generateTestKeyPair(): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
        return keyPairGenerator.generateKeyPair()
    }
}
