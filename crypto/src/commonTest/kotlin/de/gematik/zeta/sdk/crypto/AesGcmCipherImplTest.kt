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
import kotlin.test.assertFalse

@Suppress("FunctionNaming")
class AesGcmCipherImplTest {

    private val cipher = AesGcmCipherImpl()

    private val validKey = ByteArray(32) { it.toByte() }
    private val validIv = ByteArray(12) { it.toByte() }
    private val plaintext = "Hello, AES-GCM!".encodeToByteArray()
    private val aad = "additional-data".encodeToByteArray()

    @Test
    fun `encrypt then decrypt roundtrip without explicit IV`() {
        assertContentEquals(plaintext, cipher.decrypt(validKey, cipher.encrypt(validKey, plaintext)))
    }

    @Test
    fun `encrypt then decrypt roundtrip with explicit IV`() {
        val encrypted = cipher.encrypt(validKey, plaintext, iv = validIv)
        val decrypted = cipher.decrypt(validKey, encrypted.drop(12).toByteArray(), iv = validIv)
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun `encrypt then decrypt roundtrip with AAD`() {
        val encrypted = cipher.encrypt(validKey, plaintext, aad = aad)
        assertContentEquals(plaintext, cipher.decrypt(validKey, encrypted, aad = aad))
    }

    @Test
    fun `encrypt then decrypt roundtrip with empty plaintext`() {
        val encrypted = cipher.encrypt(validKey, ByteArray(0))
        assertContentEquals(ByteArray(0), cipher.decrypt(validKey, encrypted))
    }

    @Test
    fun `encrypt then decrypt roundtrip with large plaintext`() {
        val large = ByteArray(1024 * 1024) { it.toByte() }
        assertContentEquals(large, cipher.decrypt(validKey, cipher.encrypt(validKey, large)))
    }

    @Test
    fun `encrypt output prepends IV`() {
        val encrypted = cipher.encrypt(validKey, plaintext, iv = validIv)
        assertContentEquals(validIv, encrypted.copyOfRange(0, 12))
    }

    @Test
    fun `encrypt output size is IV + plaintext + 16 byte tag`() {
        val encrypted = cipher.encrypt(validKey, plaintext, iv = validIv)
        assertEquals(encrypted.size, 12 + plaintext.size + 16)
    }

    @Test
    fun `encrypt generates unique IV on each call`() {
        val ivA = cipher.encrypt(validKey, plaintext).copyOfRange(0, 12)
        val ivB = cipher.encrypt(validKey, plaintext).copyOfRange(0, 12)
        assertFalse(ivA.contentEquals(ivB))
    }

    @Test
    fun `decrypt throws with wrong key`() {
        val encrypted = cipher.encrypt(validKey, plaintext)
        assertFailsWith<Exception> {
            cipher.decrypt(ByteArray(32) { 0xFF.toByte() }, encrypted)
        }
    }

    @Test
    fun `decrypt throws when AAD is omitted but was used during encrypt`() {
        val encrypted = cipher.encrypt(validKey, plaintext, aad = aad)
        assertFailsWith<Exception> { cipher.decrypt(validKey, encrypted) }
    }

    @Test
    fun `decrypt throws when AAD does not match`() {
        val encrypted = cipher.encrypt(validKey, plaintext, aad = aad)
        assertFailsWith<Exception> { cipher.decrypt(validKey, encrypted, aad = "wrong".encodeToByteArray()) }
    }

    @Test
    fun `decrypt throws when ciphertext body is tampered`() {
        val encrypted = cipher.encrypt(validKey, plaintext)
        encrypted[encrypted.size - 1] = encrypted[encrypted.size - 1].inc()
        assertFailsWith<Exception> { cipher.decrypt(validKey, encrypted) }
    }

    @Test
    fun `decrypt throws when prepended IV is tampered`() {
        val encrypted = cipher.encrypt(validKey, plaintext)
        encrypted[0] = encrypted[0].inc()
        assertFailsWith<Exception> { cipher.decrypt(validKey, encrypted) }
    }

    @Test
    fun `encrypt throws when key is not 32 bytes`() {
        assertFailsWith<IllegalArgumentException> { cipher.encrypt(ByteArray(16), plaintext) }
        assertFailsWith<IllegalArgumentException> { cipher.encrypt(ByteArray(33), plaintext) }
    }

    @Test
    fun `encrypt throws when explicit IV is not 12 bytes`() {
        assertFailsWith<IllegalArgumentException> { cipher.encrypt(validKey, plaintext, iv = ByteArray(16)) }
        assertFailsWith<IllegalArgumentException> { cipher.encrypt(validKey, plaintext, iv = ByteArray(11)) }
    }

    @Test
    fun `decrypt throws when ciphertext is too short`() {
        assertFailsWith<IllegalArgumentException> { cipher.decrypt(validKey, ByteArray(12)) }
    }
}
