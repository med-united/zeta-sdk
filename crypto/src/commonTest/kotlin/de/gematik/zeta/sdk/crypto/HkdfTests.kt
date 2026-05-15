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

import kotlinx.io.bytestring.hexToByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class HkdfTest {

    @Test
    fun `output length matches requested size`() {
        val result = Hkdf.hkdfSha256(ikm(), outLen = 32)
        assertEquals(result.size, 32)
    }

    @Test
    fun `output length matches requested size for non-standard lengths`() {
        listOf(1, 16, 42, 64).forEach { len ->
            assertEquals(Hkdf.hkdfSha256(ikm(), outLen = len).size, len)
        }
    }

    @Test
    fun `throws when outLen is zero`() {
        assertFailsWith<IllegalArgumentException> {
            Hkdf.hkdfSha256(ikm(), outLen = 0)
        }
    }

    @Test
    fun `throws when outLen is negative`() {
        assertFailsWith<IllegalArgumentException> {
            Hkdf.hkdfSha256(ikm(), outLen = -1)
        }
    }

    @Test
    fun `derivation is deterministic`() {
        val ikm = ikm()
        val salt = ByteArray(16) { it.toByte() }
        val info = "context".encodeToByteArray()
        val a = Hkdf.hkdfSha256(ikm, salt = salt, info = info, outLen = 32)
        val b = Hkdf.hkdfSha256(ikm, salt = salt, info = info, outLen = 32)
        assertContentEquals(a, b)
    }

    @Test
    fun `different IKM produces different output`() {
        val a = Hkdf.hkdfSha256(ByteArray(32) { 0x01 }, outLen = 32)
        val b = Hkdf.hkdfSha256(ByteArray(32) { 0x02 }, outLen = 32)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `different salt produces different output`() {
        val ikm = ikm()
        val a = Hkdf.hkdfSha256(ikm, salt = ByteArray(16) { 0x01 }, outLen = 32)
        val b = Hkdf.hkdfSha256(ikm, salt = ByteArray(16) { 0x02 }, outLen = 32)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `different info produces different output`() {
        val ikm = ikm()
        val a = Hkdf.hkdfSha256(ikm, info = "context-a".encodeToByteArray(), outLen = 32)
        val b = Hkdf.hkdfSha256(ikm, info = "context-b".encodeToByteArray(), outLen = 32)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `null salt and info are accepted`() {
        val result = Hkdf.hkdfSha256(ikm(), salt = null, info = null, outLen = 32)
        assertEquals(result.size, 32)
    }

    @Test
    fun `longer output shares prefix with shorter output`() {
        val ikm = ikm()
        val salt = ByteArray(16) { it.toByte() }
        val info = "ctx".encodeToByteArray()
        val short = Hkdf.hkdfSha256(ikm, salt = salt, info = info, outLen = 16)
        val long = Hkdf.hkdfSha256(ikm, salt = salt, info = info, outLen = 32)
        assertContentEquals(short, long.take(16).toByteArray())
    }

    @Test
    fun `known vector RFC 5869 test case 1`() {
        val ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".hexToByteString()
        val salt = "000102030405060708090a0b0c".hexToByteString()
        val info = "f0f1f2f3f4f5f6f7f8f9".hexToByteString()
        val expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

        val result = Hkdf.hkdfSha256(ikm.toByteArray(), salt = salt.toByteArray(), info = info.toByteArray(), outLen = 42)
        assertEquals(result.toHexString(), expected)
    }

    @Test
    fun `allows maximum hkdf sha256 output length`() {
        val result = Hkdf.hkdfSha256(ikm(), outLen = 8160)
        assertEquals(8160, result.size)
    }

    @Test
    fun `throws when output length exceeds hkdf sha256 maximum`() {
        assertFailsWith<IllegalArgumentException> {
            Hkdf.hkdfSha256(ikm(), outLen = 8161)
        }
    }

    private fun ikm() = ByteArray(32) { it.toByte() }
}
