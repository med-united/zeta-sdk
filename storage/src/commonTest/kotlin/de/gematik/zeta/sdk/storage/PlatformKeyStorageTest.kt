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

package de.gematik.zeta.sdk.storage

import com.russhwolf.settings.Settings
import de.gematik.zeta.sdk.crypto.AesGcmCipher
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class EncryptedSettingsTest {
    private val aesKey = ByteArray(32) { 1 }
    private val keyB64 = Base64.encode(aesKey)

    @Test
    fun putString_storesEncryptedVersionedBase64Value() {
        val delegate = FakeSettings()
        val cipher = FakeAesGcmCipher()

        val settings = EncryptedSettings(
            delegate = delegate,
            cipher = cipher,
            cipherB64Key = keyB64,
        )

        settings.putString("token", "secret-value")

        val stored = delegate.getString("token", "")
        assertTrue(stored.isNotEmpty())
        assertNotEquals("secret-value", stored)

        val packed = Base64.decode(stored)
        assertEquals(1.toByte(), packed[0])

        val ciphertext = packed.copyOfRange(1, packed.size)
        assertContentEquals(
            "enc:secret-value".encodeToByteArray(),
            ciphertext,
        )
    }

    @Test
    fun getString_returnsDefault_whenValueMissing() {
        val delegate = FakeSettings()
        val cipher = FakeAesGcmCipher()

        val settings = EncryptedSettings(
            delegate = delegate,
            cipher = cipher,
            cipherB64Key = keyB64,
        )

        val result = settings.getString("missing", "default-value")

        assertEquals("default-value", result)
    }

    @Test
    fun getString_decryptsStoredEncryptedValue() {
        val delegate = FakeSettings()
        val cipher = FakeAesGcmCipher()

        val settings = EncryptedSettings(
            delegate = delegate,
            cipher = cipher,
            cipherB64Key = keyB64,
        )

        val ciphertext = "enc:secret-value".encodeToByteArray()
        val packed = byteArrayOf(1) + ciphertext
        delegate.putString("token", Base64.encode(packed))

        val result = settings.getString("token", "default-value")

        assertEquals("secret-value", result)
    }

    @Test
    fun getString_returnsDefaultValue_whenBase64IsInvalid() {
        val delegate = FakeSettings()
        val cipher = FakeAesGcmCipher()

        val settings = EncryptedSettings(
            delegate = delegate,
            cipher = cipher,
            cipherB64Key = keyB64,
        )

        delegate.putString("token", "%%%not-base64%%%")

        val result = settings.getString("token", "default-value")

        assertEquals("default-value", result)
        assertEquals("", delegate.getString("token", ""))
    }

    @Test
    fun getString_returnsDefaultValue_whenVersionUnsupported() {
        val delegate = FakeSettings()
        val cipher = FakeAesGcmCipher()

        val settings = EncryptedSettings(
            delegate = delegate,
            cipher = cipher,
            cipherB64Key = keyB64,
        )

        val packed = byteArrayOf(2) + "enc:secret-value".encodeToByteArray()
        delegate.putString("token", Base64.encode(packed))

        val result = settings.getString("token", "default-value")

        assertEquals("default-value", result)
        assertEquals("", delegate.getString("token", ""))
    }

    @Test
    fun getString_returnsDefaultValue_whenDecryptFails() {
        val delegate = FakeSettings()
        val cipher = FakeAesGcmCipher(throwOnDecrypt = true)

        val settings = EncryptedSettings(
            delegate = delegate,
            cipher = cipher,
            cipherB64Key = keyB64,
        )

        val packed = byteArrayOf(1) + "enc:secret-value".encodeToByteArray()
        delegate.putString("token", Base64.encode(packed))

        val result = settings.getString("token", "default-value")

        assertEquals("default-value", result)
        assertEquals("", delegate.getString("token", ""))
    }

    private class FakeSettings : Settings {
        private val values = mutableMapOf<String, Any?>()

        override val keys: Set<String>
            get() = values.keys

        override val size: Int
            get() = values.size

        override fun clear() {
            values.clear()
        }

        override fun remove(key: String) {
            values.remove(key)
        }

        override fun hasKey(key: String): Boolean = values.containsKey(key)

        override fun putString(key: String, value: String) {
            values[key] = value
        }

        override fun getString(key: String, defaultValue: String): String {
            return values[key] as? String ?: defaultValue
        }

        override fun getStringOrNull(key: String): String? {
            return values[key] as String?
        }

        override fun putInt(key: String, value: Int) {
            values[key] = value
        }

        override fun getInt(key: String, defaultValue: Int): Int {
            return values[key] as? Int ?: defaultValue
        }

        override fun getIntOrNull(key: String): Int? {
            return values[key] as Int?
        }

        override fun putLong(key: String, value: Long) {
            values[key] = value
        }

        override fun getLong(key: String, defaultValue: Long): Long {
            return values[key] as? Long ?: defaultValue
        }

        override fun getLongOrNull(key: String): Long? {
            return values[key] as Long?
        }

        override fun putFloat(key: String, value: Float) {
            values[key] = value
        }

        override fun getFloat(key: String, defaultValue: Float): Float {
            return values[key] as? Float ?: defaultValue
        }

        override fun getFloatOrNull(key: String): Float? {
            return values[key] as Float?
        }

        override fun putDouble(key: String, value: Double) {
            values[key] = value
        }

        override fun getDouble(key: String, defaultValue: Double): Double {
            return values[key] as? Double ?: defaultValue
        }

        override fun getDoubleOrNull(key: String): Double? {
            return values[key] as Double?
        }

        override fun putBoolean(key: String, value: Boolean) {
            values[key] = value
        }

        override fun getBoolean(key: String, defaultValue: Boolean): Boolean {
            return values[key] as? Boolean ?: defaultValue
        }

        override fun getBooleanOrNull(key: String): Boolean? {
            return values[key] as Boolean?
        }
    }

    private class FakeAesGcmCipher(
        private val throwOnDecrypt: Boolean = false,
    ) : AesGcmCipher {
        override fun encrypt(aesKey: ByteArray, plainText: ByteArray, iv: ByteArray?, aad: ByteArray?): ByteArray {
            return "enc:${plainText.decodeToString()}".encodeToByteArray()
        }

        override fun decrypt(aesKey: ByteArray, cipherText: ByteArray, iv: ByteArray?, aad: ByteArray?): ByteArray {
            if (throwOnDecrypt) error("decrypt failed")

            val text = cipherText.decodeToString()
            require(text.startsWith("enc:")) { "invalid ciphertext" }
            return text.removePrefix("enc:").encodeToByteArray()
        }
    }
    private fun assertContentEquals(expected: ByteArray, actual: ByteArray) {
        assertTrue(expected.contentEquals(actual), "Expected byte arrays to be equal")
    }
}
