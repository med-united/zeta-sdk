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
import de.gematik.zeta.logging.Log
import de.gematik.zeta.sdk.crypto.AesGcmCipher
import kotlin.io.encoding.Base64

class EncryptedSettings(
    private val delegate: Settings,
    private val cipher: AesGcmCipher,
    cipherB64Key: String,
    private val version: Byte = 1,
) : Settings by delegate {
    private val aesKey = validateAesKey(cipherB64Key)

    override fun putString(key: String, value: String) {
        val ct = cipher.encrypt(aesKey, value.encodeToByteArray())
        val packed = byteArrayOf(version) + ct
        delegate.putString(key, Base64.encode(packed))
    }

    override fun getString(key: String, defaultValue: String): String {
        val stored = delegate.getString(key, "")
        if (stored.isEmpty()) return defaultValue
        val decrypted = decryptStored(key, stored)
        return decrypted.ifEmpty { defaultValue }
    }

    override fun getStringOrNull(key: String): String? {
        val stored = delegate.getStringOrNull(key) ?: return null
        if (stored.isBlank()) return null
        val decrypted = decryptStored(key, stored)
        return decrypted.ifEmpty { null }
    }

    private fun decryptStored(key: String, stored: String): String =
        runCatching {
            val packed = Base64.decode(stored)
            require(packed.isNotEmpty()) { "Corrupt ciphertext" }
            require(packed[0] == 1.toByte()) { "Unsupported version ${packed[0]}" }
            val ct = packed.copyOfRange(1, packed.size)
            cipher.decrypt(aesKey, ct).decodeToString()
        }.onFailure {
            Log.w { "SDK storage: The key $key could not be decrypted. " }
            delegate.remove(key)
        }.getOrElse { "" }
}

expect fun provideSdkStorage(config: StorageConfig.Default): SdkStorage

interface SecretStore {
    fun put(name: String, value: String)
    fun get(name: String): String?
    fun remove(name: String)
    fun clearNamespace()
}
fun validateAesKey(aesB64Key: String): ByteArray {
    require(aesB64Key.isNotBlank()) {
        "aesB64Key must be provided."
    }
    val keyBytes = runCatching {
        Base64.decode(aesB64Key)
    }.getOrElse {
        error("aesB64Key must be a valid Base64 string")
    }
    require(keyBytes.size == 32) {
        "aesB64Key must decode to exactly 32 bytes (AES-256), got ${keyBytes.size}"
    }
    return keyBytes
}
