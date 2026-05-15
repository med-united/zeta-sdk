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

package de.gematik.zeta.sdk.tpm

import de.gematik.zeta.logging.Log
import de.gematik.zeta.sdk.storage.ExtendedStorage
import de.gematik.zeta.sdk.storage.SdkStorage
import kotlin.time.Clock

interface TpmStorage {
    suspend fun saveClientKeys(publicKey: String, privateKey: String)
    suspend fun saveDpopKeys(resource: String, publicKey: String, privateKey: String)
    suspend fun getClientPublicKey(): String?
    suspend fun getClientPrivateKey(): String?
    suspend fun getDpopPublicKey(resource: String): String?
    suspend fun getDpopPrivateKey(resource: String): String?
    suspend fun getClientKeyCreatedAt(): String?
    suspend fun deleteDpopKeys(resource: String)
    suspend fun deleteAllDpopKeys()
    suspend fun clear()
}

class TpmStorageImpl(private val storage: SdkStorage) : TpmStorage {
    private val extendedStorage = ExtendedStorage(storage)
    companion object {
        private const val CLIENT_PUBLIC_KEY = "client_public_key"
        private const val CLIENT_PRIVATE_KEY = "client_private_key"
        private const val CLIENT_KEY_CREATE_TIMESTAMP = "client_key_created_timestamp"
        private const val DPOP_RESOURCES_INDEX = "dpop_resources_index"
    }

    private fun dpopPublicKey(resource: String) = "dpop_public_key_${extendedStorage.hash(resource)}"
    private fun dpopPrivateKey(resource: String) = "dpop_private_key_${extendedStorage.hash(resource)}"

    override suspend fun saveClientKeys(publicKey: String, privateKey: String) {
        Log.d { "Saving client keys" }
        storage.put(CLIENT_PUBLIC_KEY, publicKey)
        storage.put(CLIENT_PRIVATE_KEY, privateKey)
        storage.put(CLIENT_KEY_CREATE_TIMESTAMP, Clock.System.now().toString())
    }

    override suspend fun saveDpopKeys(resource: String, publicKey: String, privateKey: String) {
        Log.d { "Saving DPoP keys for resource=$resource" }

        storage.put(dpopPublicKey(resource), publicKey)
        storage.put(dpopPrivateKey(resource), privateKey)

        addResourceToIndex(resource)
    }

    override suspend fun getClientPublicKey(): String? = storage.get(CLIENT_PUBLIC_KEY)
    override suspend fun getClientPrivateKey(): String? = storage.get(CLIENT_PRIVATE_KEY)
    override suspend fun getClientKeyCreatedAt(): String? = storage.get(CLIENT_KEY_CREATE_TIMESTAMP)

    override suspend fun getDpopPublicKey(resource: String): String? =
        storage.get(dpopPublicKey(resource))

    override suspend fun getDpopPrivateKey(resource: String): String? =
        storage.get(dpopPrivateKey(resource))

    override suspend fun deleteDpopKeys(resource: String) {
        Log.d { "Deleting DPoP keys for resource=$resource" }

        storage.remove(dpopPublicKey(resource))
        storage.remove(dpopPrivateKey(resource))

        removeResourceFromIndex(resource)
    }

    override suspend fun deleteAllDpopKeys() {
        Log.d { "Deleting all DPoP keys" }

        getResourceIndex().forEach { resource ->
            storage.remove(dpopPublicKey(resource))
            storage.remove(dpopPrivateKey(resource))
        }

        storage.remove(DPOP_RESOURCES_INDEX)
    }

    override suspend fun clear() {
        Log.d { "Clearing all TPM storage" }

        deleteAllDpopKeys()

        storage.remove(CLIENT_PUBLIC_KEY)
        storage.remove(CLIENT_PRIVATE_KEY)
        storage.remove(CLIENT_KEY_CREATE_TIMESTAMP)
    }

    private suspend fun getResourceIndex(): Set<String> {
        val raw = storage.get(DPOP_RESOURCES_INDEX) ?: return emptySet()
        return raw.split(",").filter { it.isNotBlank() }.toSet()
    }

    private suspend fun addResourceToIndex(resource: String) {
        val updated = getResourceIndex() + resource
        storage.put(DPOP_RESOURCES_INDEX, updated.joinToString(","))
    }

    private suspend fun removeResourceFromIndex(resource: String) {
        val updated = getResourceIndex() - resource
        if (updated.isEmpty()) {
            storage.remove(DPOP_RESOURCES_INDEX)
        } else {
            storage.put(DPOP_RESOURCES_INDEX, updated.joinToString(","))
        }
    }
}
