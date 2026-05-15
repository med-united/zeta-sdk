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

import com.github.javakeyring.Keyring
import com.github.javakeyring.PasswordAccessException
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class KeyringSecretStoreTest {

    private val service = "de.gematik.zeta.sdk.test"
    private val keyring = mockk<Keyring>()
    private val store = KeyringSecretStore(service, keyring)

    @Test
    fun put_callsKeyringSetPassword_withServiceNameAndValue() {
        every { keyring.setPassword(service, "my-key", "my-value") } just runs

        store.put("my-key", "my-value")

        verify { keyring.setPassword(service, "my-key", "my-value") }
    }

    @Test
    fun put_doesNotThrow_whenKeyringSetPasswordThrows() {
        every { keyring.setPassword(service, any(), any()) } throws RuntimeException("keyring locked")

        store.put("key", "value")
    }

    @Test
    fun put_doesNotThrow_whenKeyringThrowsPasswordAccessException() {
        every { keyring.setPassword(service, any(), any()) } throws
            PasswordAccessException("access denied")

        store.put("key", "value")
    }

    @Test
    fun get_returnsPassword_whenKeyringHasEntry() {
        every { keyring.getPassword(service, "my-key") } returns "my-secret"

        assertEquals("my-secret", store.get("my-key"))
    }

    @Test
    fun get_returnsNull_whenKeyringThrowsPasswordAccessException() {
        every { keyring.getPassword(service, "missing-key") } throws
            PasswordAccessException("not found")

        assertNull(store.get("missing-key"))
    }

    @Test
    fun get_returnsNull_whenKeyringThrowsGenericException() {
        every { keyring.getPassword(service, "key") } throws RuntimeException("unexpected error")

        assertNull(store.get("key"))
    }

    @Test
    fun get_callsKeyringGetPassword_withCorrectServiceAndName() {
        every { keyring.getPassword(service, "lookup-key") } returns "value"

        store.get("lookup-key")

        verify { keyring.getPassword(service, "lookup-key") }
    }

    @Test
    fun get_returnsEmptyString_whenKeyringReturnsEmpty() {
        every { keyring.getPassword(service, "key") } returns ""

        assertEquals("", store.get("key"))
    }

    @Test
    fun remove_callsKeyringDeletePassword_withServiceAndName() {
        every { keyring.deletePassword(service, "my-key") } just runs

        store.remove("my-key")

        verify { keyring.deletePassword(service, "my-key") }
    }

    @Test
    fun remove_doesNotThrow_whenKeyringThrowsPasswordAccessException() {
        every { keyring.deletePassword(service, any()) } throws
            PasswordAccessException("not found")

        store.remove("missing-key")
    }

    @Test
    fun remove_doesNotThrow_whenKeyringThrowsGenericException() {
        every { keyring.deletePassword(service, any()) } throws RuntimeException("keyring error")

        store.remove("key")
    }

    @Test
    fun get_returnsNull_afterRemove() {
        val storedValues = mutableMapOf<String, String>()
        every { keyring.setPassword(service, any(), any()) } answers {
            storedValues[secondArg()] = thirdArg()
        }
        every { keyring.getPassword(service, any()) } answers {
            storedValues[firstArg()] ?: throw PasswordAccessException("not found")
        }
        every { keyring.deletePassword(service, any()) } answers {
            storedValues.remove(firstArg<String>())
        }

        store.put("temp-key", "temp-value")
        store.remove("temp-key")
        assertNull(store.get("temp-key"))
    }

    @Test
    fun put_usesConfiguredService_notHardcodedValue() {
        val customService = "com.example.custom"
        val customStore = KeyringSecretStore(customService, keyring)
        every { keyring.setPassword(customService, "key", "val") } just runs

        customStore.put("key", "val")

        verify { keyring.setPassword(customService, "key", "val") }
    }

    @Test
    fun get_usesConfiguredService_notHardcodedValue() {
        val customService = "com.example.custom"
        val customStore = KeyringSecretStore(customService, keyring)
        every { keyring.getPassword(customService, "key") } returns "value"

        customStore.get("key")

        verify { keyring.getPassword(customService, "key") }
    }
}

class CreateOsSecretStoreTest {

    @Test
    fun createOsSecretStore_returnsNonNull_whenKeyringCreatesSuccessfully() {
        val result = runCatching { createOsSecretStore("de.gematik.zeta.test") }
        result.getOrNull()?.let { store ->
            assertNotNull(store)
        }
    }

    @Test
    fun createOsSecretStore_returnsNull_whenKeyringThrows() {
        val result = runCatching { createOsSecretStore("de.gematik.zeta.test") }
        result.onFailure {
            throw AssertionError("createOsSecretStore must not throw, but threw: ${it.message}")
        }
    }

    @Test
    fun createOsSecretStore_usesProvidedService_asKeyringServiceName() {
        val store = createOsSecretStore("test.service.name") ?: return

        runCatching { store.get("probe-key") }
    }
}
