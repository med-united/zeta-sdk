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

package de.gematik.zeta.sdk.network.http.client

import de.gematik.zeta.sdk.network.http.client.CompositeCookieStorage.Companion.ZETA_ROUTE_COOKIE
import de.gematik.zeta.sdk.storage.InMemoryStorage
import io.ktor.http.Cookie
import io.ktor.http.Url
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SdkCookieStorageTest {
    private val url = Url("https://example.com/path")
    private fun createComposite(fqdn: String = "example.com"): Pair<CompositeCookieStorage, SdkCookieStorage> {
        val sdkStorage = SdkCookieStorage(InMemoryStorage(), fqdn)
        return CompositeCookieStorage(sdkStorage) to sdkStorage
    }

    private fun createStorage(fqdn: String = "example.com"): Pair<SdkCookieStorage, InMemoryStorage> {
        val storage = InMemoryStorage()
        return SdkCookieStorage(storage, fqdn) to storage
    }

    @Test
    fun get_returnsEmpty_whenNoCookieStored() = runTest {
        val (storage, _) = createStorage()

        assertTrue(storage.get(url).isEmpty())
    }

    @Test
    fun addCookie_storesZetaRoute_andGetReturnsIt() = runTest {
        val (storage, _) = createStorage()
        storage.addCookie(url, Cookie(name = ZETA_ROUTE_COOKIE, value = "abc123"))
        val cookies = storage.get(url)

        assertEquals(1, cookies.size)
        assertEquals(ZETA_ROUTE_COOKIE, cookies[0].name)
        assertEquals("abc123", cookies[0].value)
    }

    @Test
    fun addCookie_overwritesExistingZetaRoute() = runTest {
        val (storage, _) = createStorage()
        storage.addCookie(url, Cookie(name = ZETA_ROUTE_COOKIE, value = "first"))
        storage.addCookie(url, Cookie(name = ZETA_ROUTE_COOKIE, value = "second"))
        val cookies = storage.get(url)

        assertEquals(1, cookies.size)
        assertEquals("second", cookies[0].value)
    }

    @Test
    fun clearCookie_removesStoredValue() = runTest {
        val (storage, _) = createStorage()
        storage.addCookie(url, Cookie(name = ZETA_ROUTE_COOKIE, value = "abc123"))
        storage.clearCookie()

        assertTrue(storage.get(url).isEmpty())
    }

    @Test
    fun differentFqdns_useDifferentStorageKeys() = runTest {
        val underlyingStorage = InMemoryStorage()
        val storage1 = SdkCookieStorage(underlyingStorage, "host1.example.com")
        val storage2 = SdkCookieStorage(underlyingStorage, "host2.example.com")
        storage1.addCookie(url, Cookie(name = ZETA_ROUTE_COOKIE, value = "value1"))

        assertTrue(storage2.get(url).isEmpty())
    }

    @Test
    fun sameFqdn_sharesStorageKey() = runTest {
        val underlyingStorage = InMemoryStorage()
        val storage1 = SdkCookieStorage(underlyingStorage, "example.com")
        val storage2 = SdkCookieStorage(underlyingStorage, "example.com")
        storage1.addCookie(url, Cookie(name = ZETA_ROUTE_COOKIE, value = "shared"))

        assertEquals("shared", storage2.get(url)[0].value)
    }

    @Test
    fun addCookie_zetaRoute_isRoutedToSdkStorage() = runTest {
        val (composite, sdkStorage) = createComposite()
        composite.addCookie(url, Cookie(name = ZETA_ROUTE_COOKIE, value = "abc123"))
        val cookies = sdkStorage.get(url)

        assertEquals(1, cookies.size)
        assertEquals("abc123", cookies[0].value)
    }

    @Test
    fun addCookie_nonZetaRoute_isRoutedToDefaultStorage() = runTest {
        val (composite, sdkStorage) = createComposite()
        composite.addCookie(url, Cookie(name = "session", value = "xyz"))

        assertTrue(sdkStorage.get(url).isEmpty())
        assertTrue(composite.get(url).any { it.name == "session" && it.value == "xyz" })
    }

    @Test
    fun get_returnsCookiesFromBothStorages() = runTest {
        val (composite, _) = createComposite()
        composite.addCookie(url, Cookie(name = ZETA_ROUTE_COOKIE, value = "route123"))
        composite.addCookie(url, Cookie(name = "session", value = "sess456"))
        val cookies = composite.get(url)

        assertTrue(cookies.any { it.name == ZETA_ROUTE_COOKIE && it.value == "route123" })
        assertTrue(cookies.any { it.name == "session" && it.value == "sess456" })
    }

    @Test
    fun addCookie_zetaRoute_notStoredInDefaultStorage() = runTest {
        val (composite, _) = createComposite()
        composite.addCookie(url, Cookie(name = ZETA_ROUTE_COOKIE, value = "abc123"))
        val cookies = composite.get(url)

        assertEquals(1, cookies.filter { it.name == ZETA_ROUTE_COOKIE }.size)
    }

    class SerializableCookieTest {

        @Test
        fun toCookie_mapsAllFields() {
            val serializable = SerializableCookie(
                name = "zeta_route",
                value = "abc123",
                domain = "example.com",
                path = "/",
                maxAge = 3600,
                secure = true,
                httpOnly = true,
            )

            val cookie = serializable.toCookie()

            assertEquals("zeta_route", cookie.name)
            assertEquals("abc123", cookie.value)
            assertEquals("example.com", cookie.domain)
            assertEquals("/", cookie.path)
            assertEquals(3600, cookie.maxAge)
            assertTrue(cookie.secure)
            assertTrue(cookie.httpOnly)
        }

        @Test
        fun toCookie_mapsNullableFieldsAsNull() {
            val serializable = SerializableCookie(name = "zeta_route", value = "abc123")
            val cookie = serializable.toCookie()

            assertNull(cookie.domain)
            assertNull(cookie.path)
            assertNull(cookie.maxAge)
            assertFalse(cookie.secure)
            assertFalse(cookie.httpOnly)
        }

        @Test
        fun from_mapsAllFields() {
            val cookie = Cookie(
                name = "zeta_route",
                value = "abc123",
                domain = "example.com",
                path = "/",
                maxAge = 3600,
                secure = true,
                httpOnly = true,
            )
            val serializable = SerializableCookie.from(cookie)

            assertEquals("zeta_route", serializable.name)
            assertEquals("abc123", serializable.value)
            assertEquals("example.com", serializable.domain)
            assertEquals("/", serializable.path)
            assertEquals(3600, serializable.maxAge)
            assertTrue(serializable.secure)
            assertTrue(serializable.httpOnly)
        }

        @Test
        fun from_mapsNullableFieldsAsNull() {
            val cookie = Cookie(name = "zeta_route", value = "abc123")
            val serializable = SerializableCookie.from(cookie)

            assertNull(serializable.domain)
            assertNull(serializable.path)
            assertNull(serializable.maxAge)
            assertFalse(serializable.secure)
            assertFalse(serializable.httpOnly)
        }

        @Test
        fun fromAndToCookie_isRoundtrip() {
            val original = Cookie(
                name = "session",
                value = "xyz789",
                domain = "test.com",
                path = "/api",
                maxAge = 600,
                secure = false,
                httpOnly = true,
            )
            val roundTrip = SerializableCookie.from(original).toCookie()

            assertEquals(original.name, roundTrip.name)
            assertEquals(original.value, roundTrip.value)
            assertEquals(original.domain, roundTrip.domain)
            assertEquals(original.path, roundTrip.path)
            assertEquals(original.maxAge, roundTrip.maxAge)
            assertEquals(original.secure, roundTrip.secure)
            assertEquals(original.httpOnly, roundTrip.httpOnly)
        }
    }
}
