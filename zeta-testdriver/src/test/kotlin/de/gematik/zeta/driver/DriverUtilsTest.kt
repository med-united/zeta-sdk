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

package de.gematik.zeta.driver

import de.gematik.zeta.driver.model.SdkInstanceConfig
import de.gematik.zeta.sdk.attestation.model.PlatformProductId
import de.gematik.zeta.sdk.storage.InMemoryStorage
import io.ktor.http.HttpHeaders
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

class DriverUtilsTest {

    @Test
    fun newSdk_usesCorrectPlatformProductId() {
        // Arrange
        val config = SdkInstanceConfig(
            fachdienstUrl = "https://example.com",
            smbKeystoreB64 = "dGVzdA==",
            smbKeystoreAlias = "alias",
            smbKeystorePassword = "password",
            smbKeystoreFile = "",
            smcbBaseUrl = "",
            smcbCardHandle = "",
            smcbClientSystemId = "",
            smcbMandantId = "",
            smcbUserId = "",
            smcbWorkspaceId = "",
            aslProdEnv = false,
            poppToken = "",
            requiredOid = "",
        )

        val client = newSdk(InMemoryStorage(), config)
        val buildConfig = client::class.java
            .getDeclaredField("cfg")
            .apply { isAccessible = true }
            .get(client)

        val platformProductId = buildConfig::class.java
            .getDeclaredField("platformProductId")
            .apply { isAccessible = true }
            .get(buildConfig) as PlatformProductId

        // Assert
        val osName = System.getProperty("os.name").lowercase()
        when {
            osName.contains("linux") -> {
                assertIs<PlatformProductId.LinuxProductId>(platformProductId)
                assertEquals("linux", platformProductId.platform)
            }
            osName.contains("mac") || osName.contains("darwin") -> {
                assertIs<PlatformProductId.AppleProductId>(platformProductId)
                assertEquals("apple", platformProductId.platform)
            }
            osName.contains("win") -> {
                assertIs<PlatformProductId.WindowsProductId>(platformProductId)
                assertEquals("windows", platformProductId.platform)
            }
            else -> fail("Unsupported platform: $osName")
        }
    }

    @Test
    fun newSdk_usesSmbTokenProvider_whenSmbKeystoreB64Provided() {
        // Arrange
        val config = SdkInstanceConfig(
            fachdienstUrl = "https://example.com",
            smbKeystoreB64 = "dGVzdA==",
            smbKeystoreAlias = "alias",
            smbKeystorePassword = "password",
            smbKeystoreFile = "",
            smcbBaseUrl = "",
            smcbCardHandle = "",
            smcbClientSystemId = "",
            smcbMandantId = "",
            smcbUserId = "",
            smcbWorkspaceId = "",
            aslProdEnv = false,
            poppToken = "",
            requiredOid = "",
        )

        // Act
        val client = newSdk(InMemoryStorage(), config)

        // Assert
        assertNotNull(client)
    }

    @Test
    fun newSdk_usesSmbTokenProvider_whenSmbKeystoreFileProvided() {
        // Arrange
        val config = SdkInstanceConfig(
            fachdienstUrl = "https://example.com",
            smbKeystoreB64 = "",
            smbKeystoreAlias = "alias",
            smbKeystorePassword = "password",
            smbKeystoreFile = "/path/to/keystore.p12",
            smcbBaseUrl = "",
            smcbCardHandle = "",
            smcbClientSystemId = "",
            smcbMandantId = "",
            smcbUserId = "",
            smcbWorkspaceId = "",
            aslProdEnv = false,
            poppToken = "",
            requiredOid = "",
        )

        // Act
        val client = newSdk(InMemoryStorage(), config)

        // Assert
        assertNotNull(client)
    }

    @Test
    fun newSdk_usesSmcbTokenProvider_whenSmcbBaseUrlProvided() {
        // Arrange
        val config = SdkInstanceConfig(
            fachdienstUrl = "https://example.com",
            smbKeystoreB64 = "",
            smbKeystoreAlias = "",
            smbKeystorePassword = "",
            smbKeystoreFile = "",
            smcbBaseUrl = "https://smcb.example.com",
            smcbCardHandle = "handle",
            smcbClientSystemId = "client-id",
            smcbMandantId = "mandant-id",
            smcbUserId = "user-id",
            smcbWorkspaceId = "workspace-id",
            aslProdEnv = false,
            poppToken = "",
            requiredOid = "",
        )

        // Act
        val client = newSdk(InMemoryStorage(), config)

        // Assert
        assertNotNull(client)
    }

    @Test
    fun newSdk_throwsError_whenNoAuthConfigProvided() {
        // Arrange
        val config = SdkInstanceConfig(
            fachdienstUrl = "https://example.com",
            smbKeystoreB64 = "",
            smbKeystoreAlias = "",
            smbKeystorePassword = "",
            smbKeystoreFile = "",
            smcbBaseUrl = "",
            smcbCardHandle = "",
            smcbClientSystemId = "",
            smcbMandantId = "",
            smcbUserId = "",
            smcbWorkspaceId = "",
            aslProdEnv = false,
            poppToken = "",
            requiredOid = "",
        )

        // Act & Assert
        assertFailsWith<IllegalStateException> {
            newSdk(InMemoryStorage(), config)
        }
    }

    @Test
    fun newSdk_throwsError_whenFachdienstUrlIsNull() {
        // Arrange
        val config = SdkInstanceConfig(
            fachdienstUrl = null,
            smbKeystoreB64 = "dGVzdA==",
            smbKeystoreAlias = "alias",
            smbKeystorePassword = "password",
            smbKeystoreFile = "",
            smcbBaseUrl = "",
            smcbCardHandle = "",
            smcbClientSystemId = "",
            smcbMandantId = "",
            smcbUserId = "",
            smcbWorkspaceId = "",
            aslProdEnv = false,
            poppToken = "",
            requiredOid = "",
        )

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            newSdk(InMemoryStorage(), config)
        }
    }

    @Test
    fun shouldForwardHeader_returnsTrue_whenHeaderIsAllowed() {
        // Assert
        assertTrue(shouldForwardHeader("Authorization"))
        assertTrue(shouldForwardHeader("X-Custom-Header"))
        assertTrue(shouldForwardHeader("Accept"))
    }

    @Test
    fun shouldForwardHeader_returnsFalse_whenHeaderIsContentType() {
        // Assert
        assertFalse(shouldForwardHeader(HttpHeaders.ContentType))
    }

    @Test
    fun shouldForwardHeader_returnsFalse_whenHeaderIsContentLength() {
        // Assert
        assertFalse(shouldForwardHeader(HttpHeaders.ContentLength))
    }

    @Test
    fun shouldForwardHeader_returnsFalse_whenHeaderIsTransferEncoding() {
        // Assert
        assertFalse(shouldForwardHeader(HttpHeaders.TransferEncoding))
    }

    @Test
    fun shouldForwardHeader_returnsFalse_whenHeaderIsConnection() {
        // Assert
        assertFalse(shouldForwardHeader(HttpHeaders.Connection))
    }

    @Test
    fun shouldForwardHeader_isCaseInsensitive() {
        // Assert
        assertFalse(shouldForwardHeader("content-type"))
        assertFalse(shouldForwardHeader("CONTENT-TYPE"))
        assertFalse(shouldForwardHeader("Content-Type"))
    }
}
