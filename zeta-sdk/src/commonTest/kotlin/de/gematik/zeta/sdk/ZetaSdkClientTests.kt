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

package de.gematik.zeta.sdk

import de.gematik.zeta.sdk.attestation.model.PlatformProductId
import de.gematik.zeta.sdk.authentication.AuthConfig
import de.gematik.zeta.sdk.authentication.smb.SmbTokenProvider
import de.gematik.zeta.sdk.network.http.client.ZetaHttpClient
import de.gematik.zeta.sdk.network.http.client.ZetaHttpClientBuilder
import de.gematik.zeta.sdk.storage.SdkStorage
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ZetaSdkClientTests {
    @Test
    fun storageConfig_createsWithDefaults_noParameters() {
        // Arrange & Act
        val config = StorageConfig()

        // Assert
        assertNull(config.provider)
        assertEquals("7aae7xXr8rnzVqjpYbosS0CFMrlprkD7jbVotm0fd+w=", config.aesB64Key)
    }

    @Test
    fun storageConfig_createsWithProvider_whenProvided() {
        // Arrange
        val mockProvider = object : SdkStorage {
            override suspend fun put(key: String, value: String) {
                TODO("Not yet implemented")
            }

            override suspend fun get(key: String): String? {
                TODO("Not yet implemented")
            }

            override suspend fun remove(key: String) {
                TODO("Not yet implemented")
            }

            override suspend fun clear() {}
        }

        // Act
        val config = StorageConfig(provider = mockProvider)

        // Assert
        assertEquals(mockProvider, config.provider)
    }

    @Test
    fun storageConfig_createsWithCustomKey_whenProvided() {
        // Arrange
        val customKey = "customBase64Key=="

        // Act
        val config = StorageConfig(aesB64Key = customKey)

        // Assert
        assertEquals(customKey, config.aesB64Key)
    }

    @Test
    fun storageConfig_equality_sameValues() {
        // Arrange
        val config1 = StorageConfig(aesB64Key = "key1")
        val config2 = StorageConfig(aesB64Key = "key1")

        // Act & Assert
        assertEquals(config1, config2)
    }

    @Test
    fun storageConfig_inequality_differentValues() {
        // Arrange
        val config1 = StorageConfig(aesB64Key = "key1")
        val config2 = StorageConfig(aesB64Key = "key2")

        // Act & Assert
        assertNotEquals(config1, config2)
    }

    @Test
    fun storageConfig_copy_createsNewInstance() {
        // Arrange
        val original = StorageConfig(aesB64Key = "originalKey")

        // Act
        val copy = original.copy(aesB64Key = "newKey")

        // Assert
        assertEquals("originalKey", original.aesB64Key)
        assertEquals("newKey", copy.aesB64Key)
    }

    @Test
    fun storageConfig_componentN_destructuring() {
        // Arrange
        val mockProvider = object : SdkStorage {
            override suspend fun put(key: String, value: String) {
                TODO("Not yet implemented")
            }

            override suspend fun get(key: String): String? {
                TODO("Not yet implemented")
            }

            override suspend fun remove(key: String) {
                TODO("Not yet implemented")
            }

            override suspend fun clear() {}
        }
        val config = StorageConfig(provider = mockProvider, aesB64Key = "testKey")

        // Act
        val (provider, key) = config

        // Assert
        assertEquals(mockProvider, provider)
        assertEquals("testKey", key)
    }

    @Test
    fun regInfo_createsWithClientName_whenProvided() {
        // Arrange & Act
        val regInfo = RegInfo(clientName = "TestClient")

        // Assert
        assertEquals("TestClient", regInfo.clientName)
    }

    @Test
    fun regInfo_equality_sameClientName() {
        // Arrange
        val info1 = RegInfo(clientName = "Client1")
        val info2 = RegInfo(clientName = "Client1")

        // Act & Assert
        assertEquals(info1, info2)
    }

    @Test
    fun regInfo_inequality_differentClientName() {
        // Arrange
        val info1 = RegInfo(clientName = "Client1")
        val info2 = RegInfo(clientName = "Client2")

        // Act & Assert
        assertNotEquals(info1, info2)
    }

    @Test
    fun regInfo_copy_createsNewInstance() {
        // Arrange
        val original = RegInfo(clientName = "Original")

        // Act
        val copy = original.copy(clientName = "Copy")

        // Assert
        assertEquals("Original", original.clientName)
        assertEquals("Copy", copy.clientName)
    }

    @Test
    fun regInfo_component1_destructuring() {
        // Arrange
        val regInfo = RegInfo(clientName = "TestClient")

        // Act
        val (clientName) = regInfo

        // Assert
        assertEquals("TestClient", clientName)
    }

    @Test
    fun authInfo_createsWithDefaults_noParameters() {
        // Arrange & Act
        val authInfo = AuthInfo()

        // Assert
        assertNull(authInfo.otp)
    }

    @Test
    fun authInfo_createsWithOtp_whenProvided() {
        // Arrange & Act
        val authInfo = AuthInfo(otp = "123456")

        // Assert
        assertEquals("123456", authInfo.otp)
    }

    @Test
    fun authInfo_equality_sameOtp() {
        // Arrange
        val info1 = AuthInfo(otp = "123456")
        val info2 = AuthInfo(otp = "123456")

        // Act & Assert
        assertEquals(info1, info2)
    }

    @Test
    fun authInfo_inequality_differentOtp() {
        // Arrange
        val info1 = AuthInfo(otp = "123456")
        val info2 = AuthInfo(otp = "654321")

        // Act & Assert
        assertNotEquals(info1, info2)
    }

    @Test
    fun authInfo_equality_bothNull() {
        // Arrange
        val info1 = AuthInfo(otp = null)
        val info2 = AuthInfo(otp = null)

        // Act & Assert
        assertEquals(info1, info2)
    }

    @Test
    fun authInfo_copy_createsNewInstance() {
        // Arrange
        val original = AuthInfo(otp = "original")

        // Act
        val copy = original.copy(otp = "copy")

        // Assert
        assertEquals("original", original.otp)
        assertEquals("copy", copy.otp)
    }

    @Test
    fun authInfo_component1_destructuring() {
        // Arrange
        val authInfo = AuthInfo(otp = "123456")

        // Act
        val (otp) = authInfo

        // Assert
        assertEquals("123456", otp)
    }

    @Test
    fun buildConfig_createsWithAllParameters_whenProvided() {
        // Arrange
        val storageConfig = StorageConfig()
        val authConfig = AuthConfig(listOf("scopes"), 300, true, SmbTokenProvider(SmbTokenProvider.Credentials("", "", "")))
        val platformProductId = PlatformProductId.LinuxProductId("", "", "", "")

        // Act
        val buildConfig = BuildConfig(
            productId = "product-123",
            productVersion = "1.0.0",
            clientName = "TestClient",
            storageConfig = storageConfig,
            tpmConfig = object : TpmConfig {},
            authConfig = authConfig,
            platformProductId = PlatformProductId.LinuxProductId("", "", "", ""),
        )

        // Assert
        assertEquals("product-123", buildConfig.productId)
        assertEquals("1.0.0", buildConfig.productVersion)
        assertEquals("TestClient", buildConfig.clientName)
        assertEquals(storageConfig, buildConfig.storageConfig)
        assertEquals(authConfig, buildConfig.authConfig)
        assertEquals(platformProductId, buildConfig.platformProductId)
        assertNull(buildConfig.httpClientBuilder)
        assertNull(buildConfig.registrationCallback)
        assertNull(buildConfig.authenticationCallback)
    }

    @Test
    fun buildConfig_createsWithOptionalParameters_whenProvided() {
        // Arrange
        val storageConfig = StorageConfig()
        val tpmConfig = object : TpmConfig {}
        val authConfig = AuthConfig(listOf("scopes"), 300, true, SmbTokenProvider(SmbTokenProvider.Credentials("", "", "")))
        val platformProductId = PlatformProductId.LinuxProductId("", "", "", "")
        val httpClientBuilder = ZetaHttpClientBuilder()
        val regCallback = RegistrationCallback { RegInfo("test") }
        val authCallback = AuthenticationCallback { AuthInfo("123") }

        // Act
        val buildConfig = BuildConfig(
            productId = "product-123",
            productVersion = "1.0.0",
            clientName = "TestClient",
            storageConfig = storageConfig,
            tpmConfig = tpmConfig,
            authConfig = authConfig,
            platformProductId = platformProductId,
            httpClientBuilder = httpClientBuilder,
            registrationCallback = regCallback,
            authenticationCallback = authCallback,
        )

        // Assert
        assertEquals(httpClientBuilder, buildConfig.httpClientBuilder)
        assertEquals(regCallback, buildConfig.registrationCallback)
        assertEquals(authCallback, buildConfig.authenticationCallback)
    }

    @Test
    fun buildConfig_copy_createsNewInstance() {
        // Arrange
        val storageConfig = StorageConfig()
        val tpmConfig = object : TpmConfig {}
        val authConfig = AuthConfig(listOf("scopes"), 300, true, SmbTokenProvider(SmbTokenProvider.Credentials("", "", "")))
        val platformProductId = PlatformProductId.LinuxProductId("", "", "", "")
        val original = BuildConfig(
            productId = "product-123",
            productVersion = "1.0.0",
            clientName = "Original",
            storageConfig = storageConfig,
            tpmConfig = tpmConfig,
            authConfig = authConfig,
            platformProductId = platformProductId,
        )

        // Act
        val copy = original.copy(clientName = "Copy")

        // Assert
        assertEquals("Original", original.clientName)
        assertEquals("Copy", copy.clientName)
    }

    @Test
    fun buildConfig_equality_sameValues() {
        // Arrange
        val storageConfig = StorageConfig()
        val tpmConfig = object : TpmConfig {}
        val authConfig = AuthConfig(listOf("scopes"), 300, true, SmbTokenProvider(SmbTokenProvider.Credentials("", "", "")))
        val platformProductId = PlatformProductId.LinuxProductId("", "", "", "")

        val config1 = BuildConfig(
            productId = "product-123",
            productVersion = "1.0.0",
            clientName = "Client",
            storageConfig = storageConfig,
            tpmConfig = tpmConfig,
            authConfig = authConfig,
            platformProductId = platformProductId,
        )

        val config2 = BuildConfig(
            productId = "product-123",
            productVersion = "1.0.0",
            clientName = "Client",
            storageConfig = storageConfig,
            tpmConfig = tpmConfig,
            authConfig = authConfig,
            platformProductId = platformProductId,
        )

        // Act & Assert
        assertEquals(config1, config2)
    }

    @Test
    fun registrationCallback_invokesLambda_whenCalled() = runTest {
        // Arrange
        var invoked = false
        val callback = RegistrationCallback {
            invoked = true
            RegInfo("TestClient")
        }

        // Act
        val result = callback.registrationCb()

        // Assert
        assertTrue(invoked)
        assertEquals("TestClient", result.clientName)
    }

    @Test
    fun registrationCallback_returnsCorrectValue_whenInvoked() = runTest {
        // Arrange
        val expectedClientName = "ExpectedClient"
        val callback = RegistrationCallback {
            RegInfo(expectedClientName)
        }

        // Act
        val result = callback.registrationCb()

        // Assert
        assertEquals(expectedClientName, result.clientName)
    }

    @Test
    fun authenticationCallback_invokesLambda_whenCalled() = runTest {
        // Arrange
        var invoked = false
        val callback = AuthenticationCallback {
            invoked = true
            AuthInfo("123456")
        }

        // Act
        val result = callback.authenticationCb()

        // Assert
        assertTrue(invoked)
        assertEquals("123456", result.otp)
    }

    @Test
    fun authenticationCallback_returnsCorrectValue_whenInvoked() = runTest {
        // Arrange
        val expectedOtp = "654321"
        val callback = AuthenticationCallback {
            AuthInfo(expectedOtp)
        }

        // Act
        val result = callback.authenticationCb()

        // Assert
        assertEquals(expectedOtp, result.otp)
    }

    @Test
    fun authenticationCallback_canReturnNull_whenOtpNotProvided() = runTest {
        // Arrange
        val callback = AuthenticationCallback {
            AuthInfo(otp = null)
        }

        // Act
        val result = callback.authenticationCb()

        // Assert
        assertNull(result.otp)
    }

    @Test
    fun zetaSdkClient_canBeImplemented_mockImplementation() = runTest {
        // Arrange
        val mockClient = object : ZetaSdkClient {
            override suspend fun discover(): Result<Unit> = Result.success(Unit)
            override suspend fun register(): Result<Unit> = Result.success(Unit)
            override suspend fun authenticate(): Result<Unit> = Result.success(Unit)
            override fun httpClient(builder: ZetaHttpClientBuilder.() -> Unit): ZetaHttpClient {
                return ZetaHttpClientBuilder().apply(builder).build()
            }
            override suspend fun <R> ws(
                targetUrl: String,
                builder: ZetaHttpClientBuilder.() -> Unit,
                customHeaders: Map<String, String>?,
                block: suspend DefaultClientWebSocketSession.() -> R,
            ) {}
            override suspend fun close(): Result<Unit> = Result.success(Unit)
        }

        // Act
        val discoverResult = mockClient.discover()
        val registerResult = mockClient.register()
        val authenticateResult = mockClient.authenticate()
        val closeResult = mockClient.close()

        // Assert
        assertTrue(discoverResult.isSuccess)
        assertTrue(registerResult.isSuccess)
        assertTrue(authenticateResult.isSuccess)
        assertTrue(closeResult.isSuccess)
    }

    @Test
    fun zetaSdkClient_httpClient_canBeInvoked() {
        // Arrange
        val mockClient = object : ZetaSdkClient {
            override suspend fun discover(): Result<Unit> = Result.success(Unit)
            override suspend fun register(): Result<Unit> = Result.success(Unit)
            override suspend fun authenticate(): Result<Unit> = Result.success(Unit)
            override fun httpClient(builder: ZetaHttpClientBuilder.() -> Unit): ZetaHttpClient {
                return ZetaHttpClientBuilder().apply(builder).build()
            }
            override suspend fun <R> ws(
                targetUrl: String,
                builder: ZetaHttpClientBuilder.() -> Unit,
                customHeaders: Map<String, String>?,
                block: suspend DefaultClientWebSocketSession.() -> R,
            ) {}
            override suspend fun close(): Result<Unit> = Result.success(Unit)
        }

        // Act
        val httpClient = mockClient.httpClient {
            timeouts(connectMs = 5000)
        }

        // Assert
        assertNotNull(httpClient)
        httpClient.close()
    }

    @Test
    fun tpmConfig_canBeImplemented_emptyInterface() {
        // Arrange & Act
        val tpmConfig = object : TpmConfig {}

        // Assert
        assertNotNull(tpmConfig)
    }

    @Test
    fun tpmConfig_canBeUsedInBuildConfig_asParameter() {
        // Arrange
        val tpmConfig = object : TpmConfig {}
        val storageConfig = StorageConfig()
        val authConfig = AuthConfig(listOf("scopes"), 300, true, SmbTokenProvider(SmbTokenProvider.Credentials("", "", "")))
        val platformProductId = PlatformProductId.LinuxProductId("", "", "", "")

        // Act
        val buildConfig = BuildConfig(
            productId = "test",
            productVersion = "1.0",
            clientName = "test",
            storageConfig = storageConfig,
            tpmConfig = tpmConfig,
            authConfig = authConfig,
            platformProductId = platformProductId,
        )

        // Assert
        assertEquals(tpmConfig, buildConfig.tpmConfig)
    }
}
