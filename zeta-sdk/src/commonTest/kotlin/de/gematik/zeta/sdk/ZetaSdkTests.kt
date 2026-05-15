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

import de.gematik.zeta.sdk.ZetaSdk.forget
import de.gematik.zeta.sdk.attestation.model.PlatformProductId
import de.gematik.zeta.sdk.authentication.AuthConfig
import de.gematik.zeta.sdk.authentication.AuthenticationStorageImpl
import de.gematik.zeta.sdk.authentication.smb.SmbTokenProvider
import de.gematik.zeta.sdk.network.http.client.ZetaHttpClientBuilder
import de.gematik.zeta.sdk.storage.InMemoryStorage
import de.gematik.zeta.sdk.storage.SdkStorage
import de.gematik.zeta.sdk.storage.StorageConfig
import io.ktor.client.plugins.logging.LogLevel
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

class ZetaSdkTest {

    private val requiredRoleOid = "1.2.276.0.76.4.261"
    private val aesTestKey: String = "7aae7xXr8rnzVqjpYbosS0CFMrlprkD7jbVotm0fd"

    @Test
    fun build_createsClient_withMinimalConfig() {
        // Arrange
        val config = createTestBuildConfig()

        // Act
        val client = ZetaSdk.build("https://api.example.com", config)

        // Assert
        assertNotNull(client)
    }

    @Test
    fun build_createsClient_withCustomHttpClientBuilder() {
        // Arrange
        val customBuilder = ZetaHttpClientBuilder().logging(LogLevel.NONE)
        val config = createTestBuildConfig(httpClientBuilder = customBuilder)

        // Act
        val client = ZetaSdk.build("https://api.example.com", config)

        // Assert
        assertNotNull(client)
    }

    @Test
    fun build_createsClient_withCustomStorage() {
        // Arrange
        val mockStorage = createMockStorage()
        val config = createTestBuildConfig(
            storageConfig = StorageConfig.Custom(provider = mockStorage),
        )

        // Act
        val client = ZetaSdk.build("https://api.example.com", config)

        // Assert
        assertNotNull(client)
    }

    @Test
    fun build_createsClient_withCallbacks() {
        // Arrange
        val regCallback = RegistrationCallback { RegInfo("TestClient") }
        val authCallback = AuthenticationCallback { AuthInfo("123456") }
        val config = createTestBuildConfig(
            registrationCallback = regCallback,
            authenticationCallback = authCallback,
        )

        // Act
        val client = ZetaSdk.build("https://api.example.com", config)

        // Assert
        assertNotNull(client)
    }

    @Test
    fun forget_returnsSuccess_whenNoErrors() = runTest {
        // Arrange
        val config = createTestBuildConfig()
        val client = ZetaSdk.build("https://api.example.com", config)

        // Act
        val result = client.forget()

        // Assert
        assertTrue(result.isSuccess)
    }

    @Test
    fun discover_returnsFailure_whenConfigurationFails() = runTest {
        // Arrange
        val config = createTestBuildConfig()
        val client = ZetaSdk.build("https://invalid-url", config)

        // Act
        val result = client.discover()

        // Assert
        assertTrue(result.isFailure)
    }

    @Test
    fun register_returnsSuccess_whenRegistrationCompletes() = runTest {
        // Arrange
        val config = createTestBuildConfig()
        val client = ZetaSdk.build("https://api.example.com", config)

        // Act
        val result = client.register()

        // Assert
        assertNotNull(result)
    }

    @Test
    fun authenticate_returnsResult_whenCalled() = runTest {
        // Arrange
        val config = createTestBuildConfig()
        val client = ZetaSdk.build("https://api.example.com", config)

        // Act
        val result = client.authenticate()

        // Assert
        assertNotNull(result)
    }

    @Test
    fun httpClient_createsClient_withDefaultBuilder() {
        // Arrange
        val config = createTestBuildConfig()
        val client = ZetaSdk.build("https://api.example.com", config)

        // Act
        val httpClient = client.httpClient()

        // Assert
        assertNotNull(httpClient)
        httpClient.close()
    }

    @Test
    fun httpClient_createsClient_withCustomConfiguration() {
        // Arrange
        val config = createTestBuildConfig()
        val client = ZetaSdk.build("https://api.example.com", config)

        // Act
        val httpClient = client.httpClient {
            timeouts(connectMs = 5000, requestMs = 10000)
            retry(maxRetries = 3)
        }

        // Assert
        assertNotNull(httpClient)
        httpClient.close()
    }

    @Test
    fun httpClient_installsPlugins_zetaAndAslDecryption() {
        // Arrange
        val config = createTestBuildConfig()
        val client = ZetaSdk.build("https://api.example.com", config)

        // Act
        val httpClient = client.httpClient()

        // Assert
        assertNotNull(httpClient)
        httpClient.close()
    }

    @Test
    fun httpClient_canBeCalledMultipleTimes_createsNewInstances() {
        // Arrange
        val config = createTestBuildConfig()
        val client = ZetaSdk.build("https://api.example.com", config)

        // Act
        val httpClient1 = client.httpClient()
        val httpClient2 = client.httpClient()

        // Assert
        assertNotNull(httpClient1)
        assertNotNull(httpClient2)
        httpClient1.close()
        httpClient2.close()
    }

    @Test
    fun ws_throwsException_whenDiscoverFails() = runTest {
        // Arrange
        val config = createTestBuildConfig()
        val client = ZetaSdk.build("https://invalid-url", config)

        // Act & Assert
        assertFailsWith<Exception> {
            client.ws("wss://api.example.com/ws") {}
        }
    }

    @Test
    fun logout_returnsSuccess() = runTest {
        // Arrange
        val config = createTestBuildConfig()
        val client = ZetaSdk.build("https://api.example.com", config)

        // Act
        val result = client.logout()

        // Assert
        assertTrue(result.isSuccess)
    }

    @Test
    fun close_clearsAuthenticationStorage() = runTest {
        // Arrange
        val storage = InMemoryStorage()
        val client = ZetaSdk.build(
            "https://api.example.com",
            createTestBuildConfig(
                storageConfig = StorageConfig.Custom(provider = storage),
            ),
        )

        AuthenticationStorageImpl(storage).saveAccessTokens(
            fqdn = "auth.example.com",
            accessToken = "access-token",
            refreshToken = "refresh-token",
            expiresAt = Clock.System.now().epochSeconds + 3600,
        )
        assertNotNull(AuthenticationStorageImpl(storage).getAccessToken("auth.example.com"))

        // Act
        val result = client.logout()

        // Assert
        assertTrue(result.isSuccess)
        assertNull(AuthenticationStorageImpl(storage).getAccessToken("auth.example.com"))
        assertNull(AuthenticationStorageImpl(storage).getRefreshToken("auth.example.com"))
    }

    @Test
    fun fullFlow_buildDiscoverRegisterAuthenticate_executesInOrder() = runTest {
        // Arrange
        val config = createTestBuildConfig()

        // Act
        val client = ZetaSdk.build("https://api.example.com", config)
        val discoverResult = client.discover()
        val registerResult = client.register()
        val authenticateResult = client.authenticate()

        // Assert
        assertNotNull(client)
        assertNotNull(discoverResult)
        assertNotNull(registerResult)
        assertNotNull(authenticateResult)
    }

    @Test
    fun multipleBuildCalls_createsDifferentClients_independent() {
        // Arrange
        val config1 = createTestBuildConfig()
        val config2 = createTestBuildConfig()

        // Act
        val client1 = ZetaSdk.build("https://api1.example.com", config1)
        val client2 = ZetaSdk.build("https://api2.example.com", config2)

        // Assert
        assertNotNull(client1)
        assertNotNull(client2)
    }

    @Test
    fun build_withAllCallbacks_storesThemCorrectly() {
        // Arrange
        val regCallback = RegistrationCallback {
            RegInfo("CallbackClient")
        }

        val authCallback = AuthenticationCallback {
            AuthInfo("999999")
        }

        val config = BuildConfig(
            productId = "test",
            productVersion = "1.0",
            clientName = "test",
            storageConfig = StorageConfig.Custom(provider = InMemoryStorage()),
            tpmConfig = object : TpmConfig {},
            authConfig = AuthConfig(listOf("scopes"), 300, false, SmbTokenProvider(SmbTokenProvider.Credentials("", "", "")), requiredRoleOid = requiredRoleOid),
            platformProductId = PlatformProductId.LinuxProductId("", "", "", ""),
            registrationCallback = regCallback,
            authenticationCallback = authCallback,
        )

        // Act
        val client = ZetaSdk.build("https://api.example.com", config)

        // Assert
        assertNotNull(client)
    }

    @Test
    fun storageConfig_defaultConstructor_usesDefaultValues() {
        // Act
        val config = StorageConfig.Default(aesB64Key = aesTestKey)

        // Assert
        assertNotNull(config.aesB64Key)
        assertTrue(config.aesB64Key.isNotEmpty())
    }

    @Test
    fun storageConfig_copy_withNoChanges_createsEqualObject() {
        // Arrange
        val original = StorageConfig.Default(aesB64Key = "key1")

        // Act
        val copy = original.copy()

        // Assert
        assertEquals(original, copy)
        assertNotSame(original, copy)
    }

    @Test
    fun storageConfigDefault_toString_includesClassName() {
        // Arrange
        val config = StorageConfig.Default(aesB64Key = "7aae7xXr8rnzVqjpYbosS0CFMrlprkD7jbVotm0fd+w=")

        // Act
        val result = config.toString()

        // Assert
        assertTrue(result.contains("Default"))
    }

    @Test
    fun storageConfigCustom_toString_includesClassName() {
        // Arrange
        val config = StorageConfig.Custom(InMemoryStorage())

        // Act
        val result = config.toString()

        // Assert
        assertTrue(result.contains("Custom"))
    }

    @Test
    fun storageConfig_hashCode_consistentWithEquals() {
        // Arrange
        val config1 = StorageConfig.Default(aesB64Key = "sameKey")
        val config2 = StorageConfig.Default(aesB64Key = "sameKey")

        // Assert
        assertEquals(config1, config2)
        assertEquals(config1.hashCode(), config2.hashCode())
    }

    @Test
    fun regInfo_equality_reflexive() {
        // Arrange
        val info = RegInfo(clientName = "Client")

        // Assert
        assertEquals(info, info)
    }

    @Test
    fun regInfo_equality_symmetric() {
        // Arrange
        val info1 = RegInfo(clientName = "Client")
        val info2 = RegInfo(clientName = "Client")

        // Assert
        assertEquals(info1, info2)
        assertEquals(info2, info1)
    }

    @Test
    fun regInfo_copy_withNoChanges_createsEqualObject() {
        // Arrange
        val original = RegInfo(clientName = "Original")

        // Act
        val copy = original.copy()

        // Assert
        assertEquals(original, copy)
        assertNotSame(original, copy)
    }

    @Test
    fun regInfo_withSpecialCharacters_createsValidObject() {
        // Arrange & Act
        val regInfo = RegInfo(clientName = "Client-123!@#$%")

        // Assert
        assertEquals("Client-123!@#$%", regInfo.clientName)
    }

    @Test
    fun regInfo_withUnicodeCharacters_createsValidObject() {
        // Arrange & Act
        val regInfo = RegInfo(clientName = "Cliente-ñáéíóú-客户端")

        // Assert
        assertEquals("Cliente-ñáéíóú-客户端", regInfo.clientName)
    }

    @Test
    fun regInfo_hashCode_differentForDifferentValues() {
        // Arrange
        val info1 = RegInfo(clientName = "Client1")
        val info2 = RegInfo(clientName = "Client2")

        // Assert
        assertNotEquals(info1.hashCode(), info2.hashCode())
    }

    @Test
    fun regInfo_toString_validFormat() {
        // Arrange
        val regInfo = RegInfo(clientName = "TestClient")

        // Act
        val result = regInfo.toString()

        // Assert
        assertNotNull(result)
        assertTrue(result.isNotEmpty())
    }

    @Test
    fun authInfo_defaultConstructor_hasNullOtp() {
        // Act
        val authInfo = AuthInfo()

        // Assert
        assertNull(authInfo.otp)
    }

    @Test
    fun authInfo_equality_reflexive() {
        // Arrange
        val info = AuthInfo(otp = "123456")

        // Assert
        assertEquals(info, info)
    }

    @Test
    fun authInfo_equality_symmetric() {
        // Arrange
        val info1 = AuthInfo(otp = "123456")
        val info2 = AuthInfo(otp = "123456")

        // Assert
        assertEquals(info1, info2)
        assertEquals(info2, info1)
    }

    @Test
    fun authInfo_copy_withNoChanges_createsEqualObject() {
        // Arrange
        val original = AuthInfo(otp = "original")

        // Act
        val copy = original.copy()

        // Assert
        assertEquals(original, copy)
        assertNotSame(original, copy)
    }

    @Test
    fun authInfo_copy_nullToValue_updatesCorrectly() {
        // Arrange
        val original = AuthInfo(otp = null)

        // Act
        val copy = original.copy(otp = "123456")

        // Assert
        assertNull(original.otp)
        assertEquals("123456", copy.otp)
    }

    @Test
    fun authInfo_copy_valueToNull_updatesCorrectly() {
        // Arrange
        val original = AuthInfo(otp = "123456")

        // Act
        val copy = original.copy(otp = null)

        // Assert
        assertEquals("123456", original.otp)
        assertNull(copy.otp)
    }

    @Test
    fun authInfo_withLongOtp_createsValidObject() {
        // Arrange
        val longOtp = "1".repeat(100)

        // Act
        val authInfo = AuthInfo(otp = longOtp)

        // Assert
        assertEquals(longOtp, authInfo.otp)
    }

    @Test
    fun authInfo_withAlphanumericOtp_createsValidObject() {
        // Arrange & Act
        val authInfo = AuthInfo(otp = "ABC123xyz")

        // Assert
        assertEquals("ABC123xyz", authInfo.otp)
    }

    @Test
    fun buildConfig_withNullOptionalFields_createsValidObject() {
        // Arrange & Act
        val config = createTestBuildConfig()

        // Assert
        assertNull(config.httpClientBuilder)
        assertNull(config.registrationCallback)
        assertNull(config.authenticationCallback)
    }

    @Test
    fun buildConfig_copy_onlyProductId_keepsOtherFields() {
        // Arrange
        val original = createTestBuildConfig()

        // Act
        val copy = original.copy(productId = "new-product")

        // Assert
        assertEquals("new-product", copy.productId)
        assertEquals(original.productVersion, copy.productVersion)
        assertEquals(original.clientName, copy.clientName)
        assertEquals(original.storageConfig, copy.storageConfig)
    }

    @Test
    fun buildConfig_copy_onlyProductVersion_keepsOtherFields() {
        // Arrange
        val original = createTestBuildConfig()

        // Act
        val copy = original.copy(productVersion = "2.0.0")

        // Assert
        assertEquals("2.0.0", copy.productVersion)
        assertEquals(original.productId, copy.productId)
        assertEquals(original.clientName, copy.clientName)
    }

    @Test
    fun buildConfig_copy_onlyClientName_keepsOtherFields() {
        // Arrange
        val original = createTestBuildConfig()

        // Act
        val copy = original.copy(clientName = "new-client")

        // Assert
        assertEquals("new-client", copy.clientName)
        assertEquals(original.productId, copy.productId)
        assertEquals(original.productVersion, copy.productVersion)
    }

    @Test
    fun buildConfig_copy_onlyStorageConfig_keepsOtherFields() {
        // Arrange
        val original = createTestBuildConfig()
        val newStorage = StorageConfig.Default(aesB64Key = "newKey")

        // Act
        val copy = original.copy(storageConfig = newStorage)

        // Assert
        assertEquals(newStorage, copy.storageConfig)
        assertEquals(original.productId, copy.productId)
    }

    @Test
    fun buildConfig_copy_onlyAuthConfig_keepsOtherFields() {
        // Arrange
        val original = createTestBuildConfig()
        val newAuthConfig = AuthConfig(
            listOf("new:audience"),
            600,
            true,
            SmbTokenProvider(SmbTokenProvider.Credentials("", "", "")),
            requiredRoleOid = requiredRoleOid,
        )

        // Act
        val copy = original.copy(authConfig = newAuthConfig)

        // Assert
        assertEquals(newAuthConfig, copy.authConfig)
        assertEquals(original.productId, copy.productId)
    }

    @Test
    fun buildConfig_copy_onlyPlatformProductId_keepsOtherFields() {
        // Arrange
        val original = createTestBuildConfig()
        val newPlatform = PlatformProductId.WindowsProductId("windows", "11", "app")

        // Act
        val copy = original.copy(platformProductId = newPlatform)

        // Assert
        assertEquals(newPlatform, copy.platformProductId)
        assertEquals(original.productId, copy.productId)
    }

    @Test
    fun buildConfig_copy_httpClientBuilder_updatesCorrectly() {
        // Arrange
        val original = createTestBuildConfig()
        val builder = ZetaHttpClientBuilder()

        // Act
        val copy = original.copy(httpClientBuilder = builder)

        // Assert
        assertEquals(builder, copy.httpClientBuilder)
        assertNull(original.httpClientBuilder)
    }

    @Test
    fun buildConfig_copy_registrationCallback_updatesCorrectly() {
        // Arrange
        val original = createTestBuildConfig()
        val callback = RegistrationCallback { RegInfo("new") }

        // Act
        val copy = original.copy(registrationCallback = callback)

        // Assert
        assertEquals(callback, copy.registrationCallback)
        assertNull(original.registrationCallback)
    }

    @Test
    fun buildConfig_copy_authenticationCallback_updatesCorrectly() {
        // Arrange
        val original = createTestBuildConfig()
        val callback = AuthenticationCallback { AuthInfo("new") }

        // Act
        val copy = original.copy(authenticationCallback = callback)

        // Assert
        assertEquals(callback, copy.authenticationCallback)
        assertNull(original.authenticationCallback)
    }

    @Test
    fun buildConfig_notEquals_differentStorageConfig() {
        // Arrange
        val config1 = createTestBuildConfig()
        val config2 = config1.copy(storageConfig = StorageConfig.Default(aesB64Key = "different"))

        // Assert
        assertNotEquals(config1, config2)
    }

    @Test
    fun buildConfig_withLinuxPlatform_createsValidObject() {
        // Arrange
        val config = createTestBuildConfig()

        // Assert
        assertTrue(config.platformProductId is PlatformProductId.LinuxProductId)
    }

    @Test
    fun buildConfig_withApplePlatform_createsValidObject() {
        // Arrange
        val applePlatform = PlatformProductId.AppleProductId(
            "apple",
            "macOS 14",
            listOf("com.example.app"),
        )
        val config = createTestBuildConfig().copy(platformProductId = applePlatform)

        // Assert
        assertTrue(config.platformProductId is PlatformProductId.AppleProductId)
    }

    @Test
    fun buildConfig_withWindowsPlatform_createsValidObject() {
        // Arrange
        val windowsPlatform = PlatformProductId.WindowsProductId(
            platform = "windows",
            "11",
            "win-app",
        )
        val config = createTestBuildConfig().copy(platformProductId = windowsPlatform)

        // Assert
        assertTrue(config.platformProductId is PlatformProductId.WindowsProductId)
    }

    @Test
    fun registrationCallback_capturesLambdaCorrectly() = runTest {
        // Arrange
        val expectedName = "ExpectedClient"
        val callback = RegistrationCallback {
            RegInfo(clientName = expectedName)
        }

        // Act
        val result = callback.registrationCb()

        // Assert
        assertEquals(expectedName, result.clientName)
    }

    @Test
    fun registrationCallback_withDifferentClientNames_returnsCorrectValues() = runTest {
        // Arrange
        val callback1 = RegistrationCallback { RegInfo("Client1") }
        val callback2 = RegistrationCallback { RegInfo("Client2") }

        // Act
        val result1 = callback1.registrationCb()
        val result2 = callback2.registrationCb()

        // Assert
        assertEquals("Client1", result1.clientName)
        assertEquals("Client2", result2.clientName)
    }

    @Test
    fun registrationCallback_withEmptyClientName_returnsEmpty() = runTest {
        // Arrange
        val callback = RegistrationCallback { RegInfo("") }

        // Act
        val result = callback.registrationCb()

        // Assert
        assertEquals("", result.clientName)
    }

    @Test
    fun registrationCallback_withComplexLogic_executesCorrectly() = runTest {
        // Arrange
        var sideEffect = 0
        val callback = RegistrationCallback {
            sideEffect += 10
            RegInfo("Client-$sideEffect")
        }

        // Act
        val result = callback.registrationCb()

        // Assert
        assertEquals(10, sideEffect)
        assertEquals("Client-10", result.clientName)
    }

    @Test
    fun authenticationCallback_capturesLambdaCorrectly() = runTest {
        // Arrange
        val expectedOtp = "654321"
        val callback = AuthenticationCallback {
            AuthInfo(otp = expectedOtp)
        }

        // Act
        val result = callback.authenticationCb()

        // Assert
        assertEquals(expectedOtp, result.otp)
    }

    @Test
    fun authenticationCallback_withDifferentOtps_returnsCorrectValues() = runTest {
        // Arrange
        val callback1 = AuthenticationCallback { AuthInfo("111111") }
        val callback2 = AuthenticationCallback { AuthInfo("222222") }

        // Act
        val result1 = callback1.authenticationCb()
        val result2 = callback2.authenticationCb()

        // Assert
        assertEquals("111111", result1.otp)
        assertEquals("222222", result2.otp)
    }

    @Test
    fun authenticationCallback_withEmptyOtp_returnsEmpty() = runTest {
        // Arrange
        val callback = AuthenticationCallback { AuthInfo("") }

        // Act
        val result = callback.authenticationCb()

        // Assert
        assertEquals("", result.otp)
    }

    @Test
    fun authenticationCallback_withComplexLogic_executesCorrectly() = runTest {
        // Arrange
        var counter = 100
        val callback = AuthenticationCallback {
            counter += 23
            AuthInfo("OTP-$counter")
        }

        // Act
        val result = callback.authenticationCb()

        // Assert
        assertEquals(123, counter)
        assertEquals("OTP-123", result.otp)
    }

    @Test
    fun authenticationCallback_modifyingCapturedVariable_reflectsChanges() = runTest {
        // Arrange
        var capturedOtp = "initial"
        val callback = AuthenticationCallback {
            capturedOtp = "modified"
            AuthInfo(capturedOtp)
        }

        // Act
        val result = callback.authenticationCb()

        // Assert
        assertEquals("modified", capturedOtp)
        assertEquals("modified", result.otp)
    }

    private fun createTestBuildConfig(
        productId: String = "test-product",
        productVersion: String = "1.0.0",
        clientName: String = "TestClient",
        storageConfig: StorageConfig = StorageConfig.Custom(provider = InMemoryStorage()),
        httpClientBuilder: ZetaHttpClientBuilder? = null,
        registrationCallback: RegistrationCallback? = null,
        authenticationCallback: AuthenticationCallback? = null,
    ): BuildConfig {
        val tpmConfig = object : TpmConfig {}
        val authConfig = AuthConfig(listOf("scopes"), 300, false, SmbTokenProvider(SmbTokenProvider.Credentials("", "", "")), requiredRoleOid = requiredRoleOid)
        val platformProductId = PlatformProductId.LinuxProductId("", "", "", "")

        return BuildConfig(
            productId = productId,
            productVersion = productVersion,
            clientName = clientName,
            storageConfig = storageConfig,
            tpmConfig = tpmConfig,
            authConfig = authConfig,
            platformProductId = platformProductId,
            httpClientBuilder = httpClientBuilder,
            registrationCallback = registrationCallback,
            authenticationCallback = authenticationCallback,
        )
    }

    private fun createMockStorage(): SdkStorage = object : SdkStorage {
        private val data = mutableMapOf<String, String>()

        override suspend fun put(key: String, value: String) {
            data[key] = value
        }

        override suspend fun get(key: String): String? {
            return data[key]
        }

        override suspend fun remove(key: String) {
            data.remove(key)
        }

        override suspend fun clear() {
            data.clear()
        }
    }
}
