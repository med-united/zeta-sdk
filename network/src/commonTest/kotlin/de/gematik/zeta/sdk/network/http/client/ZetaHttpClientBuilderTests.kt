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

import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.logging.LogLevel
import io.ktor.client.plugins.logging.Logger
import io.ktor.http.HttpStatusCode
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class ZetaHttpClientBuilderTest {
    @Test
    fun constructor_createsBuilder_emptyBaseUrl() {
        // Arrange & Act
        val builder = ZetaHttpClientBuilder()

        // Assert
        assertNotNull(builder)
    }

    @Test
    fun constructor_createsBuilder_withBaseUrl() {
        // Arrange & Act
        val builder = ZetaHttpClientBuilder("https://api.example.com")

        // Assert
        assertNotNull(builder)
    }

    @Test
    fun timeouts_returnsBuilder_forChaining() {
        // Arrange
        val builder = ZetaHttpClientBuilder()

        // Act
        val result = builder.timeouts(connectMs = 5000, requestMs = 10000)

        // Assert
        assertEquals(builder, result)
    }

    @Test
    fun timeouts_setsConnectTimeout_whenProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.timeouts(connectMs = 5000).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun timeouts_setsRequestTimeout_whenProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.timeouts(requestMs = 10000).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun timeouts_setsBothTimeouts_whenBothProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.timeouts(connectMs = 5000, requestMs = 10000).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun timeouts_keepsExistingValue_whenNullProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder
            .timeouts(connectMs = 5000, requestMs = 10000)
            .timeouts(connectMs = null, requestMs = 15000)
            .build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun timeouts_chainsMultipleCalls_appliesLast() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder
            .timeouts(connectMs = 1000)
            .timeouts(requestMs = 2000)
            .timeouts(connectMs = 3000)
            .build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun retry_returnsBuilder_forChaining() {
        // Arrange
        val builder = ZetaHttpClientBuilder()

        // Act
        val result = builder.retry(
            statusCodes = setOf(HttpStatusCode.ServiceUnavailable),
            maxRetries = 3,
            onlyIdempotent = true,
        )

        // Assert
        assertEquals(builder, result)
    }

    @Test
    fun retry_setsStatusCodes_whenProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.retry(
            statusCodes = setOf(HttpStatusCode.ServiceUnavailable, HttpStatusCode.TooManyRequests),
        ).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun retry_setsMaxRetries_whenProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.retry(maxRetries = 5).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun retry_setsOnlyIdempotent_whenProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.retry(onlyIdempotent = false).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun retry_setsAllParameters_whenAllProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.retry(
            statusCodes = setOf(HttpStatusCode.ServiceUnavailable),
            maxRetries = 3,
            onlyIdempotent = true,
        ).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun retry_chainsMultipleCalls_appliesLast() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder
            .retry(maxRetries = 1)
            .retry(maxRetries = 3)
            .retry(maxRetries = 5)
            .build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun disableServerValidation_returnsBuilder_forChaining() {
        // Arrange
        val builder = ZetaHttpClientBuilder()

        // Act
        val result = builder.disableServerValidation(true)

        // Assert
        assertEquals(builder, result)
    }

    @Test
    fun disableServerValidation_setsTrue_whenTrue() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.disableServerValidation(true).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun disableServerValidation_setsFalse_whenFalse() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.disableServerValidation(false).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun addCaPem_returnsBuilder_forChaining() {
        // Arrange
        val builder = ZetaHttpClientBuilder()

        // Act
        val result = builder.addCaPem("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

        // Assert
        assertEquals(builder, result)
    }

    @Test
    fun addCaPem_addsSingleCert_whenCalled() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }
        val cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"

        // Act
        val client = builder.addCaPem(cert).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun addCaPem_accumulatesCerts_whenCalledMultipleTimes() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }
        val cert1 = "-----BEGIN CERTIFICATE-----\ncert1\n-----END CERTIFICATE-----"
        val cert2 = "-----BEGIN CERTIFICATE-----\ncert2\n-----END CERTIFICATE-----"

        // Act
        val client = builder
            .addCaPem(cert1)
            .addCaPem(cert2)
            .build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun setCaPems_returnsBuilder_forChaining() {
        // Arrange
        val builder = ZetaHttpClientBuilder()

        // Act
        val result = builder.setCaPems(listOf("cert1", "cert2"))

        // Assert
        assertEquals(builder, result)
    }

    @Test
    fun setCaPems_replacesExistingCerts_whenCalled() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }
        val cert1 = "-----BEGIN CERTIFICATE-----\ncert1\n-----END CERTIFICATE-----"
        val cert2 = "-----BEGIN CERTIFICATE-----\ncert2\n-----END CERTIFICATE-----"

        // Act
        val client = builder
            .addCaPem(cert1)
            .setCaPems(listOf(cert2)) // Replaces cert1 with cert2
            .build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun setCaPems_setsEmptyList_whenEmptyListProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder
            .addCaPem("cert")
            .setCaPems(emptyList())
            .build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun setCaPems_setsMultipleCerts_whenListProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }
        val certs = listOf("cert1", "cert2", "cert3")

        // Act
        val client = builder.setCaPems(certs).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun logging_returnsBuilder_forChaining() {
        // Arrange
        val builder = ZetaHttpClientBuilder()

        // Act
        val result = builder.logging(LogLevel.INFO)

        // Assert
        assertEquals(builder, result)
    }

    @Test
    fun logging_setsLogLevel_whenProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.logging(LogLevel.HEADERS).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun logging_setsLogProvider_whenProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }
        val customLogger = object : Logger {
            override fun log(message: String) {}
        }

        // Act
        val client = builder.logging(LogLevel.ALL, customLogger).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }

    @Test
    fun logging_usesDefaultLogger_whenNotProvided() = runTest {
        // Arrange
        val builder = ZetaHttpClientBuilder()
        val mockEngine = MockEngine { respond(ByteReadChannel(""), HttpStatusCode.OK) }

        // Act
        val client = builder.logging(LogLevel.INFO).build(mockEngine)

        // Assert
        assertNotNull(client)
        client.close()
    }
}
