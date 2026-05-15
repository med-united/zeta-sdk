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

package de.gematik.zeta.sdk.attestation

import de.gematik.zeta.sdk.attestation.model.AttestationStatus
import de.gematik.zeta.sdk.network.http.client.ZetaHttpClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AttestationServiceApiTest {

    @Test
    fun generateAttestation_returnsValidResponse_whenServiceReturnsSuccess() = runTest {
        // Arrange
        val expectedResponse = AttestationResponse(
            tpmQuote = "quote-data",
            tpmQuoteSignature = "signature",
            attestationKey = "key",
            eventLog = "log",
            certificateChain = listOf("cert1", "cert2"),
        )

        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(expectedResponse)),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = null,
            statusCallback = null,
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act
        val result = service.generateAttestation("challenge123")

        // Assert
        assertEquals("quote-data", result.tpmQuote)
        assertEquals("signature", result.tpmQuoteSignature)
        assertEquals("key", result.attestationKey)
        assertEquals("log", result.eventLog)
        assertEquals(listOf("cert1", "cert2"), result.certificateChain)

        assertNull(result.error)
    }

    @Test
    fun generateAttestation_returnsError_whenTpmNotAvailable() = runTest {
        // Arrange
        var callbackInvoked = false
        var capturedStatus: AttestationStatus? = null

        val errorResponse = AttestationResponse(
            error = ServiceError(
                code = ErrorCode.TPM_NOT_AVAILABLE,
                message = "TPM device not found",
            ),
        )

        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(errorResponse)),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = null,
            statusCallback = { status ->
                callbackInvoked = true
                capturedStatus = status
            },
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act
        val result = service.generateAttestation("challenge123")

        // Assert
        assertNotNull(result.error)
        assertEquals(ErrorCode.TPM_NOT_AVAILABLE, result.error.code)
        assertEquals("TPM device not found", result.error.message)
        assertEquals("", result.tpmQuote)

        assertTrue(callbackInvoked)
        assertTrue(capturedStatus is AttestationStatus.KO)
    }

    @Test
    fun generateAttestation_returnsError_whenTpmQuoteError() = runTest {
        // Arrange
        var capturedStatus: AttestationStatus? = null

        val errorResponse = AttestationResponse(
            error = ServiceError(
                code = ErrorCode.TPM_QUOTE_ERROR,
                message = "Quote generation failed",
            ),
        )

        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(errorResponse)),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = null,
            statusCallback = { status -> capturedStatus = status },
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act
        val result = service.generateAttestation("challenge123")

        // Assert
        assertEquals(ErrorCode.TPM_QUOTE_ERROR, result.error?.code)
        assertTrue(capturedStatus is AttestationStatus.KO)
    }

    @Test
    fun generateAttestation_returnsError_whenInvalidArgument() = runTest {
        // Arrange
        var capturedStatus: AttestationStatus? = null

        val errorResponse = AttestationResponse(
            error = ServiceError(
                code = ErrorCode.INVALID_ARGUMENT,
                message = "Invalid PCR selection",
            ),
        )

        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(errorResponse)),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = null,
            statusCallback = { status -> capturedStatus = status },
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act
        val result = service.generateAttestation("challenge123")

        // Assert
        assertEquals(ErrorCode.INVALID_ARGUMENT, result.error?.code)
        assertTrue(capturedStatus is AttestationStatus.KO)
    }

    @Test
    fun generateAttestation_returnsError_whenInternalError() = runTest {
        // Arrange
        var capturedStatus: AttestationStatus? = null

        val errorResponse = AttestationResponse(
            error = ServiceError(
                code = ErrorCode.INTERNAL_ERROR,
                message = "Unexpected error occurred",
            ),
        )

        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(errorResponse)),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = null,
            statusCallback = { status -> capturedStatus = status },
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act
        val result = service.generateAttestation("challenge123")

        // Assert
        assertEquals(ErrorCode.INTERNAL_ERROR, result.error?.code)
        assertTrue(capturedStatus is AttestationStatus.KO)
    }

    @Test
    fun generateAttestation_returnsError_whenProcessNotAllowed() = runTest {
        // Arrange
        var capturedStatus: AttestationStatus? = null

        val errorResponse = AttestationResponse(
            error = ServiceError(
                code = ErrorCode.PROCESS_NOT_ALLOWED,
                message = "Process not allowed",
            ),
        )

        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(errorResponse)),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = null,
            statusCallback = { status -> capturedStatus = status },
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act
        val result = service.generateAttestation("challenge123")

        // Assert
        assertEquals(ErrorCode.PROCESS_NOT_ALLOWED, result.error?.code)
        assertTrue(capturedStatus is AttestationStatus.KO)
    }

    @Test
    fun generateAttestation_returnsError_whenResponseMissingTpmQuote() = runTest {
        // Arrange
        var capturedStatus: AttestationStatus? = null

        val errorResponse = AttestationResponse(
            tpmQuote = "",
            tpmQuoteSignature = "signature",
            attestationKey = "key",
        )

        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(errorResponse)),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = null,
            statusCallback = { status -> capturedStatus = status },
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act
        val result = service.generateAttestation("challenge123")

        // Assert
        assertEquals("", result.tpmQuote)
        assertTrue(capturedStatus is AttestationStatus.KO)
    }

    @Test
    fun generateAttestation_returnsError_whenHttpClientThrowsException() = runTest {
        // Arrange
        val mockEngine = MockEngine { _ ->
            error("Network error")
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = null,
            statusCallback = null,
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act
        val result = service.generateAttestation("challenge123")

        // Assert
        assertEquals(ErrorCode.INTERNAL_ERROR, result.error?.code)
    }

    @Test
    fun generateAttestation_sendsCorrectRequest_whenCalled() = runTest {
        // Arrange
        var capturedRequestBody: String? = null

        val mockEngine = MockEngine { request ->
            capturedRequestBody = request.body.toString()

            respond(
                content = ByteReadChannel(Json.encodeToString(AttestationResponse())),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(7, 23),
            websocketEndpoint = null,
            statusCallback = null,
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act
        service.generateAttestation("test-challenge-456")

        // Assert
        assertNotNull(capturedRequestBody)
    }

    @Test
    fun init_doesNotInvokeCallback_whenCallbackIsNull() = runTest {
        // Arrange
        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(AttestationResponse())),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = null,
            statusCallback = null,
        )

        // Act & Assert - should not throw
        AttestationServiceApi(config, httpClient)
    }

    @Test
    fun close_doesNotThrow_whenCalledMultipleTimes() = runTest {
        // Arrange
        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(AttestationResponse())),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = null,
            statusCallback = null,
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act & Assert - should not throw
        service.close()
        service.close()
        service.close()
    }

    @Test
    fun close_doesNotThrow_whenWebSocketEndpointIsProvided() = runTest {
        // Arrange
        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(AttestationResponse())),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClient(mockEngine)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = "wss://example.com/status", // WebSocket endpoint provided
            statusCallback = null,
        )

        val service = AttestationServiceApi(config, httpClient)

        // Act & Assert
        service.close()
    }

    @Test
    fun close_cancelsWebSocketJob_whenWebSocketIsActive() = runTest {
        // Arrange
        val mockEngine = MockEngine { _ ->
            respond(
                content = ByteReadChannel(Json.encodeToString(AttestationResponse())),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                ),
            )
        }

        val httpClient = createMockHttpClientWithWebSocket(mockEngine, true)
        val config = TpmAttestationServiceConfig(
            attestationEndpoint = "https://attestation.example.com/attest",
            pcrSelection = listOf(23),
            websocketEndpoint = "wss://attestation.example.com/status",
            statusCallback = null,
        )

        val service = AttestationServiceApi(config, httpClient)
        delay(100)

        // Act
        service.close()

        // Assert
    }

    private fun createMockHttpClientWithWebSocket(
        mockEngine: MockEngine,
        successfulIntegrityCheck: Boolean,
        failedFiles: List<String> = emptyList(),
    ): ZetaHttpClient {
        // Create a WebSocket mock response
        val results = if (successfulIntegrityCheck) {
            mapOf(
                "/valid/file" to AttestationServiceApi.FileIntegrityResult(
                    path = "/valid/file",
                    expectedHash = "abc123",
                    actualHash = "abc123",
                    isValid = true,
                ),
            )
        } else {
            failedFiles.associateWith { path ->
                AttestationServiceApi.FileIntegrityResult(
                    path = path,
                    expectedHash = "expected",
                    actualHash = "actual",
                    isValid = false,
                )
            } + mapOf(
                "/valid/file" to AttestationServiceApi.FileIntegrityResult(
                    path = "/valid/file",
                    expectedHash = "abc123",
                    actualHash = "abc123",
                    isValid = true,
                ),
            )
        }

        AttestationServiceApi.VerifyIntegrityResponse(
            results = results,
            success = successfulIntegrityCheck,
        )

        val http = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(
                    Json {
                        ignoreUnknownKeys = true
                        isLenient = true
                    },
                )
            }
            install(WebSockets)
        }

        return ZetaHttpClient(http)
    }

    private fun createMockHttpClient(mockEngine: MockEngine): ZetaHttpClient {
        val http = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(
                    Json {
                        ignoreUnknownKeys = true
                        isLenient = true
                    },
                )
            }
            install(WebSockets)
        }

        return ZetaHttpClient(http)
    }
}
