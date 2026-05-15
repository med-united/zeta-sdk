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

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.future.await
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class HttpClientExtensionTest {
    data class CapturedRequest(
        val method: String,
        val url: String,
        val headers: Headers,
        val body: String,
    )
    private val captured = mutableListOf<CapturedRequest>()
    private lateinit var client: ZetaHttpClient

    @BeforeTest
    fun setUp() {
        captured.clear()
        client = buildClient()
    }

    @AfterTest
    fun tearDown() {
        client.close()
    }

    private val testUrl = "https://api.example.com/test"
    private val testHeaders = mapOf("Authorization" to "Bearer token123", "X-Trace-Id" to "abc")
    private val testBody = """{"key":"value"}"""
    private val responseBody = """{"status":"ok"}"""

    private fun buildClient(): ZetaHttpClient {
        val engine = MockEngine { request ->
            captured += CapturedRequest(
                method = request.method.value,
                url = request.url.toString(),
                headers = request.headers,
                body = request.body.toByteArray().decodeToString(),
            )
            respond(
                content = responseBody,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
            )
        }
        return ZetaHttpClient(HttpClient(engine))
    }

    private val last get() = captured.last()

    @Test
    fun getAsync_returnsNonNullCompletableFuture() = runTest {
        val future = with(HttpClientExtension) { client.getAsync(testUrl) }
        assertNotNull(future)
        future.await()
    }

    @Test
    fun getAsync_usesGetMethod() = runTest {
        with(HttpClientExtension) { client.getAsync(testUrl) }.await()
        assertEquals("GET", last.method)
    }

    @Test
    fun postAsync_forwardsBody() = runTest {
        with(HttpClientExtension) { client.postAsync(testUrl, testHeaders, testBody) }.await()
        assertEquals(testBody, last.body)
    }

    @Test
    fun putAsync_forwardsBody() = runTest {
        with(HttpClientExtension) { client.putAsync(testUrl, testHeaders, testBody) }.await()
        assertEquals(testBody, last.body)
    }

    @Test
    fun patchAsync_usesPatchMethod() = runTest {
        with(HttpClientExtension) { client.patchAsync(testUrl, testHeaders, testBody) }.await()
        assertEquals("PATCH", last.method)
    }

    @Test
    fun deleteAsync_forwardsHeaders() = runTest {
        with(HttpClientExtension) { client.deleteAsync(testUrl, testHeaders) }.await()
        assertEquals("Bearer token123", last.headers["Authorization"])
    }

    @Test
    fun optionsAsync_forwardsHeaders() = runTest {
        with(HttpClientExtension) { client.optionsAsync(testUrl, testHeaders) }.await()
        assertEquals("Bearer token123", last.headers["Authorization"])
    }

    @Test
    fun getAsync_futureCompletesExceptionally_whenEngineThrows() = runTest {
        val failingClient = ZetaHttpClient(HttpClient(MockEngine { error("engine failure") }))
        try {
            with(HttpClientExtension) { failingClient.getAsync(testUrl) }.await()
            throw AssertionError("Expected exception was not thrown")
        } catch (e: IllegalStateException) {
            assertEquals("engine failure", e.message)
        } finally {
            failingClient.close()
        }
    }

    @Test
    fun getAsync_usesGetMethod_withHeaderMap() = runTest {
        with(HttpClientExtension) { client.getAsync(testUrl, testHeaders) }.await()
        assertEquals("GET", last.method)
    }

    @Test
    fun headAsync_usesHeadMethod() = runTest {
        with(HttpClientExtension) { client.headAsync(testUrl, testHeaders) }.await()
        assertEquals("HEAD", last.method)
    }

    @Test
    fun headAsync_forwardsHeaders() = runTest {
        with(HttpClientExtension) { client.headAsync(testUrl, testHeaders) }.await()
        assertEquals("Bearer token123", last.headers["Authorization"])
    }

    @Test
    fun bodyAsText_returnsBodyContent() = runTest {
        val response = with(HttpClientExtension) { client.getAsync(testUrl) }.await()
        val text = HttpClientExtension.bodyAsText(response).get()
        assertEquals(responseBody, text)
    }
}
