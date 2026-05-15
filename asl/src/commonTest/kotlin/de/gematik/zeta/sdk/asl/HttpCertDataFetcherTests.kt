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

package de.gematik.zeta.sdk.asl

import de.gematik.zeta.sdk.network.http.client.ZetaHttpClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.url
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(ExperimentalSerializationApi::class)
class HttpCertDataFetcherTest {
    private val certHashHex = "abc123"
    private val cdv = 1
    private val certBytes = byteArrayOf(1, 2, 3)
    private val caBytes = byteArrayOf(4, 5, 6)
    private val rcaChainBytes = listOf(byteArrayOf(7, 8, 9))

    private fun fakeCertData() = CertData(
        cert = certBytes,
        ca = caBytes,
        rcaChain = rcaChainBytes,
    )

    private fun encodedCertData(): ByteArray =
        cbor.encodeToByteArray(CertData.serializer(), fakeCertData())

    private fun mockClient(
        responseBytes: ByteArray = encodedCertData(),
        status: HttpStatusCode = HttpStatusCode.OK,
        throws: Boolean = false,
        captureRequest: ((String) -> Unit)? = null,
    ): ZetaHttpClient {
        val engine = MockEngine { request ->
            captureRequest?.invoke(request.url.toString())
            if (throws) error("Network error")
            respond(
                content = responseBytes,
                status = status,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Cbor.toString()),
            )
        }
        return ZetaHttpClient(HttpClient(engine))
    }

    private fun requestBuilder(url: String = "https://asl.example.com"): HttpRequestBuilder =
        HttpRequestBuilder().apply { url(url) }

    @Test
    fun fetch_returnsCertData_onSuccess() = runTest {
        val fetcher = HttpCertDataFetcher(mockClient(), requestBuilder())

        val result = fetcher.fetch(certHashHex, cdv)

        assertContentEquals(certBytes, result.cert)
        assertContentEquals(caBytes, result.ca)
        assertEquals(1, result.rcaChain.size)
        assertContentEquals(rcaChainBytes[0], result.rcaChain[0])
    }

    @Test
    fun fetch_buildsCorrectUrl() = runTest {
        var capturedUrl = ""
        val fetcher = HttpCertDataFetcher(
            mockClient(captureRequest = { capturedUrl = it }),
            requestBuilder("https://asl.example.com"),
        )

        fetcher.fetch(certHashHex, cdv)

        assertTrue(capturedUrl.contains("/CertData.$certHashHex-$cdv"))
        assertTrue(capturedUrl.startsWith("https://asl.example.com"))
    }

    @Test
    fun fetch_preservesHostAndPort_fromRequestBuilder() = runTest {
        var capturedUrl = ""
        val fetcher = HttpCertDataFetcher(
            mockClient(captureRequest = { capturedUrl = it }),
            requestBuilder("https://custom.host.com:8443"),
        )

        fetcher.fetch(certHashHex, cdv)

        assertTrue(capturedUrl.contains("custom.host.com"))
        assertTrue(capturedUrl.contains("8443"))
    }

    @Test
    fun fetch_throwsException_onNetworkError() = runTest {
        val fetcher = HttpCertDataFetcher(
            mockClient(throws = true),
            requestBuilder(),
        )

        assertFailsWith<IllegalStateException> {
            fetcher.fetch(certHashHex, cdv)
        }
    }

    @Test
    fun fetch_throwsException_onInvalidCborResponse() = runTest {
        val fetcher = HttpCertDataFetcher(
            mockClient(responseBytes = byteArrayOf(0xFF.toByte())),
            requestBuilder(),
        )
        assertFailsWith<SerializationException> {
            fetcher.fetch(certHashHex, cdv)
        }
    }

    @Test
    fun fetch_usesCorrectCdvInUrl() = runTest {
        var capturedUrl = ""
        val fetcher = HttpCertDataFetcher(
            mockClient(captureRequest = { capturedUrl = it }),
            requestBuilder(),
        )

        fetcher.fetch(certHashHex, cdv = 5)

        assertTrue(capturedUrl.contains("$certHashHex-5"))
    }

    @Test
    fun fetch_withEmptyRcaChain_returnsEmptyList() = runTest {
        val certDataNoRca = CertData(
            cert = certBytes,
            ca = caBytes,
            rcaChain = emptyList(),
        )
        val encoded = cbor.encodeToByteArray(CertData.serializer(), certDataNoRca)
        val fetcher = HttpCertDataFetcher(mockClient(responseBytes = encoded), requestBuilder())

        val result = fetcher.fetch(certHashHex, cdv)

        assertTrue(result.rcaChain.isEmpty())
    }

    @Test
    fun certData_equality_basedOnContent() {
        val a = CertData(byteArrayOf(1), byteArrayOf(2), listOf(byteArrayOf(3)))
        val b = CertData(byteArrayOf(1), byteArrayOf(2), listOf(byteArrayOf(3)))

        assertContentEquals(a.cert, b.cert)
        assertContentEquals(a.ca, b.ca)
        assertEquals(a.rcaChain.size, b.rcaChain.size)
        a.rcaChain.zip(b.rcaChain).forEach { (x, y) -> assertContentEquals(x, y) }
    }

    @Test
    fun certData_inequality_whenCertDiffers() {
        val a = CertData(byteArrayOf(1), byteArrayOf(2), emptyList())
        val b = CertData(byteArrayOf(9), byteArrayOf(2), emptyList())

        assertFalse(a.cert.contentEquals(b.cert))
    }
}
