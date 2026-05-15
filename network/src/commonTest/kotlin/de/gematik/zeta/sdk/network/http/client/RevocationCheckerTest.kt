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

import de.gematik.zeta.sdk.crypto.OcspHandler
import de.gematik.zeta.sdk.crypto.OcspRequestData
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RevocationCheckerTest {
    open class FakeOcspHandler(
        private val ocspUrl: String = "http://ocsp.example.com",
        private val crlUrl: String? = "http://crl.example.com/crl.crl",
        private val throwOnPrepare: Exception? = null,
        private val throwOnValidate: Exception? = null,
        private val throwOnValidateCrl: Exception? = null,
    ) : OcspHandler {
        var prepareCallCount = 0
        var validateCallCount = 0
        var validateCrlCount = 0
        var extractCrlCallCount = 0
        var lastCertDer: ByteArray? = null
        var lastIssuerDer: ByteArray? = null

        override suspend fun prepareOcspRequest(certDer: ByteArray, issuerDer: ByteArray): OcspRequestData {
            prepareCallCount++
            lastCertDer = certDer
            lastIssuerDer = issuerDer
            throwOnPrepare?.let { throw it }
            return OcspRequestData(url = ocspUrl, requestDer = ByteArray(16) { 0x01 })
        }

        override fun getProducedAtEpochSeconds(ocspResponseDer: ByteArray): Long {
            return 0
        }

        override fun validate(ocspResponseDer: ByteArray, certDer: ByteArray, issuerDer: ByteArray) {
            validateCallCount++
            throwOnValidate?.let { throw it }
        }

        override fun extractCrlUrl(certDer: ByteArray): String? {
            extractCrlCallCount++
            return crlUrl
        }

        override fun validateCrl(crlDer: ByteArray, certDer: ByteArray, issuerDer: ByteArray) {
            validateCrlCount++
            throwOnValidateCrl?.let { throw it }
        }
    }

    data class CapturedRequest(val method: String, val url: String)

    private val capturedRequests = mutableListOf<CapturedRequest>()

    @BeforeTest
    fun setUp() { capturedRequests.clear() }

    private val certDer = ByteArray(32) { it.toByte() }
    private val issuerDer = ByteArray(32) { (it + 1).toByte() }

    private fun buildMockClient(body: ByteArray = ByteArray(64) { 0x02 }): HttpClient {
        val engine = MockEngine { request ->
            capturedRequests += CapturedRequest(request.method.value, request.url.toString())
            respond(body, HttpStatusCode.OK, headersOf())
        }
        return HttpClient(engine)
    }

    private fun buildChecker(
        ocspHandler: FakeOcspHandler = FakeOcspHandler(),
        httpClient: HttpClient = buildMockClient(),
    ) = RevocationChecker(ocspHandler = ocspHandler, httpClient = httpClient)

    @Test
    fun checkRevocation_completesSuccessfully_whenOcspValidationPasses() = runTest {
        val handler = FakeOcspHandler()
        buildChecker(handler).checkRevocation(certDer, issuerDer)
        assertEquals(1, handler.validateCallCount)
    }

    @Test
    fun checkRevocation_callsPrepareOcspRequest_withCorrectCertAndIssuer() = runTest {
        val handler = FakeOcspHandler()
        buildChecker(handler).checkRevocation(certDer, issuerDer)
        assertEquals(1, handler.prepareCallCount)
        assertTrue(handler.lastCertDer.contentEquals(certDer))
        assertTrue(handler.lastIssuerDer.contentEquals(issuerDer))
    }

    @Test
    fun checkRevocation_sendsOcspPostRequest_toCorrectUrl() = runTest {
        val handler = FakeOcspHandler(ocspUrl = "http://ocsp.example.com/check")
        buildChecker(handler).checkRevocation(certDer, issuerDer)
        assertTrue(capturedRequests.any { it.method == "POST" && it.url == "http://ocsp.example.com/check" })
    }

    @Test
    fun checkRevocation_doesNotFallBackToCrl_whenOcspSucceeds() = runTest {
        val handler = FakeOcspHandler()
        buildChecker(handler).checkRevocation(certDer, issuerDer)
        assertEquals(0, handler.validateCrlCount)
        assertTrue(capturedRequests.none { it.method == "GET" })
    }

    @Test
    fun checkRevocation_doesNotCallExtractCrlUrl_whenOcspSucceeds() = runTest {
        val handler = FakeOcspHandler()
        buildChecker(handler).checkRevocation(certDer, issuerDer)
        assertEquals(0, handler.extractCrlCallCount)
    }

    @Test
    fun checkRevocation_fallsBackToCrl_whenOcspPrepareFails() = runTest {
        val handler = FakeOcspHandler(
            throwOnPrepare = RuntimeException("OCSP unavailable"),
            crlUrl = "http://crl.example.com/crl.crl",
        )
        buildChecker(handler).checkRevocation(certDer, issuerDer)
        assertEquals(1, handler.validateCrlCount)
    }

    @Test
    fun checkRevocation_fallsBackToCrl_whenOcspValidateFails() = runTest {
        val handler = FakeOcspHandler(
            throwOnValidate = RuntimeException("OCSP signature invalid"),
            crlUrl = "http://crl.example.com/crl.crl",
        )
        buildChecker(handler).checkRevocation(certDer, issuerDer)
        assertEquals(1, handler.validateCrlCount)
    }

    @Test
    fun checkRevocation_downloadsCrl_fromExtractedUrl() = runTest {
        val handler = FakeOcspHandler(
            throwOnPrepare = RuntimeException("OCSP down"),
            crlUrl = "http://crl.example.com/crl.crl",
        )
        buildChecker(handler).checkRevocation(certDer, issuerDer)
        assertTrue(capturedRequests.any { it.method == "GET" && it.url == "http://crl.example.com/crl.crl" })
    }

    @Test
    fun checkRevocation_completesSuccessfully_whenOcspFailsButCrlPasses() = runTest {
        val handler = FakeOcspHandler(
            throwOnPrepare = RuntimeException("OCSP timeout"),
            crlUrl = "http://crl.example.com/crl.crl",
        )
        // Should not throw
        buildChecker(handler).checkRevocation(certDer, issuerDer)
    }

    @Test
    fun checkRevocation_throwsCertificateRevokedException_whenNoCrlDistributionPoint() = runTest {
        val handler = FakeOcspHandler(
            throwOnPrepare = RuntimeException("OCSP failed"),
            crlUrl = null,
        )
        assertFailsWith<CertificateRevokedException> {
            buildChecker(handler).checkRevocation(certDer, issuerDer)
        }
    }

    @Test
    fun checkRevocation_throwsCertificateRevokedException_whenBothOcspAndCrlFail() = runTest {
        val handler = FakeOcspHandler(
            throwOnPrepare = RuntimeException("OCSP unavailable"),
            crlUrl = "http://crl.example.com/crl.crl",
            throwOnValidateCrl = RuntimeException("CRL invalid"),
        )
        assertFailsWith<CertificateRevokedException> {
            buildChecker(handler).checkRevocation(certDer, issuerDer)
        }
    }

    @Test
    fun checkRevocation_exceptionMessage_mentionsRevocationFailure_whenBothFail() = runTest {
        val handler = FakeOcspHandler(
            throwOnPrepare = RuntimeException("OCSP down"),
            crlUrl = "http://crl.example.com/crl.crl",
            throwOnValidateCrl = RuntimeException("CRL expired"),
        )
        val ex = assertFailsWith<CertificateRevokedException> {
            buildChecker(handler).checkRevocation(certDer, issuerDer)
        }
        assertNotNull(ex.message)
        assertTrue(
            ex.message!!.contains("OCSP", ignoreCase = true) ||
                ex.message!!.contains("CRL", ignoreCase = true) ||
                ex.message!!.contains("Revocation", ignoreCase = true),
        )
    }

    @Test
    fun checkRevocation_throwsCertificateRevokedException_whenCrlExplicitlyRevokes() = runTest {
        val handler = FakeOcspHandler(
            throwOnPrepare = RuntimeException("OCSP failed"),
            crlUrl = "http://crl.example.com/crl.crl",
            throwOnValidateCrl = CertificateRevokedException("Certificate found in CRL"),
        )
        assertFailsWith<CertificateRevokedException> {
            buildChecker(handler).checkRevocation(certDer, issuerDer)
        }
    }

    @Test
    fun checkRevocation_downloadsNewCrl_forDifferentUrls() = runTest {
        val certA = ByteArray(32) { 0x01 }
        val certB = ByteArray(32) { 0x02 }
        val issuerA = ByteArray(32) { 0x0A }
        val issuerB = ByteArray(32) { 0x0B }

        var callCount = 0
        val handler = object : FakeOcspHandler(throwOnPrepare = RuntimeException("OCSP down")) {
            override fun extractCrlUrl(certDer: ByteArray): String {
                callCount++
                return if (certDer.contentEquals(certA)) {
                    "http://crl.example.com/a.crl"
                } else {
                    "http://crl.example.com/b.crl"
                }
            }
        }

        val checker = buildChecker(handler)
        checker.checkRevocation(certA, issuerA)
        checker.checkRevocation(certB, issuerB)

        val crlDownloads = capturedRequests.count { it.method == "GET" }
        assertEquals(
            2, crlDownloads,
            "Two distinct CRL URLs should each be downloaded once",
        )
    }

    @Test
    fun close_doesNotThrow_whenCalled() {
        buildChecker().close()
    }
}
