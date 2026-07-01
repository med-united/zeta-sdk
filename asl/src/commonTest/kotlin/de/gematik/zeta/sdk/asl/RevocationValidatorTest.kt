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

import de.gematik.zeta.sdk.crypto.OcspHandler
import de.gematik.zeta.sdk.crypto.OcspRequestData
import de.gematik.zeta.sdk.network.http.client.validateRevocation
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Clock

class RevocationValidatorTest {
    private val nowEpoch = Clock.System.now().epochSeconds
    private val certDer = byteArrayOf(1, 2, 3)
    private val issuerDer = byteArrayOf(4, 5, 6)
    private val ocspResponseBytes = byteArrayOf(7, 8, 9)

    @Test
    fun validateRevocation_fallsBackToCrl_whenDirectOcspFails() = runTest {
        val validator = FakeOcspHandler(
            validateThrows = Exception("OCSP failed"),
        )

        validateRevocation(
            stapledOcspResponse = null,
            certDer = certDer,
            issuerDer = issuerDer,
            ocspValidator = validator,
            httpClient = mockHttpClient(),
            allowSkipForTestCertificates = false,
        )
    }

    @Test
    fun validateRevocation_fails_whenCrlFetchFails() = runTest {
        val validator = FakeOcspHandler(
            validateThrows = Exception("OCSP failed"),
            crlUrl = "https://crl.example.com",
        )

        assertFailsWith<IllegalStateException> {
            validateRevocation(
                stapledOcspResponse = null,
                certDer = certDer,
                issuerDer = issuerDer,
                ocspValidator = validator,
                httpClient = mockHttpClient(throws = true),
                allowSkipForTestCertificates = false,
            )
        }
    }

    @Test
    fun validateRevocation_fails_whenStapledOcspTooOld() = runTest {
        val tooOld = nowEpoch - (25 * 3600)
        val validator = FakeOcspHandler(
            producedAt = tooOld,
            nextUpdate = null,
        )
        assertFailsWith<IllegalArgumentException> {
            validateRevocation(
                stapledOcspResponse = ocspResponseBytes,
                certDer = certDer,
                issuerDer = issuerDer,
                ocspValidator = validator,
                httpClient = mockHttpClient(),
                allowSkipForTestCertificates = false,
            )
        }
    }

    @Test
    fun validateRevocation_acceptsStaleStaple_whenNextUpdateInFuture() = runTest {
        val producedAt = nowEpoch - (3 * 24 * 3600)
        val nextUpdate = nowEpoch + (4 * 24 * 3600)
        val validator = FakeOcspHandler(
            producedAt = producedAt,
            nextUpdate = nextUpdate,
        )

        validateRevocation(
            stapledOcspResponse = ocspResponseBytes,
            certDer = certDer,
            issuerDer = issuerDer,
            ocspValidator = validator,
            httpClient = mockHttpClient(),
            allowSkipForTestCertificates = false,
        )
    }

    @Test
    fun validateRevocation_rejectsStaple_whenNextUpdateExpired() = runTest {
        val nextUpdate = nowEpoch - 3600
        val validator = FakeOcspHandler(
            producedAt = nowEpoch - (8 * 24 * 3600),
            nextUpdate = nextUpdate,
        )

        assertFailsWith<IllegalArgumentException> {
            validateRevocation(
                stapledOcspResponse = ocspResponseBytes,
                certDer = certDer,
                issuerDer = issuerDer,
                ocspValidator = validator,
                httpClient = mockHttpClient(),
                allowSkipForTestCertificates = false,
            )
        }
    }

    @Test
    fun validateRevocation_fallsBackTo24H_whenNextUpdateAbsent() = runTest {
        val validator = FakeOcspHandler(
            producedAt = nowEpoch - 3600,
            nextUpdate = null,
        )
        validateRevocation(
            stapledOcspResponse = ocspResponseBytes,
            certDer = certDer,
            issuerDer = issuerDer,
            ocspValidator = validator,
            httpClient = mockHttpClient(),
            allowSkipForTestCertificates = false,
        )
    }

    @Test
    fun validateRevocation_rejects_whenNextUpdateAbsentAndOlderThan24H() = runTest {
        val validator = FakeOcspHandler(
            producedAt = nowEpoch - (25 * 3600),
            nextUpdate = null,
        )

        assertFailsWith<IllegalArgumentException> {
            validateRevocation(
                stapledOcspResponse = ocspResponseBytes,
                certDer = certDer,
                issuerDer = issuerDer,
                ocspValidator = validator,
                httpClient = mockHttpClient(),
                allowSkipForTestCertificates = false,
            )
        }
    }

    @Test
    fun validateRevocation_usesStagledOcsp_whenAvailable() = runTest {
        val validator = FakeOcspHandler(
            producedAt = nowEpoch,
            nextUpdate = nowEpoch + 3600,
        )
        validateRevocation(
            stapledOcspResponse = ocspResponseBytes,
            certDer = certDer,
            issuerDer = issuerDer,
            ocspValidator = validator,
            httpClient = mockHttpClient(),
            allowSkipForTestCertificates = false,
        )
    }

    @Test
    fun validateRevocation_fails_whenStapledOcspValidationFails() = runTest {
        val validator = FakeOcspHandler(
            producedAt = nowEpoch,
            validateThrows = Exception("Certificate revoked"),
        )
        assertFailsWith<Exception> {
            validateRevocation(
                stapledOcspResponse = ocspResponseBytes,
                certDer = certDer,
                issuerDer = issuerDer,
                ocspValidator = validator,
                httpClient = mockHttpClient(),
                allowSkipForTestCertificates = false,
            )
        }
    }

    @Test
    fun validateRevocation_succeedsViaDirectOcsp_whenNoStapling() = runTest {
        val validator = FakeOcspHandler(producedAt = nowEpoch)
        validateRevocation(
            stapledOcspResponse = null,
            certDer = certDer,
            issuerDer = issuerDer,
            ocspValidator = validator,
            httpClient = mockHttpClient(responseBytes = ocspResponseBytes),
            allowSkipForTestCertificates = false,
        )
    }

    @Test
    fun validateRevocation_fails_whenNoCrlUrlInCertificate() = runTest {
        val validator = FakeOcspHandler(
            validateThrows = Exception("OCSP failed"),
            crlUrl = null,
        )
        assertFailsWith<IllegalStateException> {
            validateRevocation(
                stapledOcspResponse = null,
                certDer = certDer,
                issuerDer = issuerDer,
                ocspValidator = validator,
                httpClient = mockHttpClient(),
                allowSkipForTestCertificates = false,
            )
        }
    }

    @Test
    fun validateRevocation_fails_whenCrlValidationFails() = runTest {
        val validator = FakeOcspHandler(
            validateThrows = Exception("OCSP failed"),
            crlUrl = "https://crl.example.com",
            crlValidateThrows = Exception("CRL invalid"),
        )
        assertFailsWith<IllegalStateException> {
            validateRevocation(
                stapledOcspResponse = null,
                certDer = certDer,
                issuerDer = issuerDer,
                ocspValidator = validator,
                httpClient = mockHttpClient(),
                allowSkipForTestCertificates = false,
            )
        }
    }

    @Test
    fun validateRevocation_skipsCheck_forTestCertificates() = runTest {
        val validator = FakeOcspHandler(
            validateThrows = Exception("OCSP failed"),
            crlUrl = null,
        )
        validateRevocation(
            stapledOcspResponse = null,
            certDer = certDer,
            issuerDer = issuerDer,
            ocspValidator = validator,
            httpClient = mockHttpClient(),
            allowSkipForTestCertificates = true,
        )
    }

    @Test
    fun validateRevocation_errorMessage_containsAllFailureReasons() = runTest {
        val validator = FakeOcspHandler(
            validateThrows = Exception("OCSP failed"),
            crlUrl = "https://crl.example.com",
            crlValidateThrows = Exception("CRL failed"),
        )
        val ex = assertFailsWith<IllegalStateException> {
            validateRevocation(
                stapledOcspResponse = null,
                certDer = certDer,
                issuerDer = issuerDer,
                ocspValidator = validator,
                httpClient = mockHttpClient(),
                allowSkipForTestCertificates = false,
            )
        }
        assertTrue(ex.message!!.contains("OCSP failed"))
        assertTrue(ex.message!!.contains("CRL failed"))
    }

    @Test
    fun validateRevocation_respectsCustomMaxOcspAge() = runTest {
        val oneHourAgo = nowEpoch - 3600
        val validator = FakeOcspHandler(producedAt = oneHourAgo)

        validateRevocation(
            stapledOcspResponse = ocspResponseBytes,
            certDer = certDer,
            issuerDer = issuerDer,
            ocspValidator = validator,
            httpClient = mockHttpClient(),
            maxOcspAgeSeconds = 2 * 3600,
            allowSkipForTestCertificates = false,
        )

        assertFailsWith<IllegalArgumentException> {
            validateRevocation(
                stapledOcspResponse = ocspResponseBytes,
                certDer = certDer,
                issuerDer = issuerDer,
                ocspValidator = validator,
                httpClient = mockHttpClient(),
                maxOcspAgeSeconds = 1800,
                allowSkipForTestCertificates = false,
            )
        }
    }

    private class FakeOcspHandler(
        private val producedAt: Long = Clock.System.now().epochSeconds,
        private val nextUpdate: Long? = null,
        private val validateThrows: Exception? = null,
        private val crlUrl: String? = "https://crl.example.com",
        private val crlValidateThrows: Exception? = null,
    ) : OcspHandler {
        override fun getProducedAtEpochSeconds(ocspResponseDer: ByteArray) = producedAt
        override fun getNextUpdateEpochSeconds(
            ocspResponseDer: ByteArray,
            certDer: ByteArray,
            issuerDer: ByteArray,
        ): Long? = nextUpdate

        override fun validate(ocspResponseDer: ByteArray, certDer: ByteArray, issuerDer: ByteArray) {
            validateThrows?.let { throw it }
        }
        override suspend fun prepareOcspRequest(certDer: ByteArray, issuerDer: ByteArray) =
            OcspRequestData("https://ocsp.example.com", byteArrayOf(1))
        override fun extractCrlUrl(certDer: ByteArray) = crlUrl
        override fun validateCrl(crlDer: ByteArray, certDer: ByteArray, issuerDer: ByteArray) {
            crlValidateThrows?.let { throw it }
        }
    }

    private fun mockHttpClient(
        responseBytes: ByteArray = byteArrayOf(10, 11, 12),
        throws: Boolean = false,
    ): HttpClient {
        val engine = MockEngine { request ->
            if (throws) error("Fetch failed for ${request.url}")
            respond(
                content = responseBytes,
                status = HttpStatusCode.OK,
            )
        }
        return HttpClient(engine)
    }
}
