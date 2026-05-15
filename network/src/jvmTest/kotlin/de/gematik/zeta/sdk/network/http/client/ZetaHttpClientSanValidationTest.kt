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

import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.test.runTest
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import java.net.InetAddress
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ZetaHttpClientSanValidationTest {
    private fun buildClientTrustingRoot(
        root: HeldCertificate,
    ): ZetaHttpClient {
        val clientCerts = HandshakeCertificates.Builder()
            .addTrustedCertificate(root.certificate)
            .build()
        val okClient = OkHttpClient.Builder()
            .sslSocketFactory(clientCerts.sslSocketFactory(), clientCerts.trustManager)
            .dns { hostname ->
                if (hostname == "zeta-staging.spree.de") {
                    listOf(InetAddress.getByName("127.0.0.1"))
                } else {
                    Dns.SYSTEM.lookup(hostname)
                }
            }
            .build()
        return ZetaHttpClient(
            io.ktor.client.HttpClient(io.ktor.client.engine.okhttp.OkHttp) {
                engine { preconfigured = okClient }
            },
        )
    }

    private fun buildClientWithHandshakeProbe(
        root: HeldCertificate,
        targetHost: String,
        onIntercepted: () -> Unit,
    ): ZetaHttpClient {
        val clientCerts = HandshakeCertificates.Builder()
            .addTrustedCertificate(root.certificate)
            .build()
        val okClient = OkHttpClient.Builder()
            .sslSocketFactory(clientCerts.sslSocketFactory(), clientCerts.trustManager)
            .dns { hostname ->
                if (hostname == targetHost) {
                    listOf(InetAddress.getByName("127.0.0.1"))
                } else {
                    Dns.SYSTEM.lookup(hostname)
                }
            }
            .addNetworkInterceptor { chain ->
                onIntercepted()
                chain.proceed(chain.request())
            }
            .build()
        return ZetaHttpClient(
            io.ktor.client.HttpClient(io.ktor.client.engine.okhttp.OkHttp) {
                engine { preconfigured = okClient }
            },
        )
    }

    private fun startTlsServerWithSan(cn: String, san: String): Pair<MockWebServer, HeldCertificate> {
        val root = HeldCertificate.Builder().certificateAuthority(1).build()
        val serverCert = HeldCertificate.Builder()
            .signedBy(root)
            .commonName(cn)
            .addSubjectAlternativeName(san)
            .build()
        val serverHandshake = HandshakeCertificates.Builder()
            .heldCertificate(serverCert, root.certificate)
            .build()
        val server = MockWebServer().apply {
            useHttps(serverHandshake.sslSocketFactory(), false)
            enqueue(MockResponse().setResponseCode(200).setBody("ok"))
            start(InetAddress.getByName("127.0.0.1"), 0)
        }
        return server to root
    }

    private fun Throwable.findSslPeerUnverified(): javax.net.ssl.SSLPeerUnverifiedException? =
        generateSequence(this) { it.cause }
            .filterIsInstance<javax.net.ssl.SSLPeerUnverifiedException>()
            .firstOrNull()

    @Test
    fun sanWrongCnWrong_handshakeMustFail() = runTest {
        val (server, root) = startTlsServerWithSan(cn = "other.de", san = "other.de")
        val client = buildClientTrustingRoot(root)

        val ex = assertFailsWith<Throwable> {
            client.get("https://zeta-staging.spree.de:${server.port}/test")
        }
        val sslEx = ex.findSslPeerUnverified()

        assertNotNull(sslEx, "Expected SSLPeerUnverifiedException in cause chain, got: ${ex::class.qualifiedName}")
        assertEquals(sslEx.message?.contains("zeta-staging.spree.de"), true)
        assertEquals(sslEx.message?.contains("other.de"), true)

        server.shutdown()
    }

    @Test
    @Ignore // NOSONAR ignored until the test requirement is clarified
    fun sanWrongCnMatch_handshakeMustSucceed() = runTest {
        val (server, root) = startTlsServerWithSan(cn = "zeta-staging.spree.de", san = "other.de")
        val client = buildClientTrustingRoot(root)

        val response = client.get("https://zeta-staging.spree.de:${server.port}/test")

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("ok", response.bodyAsText())

        server.shutdown()
    }

    @Test
    fun sanMatchCnWrong_handshakeMustSucceed() = runTest {
        val (server, root) = startTlsServerWithSan(cn = "other.de", san = "zeta-staging.spree.de")
        val client = buildClientTrustingRoot(root)

        val response = client.get("https://zeta-staging.spree.de:${server.port}/test")

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("ok", response.bodyAsText())

        server.shutdown()
    }

    @Test
    fun sanMatchCnMatch_handshakeMustSucceed() = runTest {
        val (server, root) = startTlsServerWithSan(cn = "zeta-staging.spree.de", san = "zeta-staging.spree.de")
        val client = buildClientTrustingRoot(root)

        val response = client.get("https://zeta-staging.spree.de:${server.port}/test")

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("ok", response.bodyAsText())

        server.shutdown()
    }

    @Test
    fun sanWrongCnWrong_failureHappensAtHandshake_notAfter() = runTest {
        val (server, root) = startTlsServerWithSan(cn = "other.de", san = "other.de")
        var handshakeCompleted = false
        val client = buildClientWithHandshakeProbe(root, "zeta-staging.spree.de") {
            handshakeCompleted = true
        }

        val ex = assertFailsWith<Throwable> {
            client.get("https://zeta-staging.spree.de:${server.port}/test")
        }

        assertFalse(handshakeCompleted)
        assertEquals(0, server.requestCount)
        assertNotNull(ex.findSslPeerUnverified())

        server.shutdown()
    }

    @Test
    fun sanMatchCnWrong_handshakeCompletes_requestReachesServer() = runTest {
        val (server, root) = startTlsServerWithSan(cn = "other.de", san = "zeta-staging.spree.de")
        var handshakeCompleted = false
        val client = buildClientWithHandshakeProbe(root, "zeta-staging.spree.de") {
            handshakeCompleted = true
        }

        val response = client.get("https://zeta-staging.spree.de:${server.port}/test")

        assertTrue(handshakeCompleted)
        assertEquals(1, server.requestCount)
        assertEquals(HttpStatusCode.OK, response.status)

        server.shutdown()
    }
}
