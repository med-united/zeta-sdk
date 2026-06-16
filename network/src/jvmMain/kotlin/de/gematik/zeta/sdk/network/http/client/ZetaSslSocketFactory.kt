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

import de.gematik.zeta.logging.Log
import de.gematik.zeta.sdk.crypto.OcspHandler
import de.gematik.zeta.sdk.crypto.OcspHandlerImpl
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaCertificateValidator
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaCipherSuites
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaSignatureAlgorithms
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaTlsCurves
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaTlsProtocols
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaTlsValidator
import de.gematik.zeta.sdk.network.http.client.config.tls.sanMatchesHost
import de.gematik.zeta.sdk.network.http.client.config.tls.toZetaCertInfo
import io.ktor.client.HttpClient
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x509.GeneralName
import java.net.InetAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.HandshakeCompletedEvent
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

internal class ZetaSslSocketFactory(
    private val delegate: SSLSocketFactory,
    private val trustManager: X509TrustManager,
    private val onStaple: (ByteArray?) -> Unit = {},
    private val ocspHandler: OcspHandler = OcspHandlerImpl(),
    private val allowSkipForTestCertificates: Boolean = false,
    private val httpClient: HttpClient = HttpClient(),
) : SSLSocketFactory() {

    @Volatile
    var lastStaple: ByteArray? = null
    override fun getDefaultCipherSuites(): Array<String> =
        ZetaCipherSuites.FULL_PREFERRED_ORDER_IANA.toTypedArray()

    override fun getSupportedCipherSuites(): Array<String> =
        ZetaCipherSuites.FULL_PREFERRED_ORDER_IANA.toTypedArray()

    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket =
        (delegate.createSocket(s, host, port, autoClose) as SSLSocket).also(::configure)

    override fun createSocket(host: String, port: Int): Socket =
        (delegate.createSocket(host, port) as SSLSocket).also(::configure)

    override fun createSocket(host: InetAddress, port: Int): Socket =
        (delegate.createSocket(host, port) as SSLSocket).also(::configure)

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        (delegate.createSocket(host, port, localHost, localPort) as SSLSocket).also(::configure)

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
        (delegate.createSocket(address, port, localAddress, localPort) as SSLSocket).also(::configure)

    fun findIssuer(cert: X509Certificate): X509Certificate? {
        return trustManager.acceptedIssuers.firstOrNull { ca ->
            runCatching { cert.verify(ca.publicKey) }.isSuccess
        }
    }

    private fun configure(socket: SSLSocket) {
        val params = socket.sslParameters
        params.protocols = ZetaTlsProtocols.ALLOWED
            .filter { it in socket.supportedProtocols }
            .toTypedArray()

        params.cipherSuites = ZetaCipherSuites.FULL_PREFERRED_ORDER_IANA
            .filter { it in socket.supportedCipherSuites }
            .toTypedArray()

        params.namedGroups = ZetaTlsCurves.ALLOWED.toTypedArray()

        params.signatureSchemes = ZetaSignatureAlgorithms.ALLOWED.toTypedArray()

        socket.sslParameters = params

        socket.addHandshakeCompletedListener(::onHandshakeCompleted)

        Log.i {
            "ZetaTls: socket configured: " +
                "protocols=${params.protocols.toList()}, " +
                "ciphers=${params.cipherSuites.toList()}, " +
                "curves=${params.namedGroups?.toList()}, " +
                "signatures=${params.signatureSchemes?.toList()}"
        }

        val result = ZetaTlsValidator.validateEnabledCipherSuites(socket.enabledCipherSuites.toList())
        if (!result.isCompliant) {
            Log.e { "ZetaTls: cipher suite validation FAILED: ${result.errors}" }
            throw SSLException("gematik TLS cipher suite compliance failure: ${result.errors}")
        }
        result.warnings.forEach { Log.w { "ZetaTls: $it" } }
    }

    private fun onHandshakeCompleted(event: HandshakeCompletedEvent) {
        val session = event.session
        val x509 = session.peerCertificates.firstOrNull() as? X509Certificate ?: return

        lastStaple = extractStapleFromSocket(event.socket)
        onStaple(lastStaple)

        val peerHost = session.peerHost
        val sanDnsNames = x509.subjectAlternativeNames
            ?.filter { it[0] == GeneralName.dNSName }
            ?.map { it[1] as String }
            ?: emptyList()

        if (sanDnsNames.isEmpty()) {
            Log.e { "ZetaTls: certificate has no SAN entries for host=$peerHost — rejecting" }
            runCatching { event.socket.close() }
            return
        }

        val sanValid = sanDnsNames.any { san -> sanMatchesHost(san, peerHost) }
        if (!sanValid) {
            Log.e { "ZetaTls: SAN mismatch: host=$peerHost SANs=$sanDnsNames" }
            runCatching { event.socket.close() }
            return
        }

        Log.i { "ZetaTls: SAN validated: host=$peerHost matched in $sanDnsNames" }

        val certResult = ZetaCertificateValidator.validate(
            cert = x509.toZetaCertInfo(),
            nowEpochSeconds = System.currentTimeMillis() / 1000,
        )
        if (!certResult.isValid) {
            Log.e { "ZetaTls: cert validation FAILED: ${certResult.errors}" }
            runCatching { event.socket.close() }
            return
        }

        val chain = session.peerCertificates
        val issuer: X509Certificate? = if (chain.size >= 2) {
            chain[1] as? X509Certificate
        } else {
            Log.i { "OCSP JVM: TLS 1.3, looking up issuer in trust store" }
            findIssuer(x509)
        }

        if (issuer == null) {
            Log.e { "OCSP JVM: issuer not found, rejecting" }
            runCatching { event.socket.close() }
            return
        }

        Log.i { "OCSP JVM: running revocation check staple=${lastStaple?.size} bytes" }
        runCatching {
            runBlocking {
                validateRevocation(
                    stapledOcspResponse = lastStaple,
                    certDer = x509.encoded,
                    issuerDer = issuer.encoded,
                    ocspValidator = ocspHandler,
                    allowSkipForTestCertificates = allowSkipForTestCertificates,
                    httpClient = httpClient,
                )
            }
        }.onFailure {
            Log.e { "OCSP JVM: revocation check FAILED: ${it.message}" }
            runCatching { event.socket.close() }
            return
        }

        Log.i { "OCSP JVM: revocation check passed" }
    }

    private fun extractStapleFromSocket(socket: SSLSocket): ByteArray? {
        val session = socket.session
        Log.i { "OCSP JVM: session type=${session::class.simpleName}" }
        if (session !is ExtendedSSLSession) {
            Log.w { "OCSP JVM: not ExtendedSSLSession" }
            return null
        }
        val statusResponses = session.statusResponses
        Log.i { "OCSP JVM: statusResponses count=${statusResponses?.size}" }
        if (statusResponses.isNullOrEmpty()) {
            Log.w { "OCSP JVM: no staple" }
            return null
        }
        Log.i { "OCSP JVM: staple extracted ${statusResponses[0].size} bytes" }
        return statusResponses[0]
    }
}
