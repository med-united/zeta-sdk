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
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaCertificateValidator
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaCipherSuites
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaSignatureAlgorithms
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaTlsCurves
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaTlsProtocols
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaTlsValidator
import de.gematik.zeta.sdk.network.http.client.config.tls.sanMatchesHost
import de.gematik.zeta.sdk.network.http.client.config.tls.toZetaCertInfo
import org.bouncycastle.asn1.x509.GeneralName
import java.net.InetAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.HandshakeCompletedEvent
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

internal class ZetaSslSocketFactory(
    private val delegate: SSLSocketFactory,
) : SSLSocketFactory() {

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
}
private fun onHandshakeCompleted(event: HandshakeCompletedEvent) {
    val session = event.session
    val x509 = session.peerCertificates.firstOrNull() as? X509Certificate ?: return

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
    }
}
