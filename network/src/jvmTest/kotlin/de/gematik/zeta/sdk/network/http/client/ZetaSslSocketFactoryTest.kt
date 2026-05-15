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

import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaCipherSuites
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaSignatureAlgorithms
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaTlsCurves
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaTlsProtocols
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.BeforeClass
import java.math.BigInteger
import java.net.InetAddress
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.HandshakeCompletedEvent
import javax.net.ssl.HandshakeCompletedListener
import javax.net.ssl.SSLException
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ZetaSslSocketFactoryTest {
    companion object {
        @BeforeClass
        @JvmStatic
        fun setupBouncyCastle() {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }
    }

    private val validEnabledSuites: Array<String> =
        (ZetaCipherSuites.REQUIRED_TLS_1_2 + ZetaCipherSuites.TLS_1_3_SUITES).toTypedArray()

    private fun buildFactory(delegate: SSLSocketFactory = mockk()) =
        ZetaSslSocketFactory(delegate)

    private fun buildMockSocket(
        params: SSLParameters = SSLParameters(),
        supportedProtocols: Array<String> = ZetaTlsProtocols.ALLOWED.toTypedArray(),
        supportedCipherSuites: Array<String> = ZetaCipherSuites.FULL_PREFERRED_ORDER_IANA.toTypedArray(),
        enabledCipherSuites: Array<String> = validEnabledSuites,
    ): SSLSocket = mockk<SSLSocket>(relaxed = true).also { socket ->
        every { socket.sslParameters } returns params
        every { socket.sslParameters = any() } just Runs
        every { socket.supportedProtocols } returns supportedProtocols
        every { socket.supportedCipherSuites } returns supportedCipherSuites
        every { socket.enabledCipherSuites } returns enabledCipherSuites
        every { socket.addHandshakeCompletedListener(any()) } just Runs
    }

    private fun buildMockDelegate(socket: SSLSocket): SSLSocketFactory =
        mockk<SSLSocketFactory>().also { d ->
            every { d.createSocket(any<Socket>(), any<String>(), any<Int>(), any<Boolean>()) } returns socket
            every { d.createSocket(any<String>(), any<Int>()) } returns socket
            every { d.createSocket(any<InetAddress>(), any<Int>()) } returns socket
            every { d.createSocket(any<String>(), any<Int>(), any<InetAddress>(), any<Int>()) } returns socket
            every { d.createSocket(any<InetAddress>(), any<Int>(), any<InetAddress>(), any<Int>()) } returns socket
        }
    private val caKeyPair by lazy {
        KeyPairGenerator.getInstance("EC", "BC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
    }
    private val caName = X500Name("CN=Test CA")
    private val caSigner by lazy {
        JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC").build(caKeyPair.private)
    }
    private val now = java.util.Date()
    private fun buildValidX509Cert(): X509Certificate {
        val oneYear = java.util.Date(now.time + 365L * 24 * 60 * 60 * 1000)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                caName, BigInteger.ONE, now, oneYear,
                X500Name("CN=Valid Leaf"), caKeyPair.public,
            )
                .addExtension(
                    Extension.subjectAlternativeName, false,
                    GeneralNames(arrayOf(GeneralName(GeneralName.dNSName, "valid.example.com"))),
                )
                .build(caSigner),
        )
    }

    private fun buildExpiredX509Cert(): X509Certificate {
        val pastStart = java.util.Date(now.time - 2 * 86_400_000L)
        val pastEnd = java.util.Date(now.time - 86_400_000L)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                caName, BigInteger.TWO, pastStart, pastEnd,
                X500Name("CN=Expired Leaf"), caKeyPair.public,
            ).build(caSigner),
        )
    }

    private fun captureHandshakeListener(mockSocket: SSLSocket = buildMockSocket()): HandshakeCompletedListener {
        val slot = slot<HandshakeCompletedListener>()
        every { mockSocket.addHandshakeCompletedListener(capture(slot)) } just Runs
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        return slot.captured
    }

    private fun buildHandshakeEvent(
        cert: X509Certificate? = null,
        peerHost: String = "valid.example.com",
        eventSocket: SSLSocket = mockk(relaxed = true),
    ): HandshakeCompletedEvent {
        val session = mockk<SSLSession>()
        every { session.cipherSuite } returns "TLS_AES_128_GCM_SHA256"
        every { session.protocol } returns "TLSv1.3"
        every { session.peerHost } returns peerHost
        every { session.peerCertificates } returns
            if (cert != null) arrayOf(cert) else emptyArray()

        val event = HandshakeCompletedEvent(eventSocket, session)
        return event
    }

    @Test
    fun getDefaultCipherSuites_returnsFullIanaList() {
        assertContentEquals(
            ZetaCipherSuites.FULL_PREFERRED_ORDER_IANA.toTypedArray(),
            buildFactory().getDefaultCipherSuites(),
        )
    }

    @Test
    fun getDefaultCipherSuites_containsAllRequiredTls12Suites() {
        val result = buildFactory().getDefaultCipherSuites().toSet()
        val tls13 = ZetaCipherSuites.TLS_1_3_SUITES.toSet()
        val requiredTls12Iana = ZetaCipherSuites.FULL_PREFERRED_ORDER_IANA.filterNot { it in tls13 }

        requiredTls12Iana.forEach { assertTrue(it in result, "Missing: $it") }
    }

    @Test
    fun getDefaultCipherSuites_containsAllTls13Suites() {
        val result = buildFactory().getDefaultCipherSuites().toSet()
        ZetaCipherSuites.TLS_1_3_SUITES.forEach { assertTrue(it in result, "Missing: $it") }
    }

    @Test
    fun getDefaultCipherSuites_sizeMatchesFullPreferredOrder() {
        assertEquals(ZetaCipherSuites.FULL_PREFERRED_ORDER_IANA.size, buildFactory().getDefaultCipherSuites().size)
    }

    @Test
    fun getSupportedCipherSuites_returnsFullIanaList() {
        assertContentEquals(
            ZetaCipherSuites.FULL_PREFERRED_ORDER_IANA.toTypedArray(),
            buildFactory().getSupportedCipherSuites(),
        )
    }

    @Test
    fun getSupportedCipherSuites_matchesGetDefaultCipherSuites() {
        val factory = buildFactory()
        assertContentEquals(factory.getDefaultCipherSuites(), factory.getSupportedCipherSuites())
    }

    @Test
    fun createSocket_socketHostPortAutoClose_returnsConfiguredSocket() {
        val mockSocket = buildMockSocket()
        val result = buildFactory(buildMockDelegate(mockSocket))
            .createSocket(mockk<Socket>(relaxed = true), "host", 443, true)
        assertNotNull(result)
        verify { mockSocket.addHandshakeCompletedListener(any()) }
    }

    @Test
    fun createSocket_hostPort_returnsConfiguredSocket() {
        val mockSocket = buildMockSocket()
        val result = buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        assertNotNull(result)
        verify { mockSocket.addHandshakeCompletedListener(any()) }
    }

    @Test
    fun createSocket_inetAddressPort_returnsConfiguredSocket() {
        val mockSocket = buildMockSocket()
        val result = buildFactory(buildMockDelegate(mockSocket))
            .createSocket(InetAddress.getLoopbackAddress(), 443)
        assertNotNull(result)
        verify { mockSocket.addHandshakeCompletedListener(any()) }
    }

    @Test
    fun createSocket_hostPortLocalHostLocalPort_returnsConfiguredSocket() {
        val mockSocket = buildMockSocket()
        val result = buildFactory(buildMockDelegate(mockSocket))
            .createSocket("host", 443, InetAddress.getLoopbackAddress(), 0)
        assertNotNull(result)
        verify { mockSocket.addHandshakeCompletedListener(any()) }
    }

    @Test
    fun createSocket_addressPortLocalAddressLocalPort_returnsConfiguredSocket() {
        val mockSocket = buildMockSocket()
        val result = buildFactory(buildMockDelegate(mockSocket))
            .createSocket(InetAddress.getLoopbackAddress(), 443, InetAddress.getLoopbackAddress(), 0)
        assertNotNull(result)
        verify { mockSocket.addHandshakeCompletedListener(any()) }
    }

    @Test
    fun configure_setsAllowedProtocols_filteredBySupportedProtocols() {
        val params = SSLParameters()
        val mockSocket = buildMockSocket(
            params = params,
            supportedProtocols = arrayOf("TLSv1.2", "TLSv1.1", "SSLv3"),
        )
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        assertTrue("TLSv1.2" in params.protocols)
        assertFalse("TLSv1.1" in params.protocols)
        assertFalse("SSLv3" in params.protocols)
    }

    @Test
    fun configure_setsBothAllowedProtocols_whenBothSupported() {
        val params = SSLParameters()
        val mockSocket = buildMockSocket(
            params = params,
            supportedProtocols = arrayOf("TLSv1.2", "TLSv1.3"),
        )
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        assertTrue("TLSv1.2" in params.protocols)
        assertTrue("TLSv1.3" in params.protocols)
    }

    @Test
    fun configure_setsEmptyProtocols_whenNoSupportedProtocolsAllowed() {
        val params = SSLParameters()
        val mockSocket = buildMockSocket(
            params = params,
            supportedProtocols = arrayOf("SSLv2", "SSLv3"),
        )
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        assertTrue(params.protocols.isEmpty())
    }

    @Test
    fun configure_excludesForbiddenProtocols_evenIfSupported() {
        val params = SSLParameters()
        val mockSocket = buildMockSocket(
            params = params,
            supportedProtocols = arrayOf("TLSv1.2", "TLSv1", "TLSv1.1"),
        )
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        assertFalse("TLSv1" in params.protocols)
        assertFalse("TLSv1.1" in params.protocols)
    }

    @Test
    fun configure_setsOnlyAllowedCipherSuites_filteredBySupportedSuites() {
        val params = SSLParameters()
        val ianaName = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"

        val mockSocket = buildMockSocket(
            params = params,
            supportedCipherSuites = arrayOf(ianaName, "TLS_UNSUPPORTED_CIPHER"),
        )
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        assertTrue(ianaName in params.cipherSuites)
        assertFalse("TLS_UNSUPPORTED_CIPHER" in params.cipherSuites)
    }

    @Test
    fun configure_setsEmptyCipherSuites_whenNoneSupported() {
        val params = SSLParameters()
        val mockSocket = buildMockSocket(params = params, supportedCipherSuites = arrayOf("TLS_NONE"))
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        assertTrue(params.cipherSuites.isEmpty())
    }

    @Test
    fun configure_setsAllSuites_whenAllAreSupported() {
        val params = SSLParameters()
        val mockSocket = buildMockSocket(
            params = params,
            supportedCipherSuites = ZetaCipherSuites.FULL_PREFERRED_ORDER_IANA.toTypedArray(),
        )
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        assertEquals(ZetaCipherSuites.FULL_PREFERRED_ORDER_IANA.size, params.cipherSuites.size)
    }

    @Test
    fun configure_setsAllAllowedNamedGroups_onSslParameters() {
        val params = SSLParameters()
        val mockSocket = buildMockSocket(params = params)
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        assertContentEquals(ZetaTlsCurves.ALLOWED.toTypedArray(), params.namedGroups)
    }

    @Test
    fun configure_namedGroupsContainP256() {
        val params = SSLParameters()
        val mockSocket = buildMockSocket(params = params)
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        assertTrue(ZetaTlsCurves.P256 in requireNotNull(params.namedGroups).toList())
    }

    @Test
    fun configure_setsAllowedSignatureSchemes_always() {
        val params = SSLParameters()
        val mockSocket = buildMockSocket(params = params)
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)

        assertContentEquals(ZetaSignatureAlgorithms.ALLOWED.toTypedArray(), params.signatureSchemes)
    }

    @Test
    fun configure_overridesExistingSignatureSchemes_withAllowedList() {
        val params = SSLParameters()
        params.signatureSchemes = arrayOf("rsa_pss_rsae_sha256")
        val mockSocket = buildMockSocket(params = params)
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)

        assertContentEquals(ZetaSignatureAlgorithms.ALLOWED.toTypedArray(), params.signatureSchemes)
    }

    @Test
    fun configure_addsExactlyOneHandshakeListener_perSocket() {
        val mockSocket = buildMockSocket()
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        verify(exactly = 1) { mockSocket.addHandshakeCompletedListener(any()) }
    }

    @Test
    fun configure_addsHandshakeListener_toEachNewSocket() {
        val socket1 = buildMockSocket()
        val socket2 = buildMockSocket()
        var callCount = 0
        val delegate = mockk<SSLSocketFactory>()
        every { delegate.createSocket(any<String>(), any<Int>()) } answers {
            if (callCount++ == 0) socket1 else socket2
        }
        val factory = buildFactory(delegate)

        factory.createSocket("host", 443)
        factory.createSocket("host", 443)

        verify(exactly = 1) { socket1.addHandshakeCompletedListener(any()) }
        verify(exactly = 1) { socket2.addHandshakeCompletedListener(any()) }
    }

    @Test
    fun configure_throwsSSLException_whenEnabledCipherSuitesIsEmpty() {
        val mockSocket = buildMockSocket(enabledCipherSuites = emptyArray())

        assertFailsWith<SSLException> {
            buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        }
    }

    @Test
    fun configure_throwsSSLException_whenRequiredTls12SuitesMissing() {
        val mockSocket = buildMockSocket(
            enabledCipherSuites = arrayOf(ZetaCipherSuites.AES_128_GCM_SHA256),
        )
        assertFailsWith<SSLException> {
            buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        }
    }

    @Test
    fun configure_sslExceptionMessage_containsComplianceText() {
        val mockSocket = buildMockSocket(enabledCipherSuites = emptyArray())
        val ex = assertFailsWith<SSLException> {
            buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        }
        assertTrue(
            ex.message?.contains("gematik") == true || ex.message?.contains("compliance") == true,
            "SSLException message should reference compliance: ${ex.message}",
        )
    }

    @Test
    fun configure_doesNotThrow_whenAllRequiredSuitesPresent() {
        val mockSocket = buildMockSocket(enabledCipherSuites = validEnabledSuites)
        buildFactory(buildMockDelegate(mockSocket)).createSocket("host", 443)
        verify { mockSocket.addHandshakeCompletedListener(any()) }
    }

    @Test
    fun configure_throwsSSLException_forAllCreateSocketOverloads_whenValidationFails() {
        fun factory() = buildFactory(buildMockDelegate(buildMockSocket(enabledCipherSuites = emptyArray())))

        assertFailsWith<SSLException> { factory().createSocket(mockk<Socket>(relaxed = true), "h", 443, true) }
        assertFailsWith<SSLException> { factory().createSocket("host", 443) }
        assertFailsWith<SSLException> { factory().createSocket(InetAddress.getLoopbackAddress(), 443) }
        assertFailsWith<SSLException> { factory().createSocket("host", 443, InetAddress.getLoopbackAddress(), 0) }
        assertFailsWith<SSLException> {
            factory().createSocket(InetAddress.getLoopbackAddress(), 443, InetAddress.getLoopbackAddress(), 0)
        }
    }

    @Test
    fun onHandshakeCompleted_doesNotCloseSocket_whenPeerCertificatesIsEmpty() {
        val listener = captureHandshakeListener()
        val eventSocket = mockk<SSLSocket>(relaxed = true)

        listener.handshakeCompleted(buildHandshakeEvent(cert = null, eventSocket = eventSocket))

        verify(exactly = 0) { eventSocket.close() }
    }

    @Test
    fun onHandshakeCompleted_doesNotCloseSocket_whenCertValidationPasses() {
        val listener = captureHandshakeListener()
        val eventSocket = mockk<SSLSocket>(relaxed = true)

        listener.handshakeCompleted(buildHandshakeEvent(cert = buildValidX509Cert(), eventSocket = eventSocket))

        verify(exactly = 0) { eventSocket.close() }
    }

    @Test
    fun onHandshakeCompleted_closesSocket_whenCertIsExpired() {
        val listener = captureHandshakeListener()
        val eventSocket = mockk<SSLSocket>(relaxed = true)

        listener.handshakeCompleted(buildHandshakeEvent(cert = buildExpiredX509Cert(), eventSocket = eventSocket))

        verify(exactly = 1) { eventSocket.close() }
    }

    @Test
    fun onHandshakeCompleted_closesSocket_whenCertHasForbiddenSigAlg() {
        val sha1KeyPair = KeyPairGenerator.getInstance("EC", "BC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val sha1Signer = JcaContentSignerBuilder("SHA1WithECDSA").setProvider("BC").build(sha1KeyPair.private)
        val oneYear = java.util.Date(now.time + 365L * 24 * 60 * 60 * 1000)
        val weakCert = JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(3), now, oneYear,
                X500Name("CN=Weak Cert"), sha1KeyPair.public,
            ).build(sha1Signer),
        )
        val listener = captureHandshakeListener()
        val eventSocket = mockk<SSLSocket>(relaxed = true)

        listener.handshakeCompleted(buildHandshakeEvent(cert = weakCert, eventSocket = eventSocket))

        verify(exactly = 1) { eventSocket.close() }
    }

    @Test
    fun onHandshakeCompleted_closesSocket_onlyOnce_whenCertIsInvalid() {
        val listener = captureHandshakeListener()
        val eventSocket = mockk<SSLSocket>(relaxed = true)

        listener.handshakeCompleted(buildHandshakeEvent(cert = buildExpiredX509Cert(), eventSocket = eventSocket))

        verify(exactly = 1) { eventSocket.close() }
    }

    @Test
    fun onHandshakeCompleted_doesNotThrow_whenSocketCloseFailsDuringInvalidCert() {
        val listener = captureHandshakeListener()
        val eventSocket = mockk<SSLSocket>(relaxed = true)
        every { eventSocket.close() } throws RuntimeException("already closed")

        listener.handshakeCompleted(buildHandshakeEvent(cert = buildExpiredX509Cert(), eventSocket = eventSocket))

        verify(exactly = 1) { eventSocket.close() }
    }

    @Test
    fun onHandshakeCompleted_eachSocketGetsItsOwnListener_independentBehavior() {
        val socket1 = buildMockSocket()
        val socket2 = buildMockSocket()
        val slot1 = slot<HandshakeCompletedListener>()
        val slot2 = slot<HandshakeCompletedListener>()
        every { socket1.addHandshakeCompletedListener(capture(slot1)) } just Runs
        every { socket2.addHandshakeCompletedListener(capture(slot2)) } just Runs

        var callCount = 0
        val delegate = mockk<SSLSocketFactory>()
        every { delegate.createSocket(any<String>(), any<Int>()) } answers {
            if (callCount++ == 0) socket1 else socket2
        }
        val factory = buildFactory(delegate)
        factory.createSocket("host", 443)
        factory.createSocket("host", 443)

        val eventSocket1 = mockk<SSLSocket>(relaxed = true)
        val eventSocket2 = mockk<SSLSocket>(relaxed = true)

        slot1.captured.handshakeCompleted(buildHandshakeEvent(cert = buildExpiredX509Cert(), eventSocket = eventSocket1))
        slot2.captured.handshakeCompleted(buildHandshakeEvent(cert = buildValidX509Cert(), eventSocket = eventSocket2))

        verify(exactly = 1) { eventSocket1.close() }
        verify(exactly = 0) { eventSocket2.close() }
    }
}
