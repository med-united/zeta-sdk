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

import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaTrustManager
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.BeforeClass
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.net.ssl.SSLException
import javax.net.ssl.X509TrustManager
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ZetaTrustManagerTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setupBouncyCastle() {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }
    }

    private val mockDelegate = mockk<X509TrustManager>(relaxed = true)

    private fun buildManager() = ZetaTrustManager(mockDelegate)

    private val now = Date()
    private val caKeyPair by lazy {
        KeyPairGenerator.getInstance("EC", "BC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
    }
    private val caName = X500Name("CN=Test CA")
    private val caSigner by lazy {
        JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC").build(caKeyPair.private)
    }

    private fun buildValidCert(serial: Long = 1L): X509Certificate {
        val oneYear = Date(now.time + 365L * 24 * 60 * 60 * 1000)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(serial), now, oneYear,
                X500Name("CN=Valid Leaf $serial"), caKeyPair.public,
            ).build(caSigner),
        )
    }

    private fun buildExpiredCert(): X509Certificate {
        val pastStart = Date(now.time - 2 * 86_400_000L)
        val pastEnd = Date(now.time - 86_400_000L)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(2), pastStart, pastEnd,
                X500Name("CN=Expired Leaf"), caKeyPair.public,
            ).build(caSigner),
        )
    }

    private fun buildWeakSigAlgCert(): X509Certificate {
        val sha1KeyPair = KeyPairGenerator.getInstance("EC", "BC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val sha1Signer = JcaContentSignerBuilder("SHA1WithECDSA").setProvider("BC").build(sha1KeyPair.private)
        val oneYear = Date(now.time + 365L * 24 * 60 * 60 * 1000)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(3), now, oneYear,
                X500Name("CN=Weak Sig Leaf"), sha1KeyPair.public,
            ).build(sha1Signer),
        )
    }

    @Test
    fun checkServerTrusted_callsDelegate_whenChainIsValid() {
        val chain = arrayOf(buildValidCert())
        buildManager().checkServerTrusted(chain, "RSA")
        verify { mockDelegate.checkServerTrusted(chain, "RSA") }
    }

    @Test
    fun checkServerTrusted_forwardsExactChainAndAuthType_toDelegate() {
        val chain = arrayOf(buildValidCert())
        val authType = "ECDHE_ECDSA"
        buildManager().checkServerTrusted(chain, authType)
        verify { mockDelegate.checkServerTrusted(chain, authType) }
    }

    @Test
    fun checkServerTrusted_callsDelegate_withMultiCertChain() {
        val chain = arrayOf(buildValidCert(1L), buildValidCert(2L))
        buildManager().checkServerTrusted(chain, "RSA")
        verify { mockDelegate.checkServerTrusted(chain, "RSA") }
    }

    @Test
    fun checkServerTrusted_throwsSSLException_whenCertIsExpired() {
        assertFailsWith<SSLException> {
            buildManager().checkServerTrusted(arrayOf(buildExpiredCert()), "RSA")
        }
    }

    @Test
    fun checkServerTrusted_throwsSSLException_whenCertHasForbiddenSigAlg() {
        assertFailsWith<SSLException> {
            buildManager().checkServerTrusted(arrayOf(buildWeakSigAlgCert()), "RSA")
        }
    }

    @Test
    fun checkServerTrusted_doesNotCallDelegate_whenChainValidationFails() {
        runCatching { buildManager().checkServerTrusted(arrayOf(buildExpiredCert()), "RSA") }
        verify(exactly = 0) { mockDelegate.checkServerTrusted(any(), any()) }
    }

    @Test
    fun checkServerTrusted_sslExceptionMessage_containsGematikPrefix() {
        val ex = assertFailsWith<SSLException> {
            buildManager().checkServerTrusted(arrayOf(buildExpiredCert()), "RSA")
        }

        assertEquals(ex.message?.contains("gematik cert validation failed"), true, "Expected 'gematik cert validation failed' in: ${ex.message}")
    }

    @Test
    fun checkServerTrusted_sslExceptionMessage_containsErrorDetail() {
        val ex = assertFailsWith<SSLException> {
            buildManager().checkServerTrusted(arrayOf(buildExpiredCert()), "RSA")
        }
        val msg = requireNotNull(ex.message)

        assertTrue(msg.length > "gematik cert validation failed: ".length, "Message should include error detail: $msg")
    }

    @Test
    fun checkServerTrusted_propagatesCertificateException_whenDelegateThrows() {
        every { mockDelegate.checkServerTrusted(any(), any()) } throws CertificateException("untrusted root")
        assertFailsWith<CertificateException> {
            buildManager().checkServerTrusted(arrayOf(buildValidCert()), "RSA")
        }
    }

    @Test
    fun checkServerTrusted_propagatesSSLException_whenDelegateThrowsSSLException() {
        every { mockDelegate.checkServerTrusted(any(), any()) } throws SSLException("peer not authenticated")

        assertFailsWith<SSLException> {
            buildManager().checkServerTrusted(arrayOf(buildValidCert()), "RSA")
        }
    }

    @Test
    fun checkClientTrusted_delegatesToDelegate() {
        val chain = arrayOf(buildValidCert())
        buildManager().checkClientTrusted(chain, "RSA")
        verify { mockDelegate.checkClientTrusted(chain, "RSA") }
    }

    @Test
    fun getAcceptedIssuers_delegatesToDelegate() {
        val issuers = arrayOf(buildValidCert())
        every { mockDelegate.acceptedIssuers } returns issuers
        assertContentEquals(issuers, buildManager().acceptedIssuers)
    }

    @Test
    fun getAcceptedIssuers_returnsEmptyArray_whenDelegateReturnsEmpty() {
        every { mockDelegate.acceptedIssuers } returns emptyArray()
        assertTrue(buildManager().acceptedIssuers.isEmpty())
    }
}
