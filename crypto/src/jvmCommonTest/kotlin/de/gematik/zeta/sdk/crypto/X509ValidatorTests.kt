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

package de.gematik.zeta.sdk.crypto

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax
import org.bouncycastle.asn1.isismtt.x509.Admissions
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo
import org.bouncycastle.asn1.x500.DirectoryString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@Suppress("FunctionNaming")
class X509CertValidatorTest {
    private val validator = X509CertValidator()
    private val guardOid = "1.2.276.0.76.4.328"

    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private val keyGen = KeyPairGenerator.getInstance("EC", "BC")
        .apply { initialize(ECNamedCurveTable.getParameterSpec("brainpoolP256r1")) }

    private val caKeyPair: KeyPair = keyGen.generateKeyPair()
    private val caSigner = JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC").build(caKeyPair.private)
    private val caName = X500Name("CN=Test CA")
    private val now = Date()
    private val oneYear = Date(now.time + 365L * 24 * 60 * 60 * 1000)

    private val caCert: X509Certificate = JcaX509CertificateConverter().setProvider("BC").getCertificate(
        JcaX509v3CertificateBuilder(caName, BigInteger.ONE, now, oneYear, caName, caKeyPair.public)
            .apply { addExtension(Extension.basicConstraints, true, BasicConstraints(true)) }
            .build(caSigner),
    )
    private val leafKeyPair: KeyPair = keyGen.generateKeyPair()

    fun buildCertWithSan(
        dnsNames: List<String> = emptyList(),
        serial: Long = 100L,
    ): X509Certificate {
        val generalNames = dnsNames
            .map { GeneralName(GeneralName.dNSName, it) }
            .toTypedArray()
        val builder = JcaX509v3CertificateBuilder(
            caName, BigInteger.valueOf(serial), now, oneYear,
            X500Name("CN=SAN Cert"), keyGen.generateKeyPair().public,
        )
        if (generalNames.isNotEmpty()) {
            builder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(generalNames))
        }
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(caSigner))
    }

    private val leafCert: X509Certificate = JcaX509CertificateConverter().setProvider("BC").getCertificate(
        JcaX509v3CertificateBuilder(caName, BigInteger.valueOf(2), now, oneYear, X500Name("CN=Test Leaf"), leafKeyPair.public)
            .apply {
                addExtension(Extension.basicConstraints, false, BasicConstraints(false))
                addExtension(
                    ISISMTTObjectIdentifiers.id_isismtt_at_admission, false,
                    AdmissionSyntax(
                        null,
                        ASN1EncodableVector().apply {
                            add(
                                Admissions(
                                    null,
                                    null,
                                    arrayOf(
                                        ProfessionInfo(
                                            null,
                                            arrayOf(DirectoryString("ZETA Guard")),
                                            arrayOf(ASN1ObjectIdentifier(guardOid)),
                                            null,
                                            null,
                                        ),
                                    ),
                                ),
                            )
                        }.let { DERSequence(it) },
                    ),
                )
            }
            .build(caSigner),
    )

    private val expiredCert: X509Certificate = JcaX509CertificateConverter().setProvider("BC").getCertificate(
        JcaX509v3CertificateBuilder(
            caName, BigInteger.valueOf(3),
            Date(now.time - 2 * 86_400_000),
            Date(now.time - 86_400_000),
            X500Name("CN=Expired Cert"), keyGen.generateKeyPair().public,
        ).build(caSigner),
    )

    @Test
    fun `checkValidity passes for valid certificate`() {
        validator.checkValidity(leafCert.encoded)
    }

    @Test
    fun `checkValidity throws for expired certificate`() {
        assertFailsWith<Exception> {
            validator.checkValidity(expiredCert.encoded)
        }
    }

    @Test
    fun `getPublicKey returns DER-encoded public key matching original`() {
        val result = validator.getPublicKey(leafCert.encoded)
        assertTrue(result.contentEquals(leafKeyPair.public.encoded))
    }

    @Test
    fun `validateCertChain passes for valid chain`() {
        validator.validateCertChain(
            chainDer = listOf(leafCert.encoded),
            trustAnchorsDer = listOf(caCert.encoded),
        )
    }

    @Test
    fun `validateCertChain throws for empty chain`() {
        assertFailsWith<IllegalArgumentException> {
            validator.validateCertChain(
                chainDer = emptyList(),
                trustAnchorsDer = listOf(caCert.encoded),
            )
        }
    }

    @Test
    fun `validateCertChain throws when trust anchor does not match issuer`() {
        val unrelatedCa = JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                X500Name("CN=Unrelated CA"), BigInteger.ONE, now, oneYear,
                X500Name("CN=Unrelated CA"), keyGen.generateKeyPair().public,
            )
                .apply { addExtension(Extension.basicConstraints, true, BasicConstraints(true)) }
                .build(JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC").build(keyGen.generateKeyPair().private)),
        )
        assertFailsWith<Exception> {
            validator.validateCertChain(
                chainDer = listOf(leafCert.encoded),
                trustAnchorsDer = listOf(unrelatedCa.encoded),
            )
        }
    }

    @Test
    fun `validateCertChain throws when chain contains expired certificate`() {
        val expiredLeaf = JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(4),
                Date(now.time - 2 * 86_400_000),
                Date(now.time - 86_400_000),
                X500Name("CN=Expired Leaf"), keyGen.generateKeyPair().public,
            ).build(caSigner),
        )
        assertFailsWith<Exception> {
            validator.validateCertChain(
                chainDer = listOf(expiredLeaf.encoded),
                trustAnchorsDer = listOf(caCert.encoded),
            )
        }
    }

    @Test
    fun checkValidity_passes_forValidCertificate() {
        validator.checkValidity(leafCert.encoded)
    }

    @Test
    fun checkValidity_throws_forExpiredCertificate() {
        assertFailsWith<Exception> {
            validator.checkValidity(expiredCert.encoded)
        }
    }

    @Test
    fun checkValidity_throws_forNotYetValidCertificate() {
        val notYetValid = JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(99),
                Date(now.time + 86_400_000), // starts tomorrow
                Date(now.time + 2 * 86_400_000),
                X500Name("CN=Future Cert"), keyGen.generateKeyPair().public,
            ).build(caSigner),
        )
        assertFailsWith<Exception> {
            validator.checkValidity(notYetValid.encoded)
        }
    }

    @Test
    fun `leaf cert contains admission extension`() {
        val holder = X509CertificateHolder(leafCert.encoded)
        val oids = holder.extensions.extensionOIDs.map { it.id }
        println("Extension OIDs present: $oids")

        assertTrue(oids.contains(ISISMTTObjectIdentifiers.id_isismtt_at_admission.id))
    }

    @Test
    fun `getProfessionOids returns empty list when admission extension is absent`() {
        assertTrue(validator.getProfessionOids(caCert.encoded).isEmpty())
    }

    @Test
    fun getPublicKey_returnsDerEncodedPublicKey_matchingOriginal() {
        val result = validator.getPublicKey(leafCert.encoded)
        assertTrue(result.contentEquals(leafKeyPair.public.encoded))
    }

    @Test
    fun validateCertChain_passes_forValidChain() {
        validator.validateCertChain(
            chainDer = listOf(leafCert.encoded),
            trustAnchorsDer = listOf(caCert.encoded),
        )
    }

    @Test
    fun validateCertChain_throws_forEmptyChain() {
        assertFailsWith<IllegalArgumentException> {
            validator.validateCertChain(
                chainDer = emptyList(),
                trustAnchorsDer = listOf(caCert.encoded),
            )
        }
    }

    @Test
    fun validateCertChain_throws_whenTrustAnchorDoesNotMatchIssuer() {
        val unrelatedKeyPair = keyGen.generateKeyPair()
        val unrelatedCa = JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                X500Name("CN=Unrelated CA"), BigInteger.ONE, now, oneYear,
                X500Name("CN=Unrelated CA"), unrelatedKeyPair.public,
            )
                .apply { addExtension(Extension.basicConstraints, true, BasicConstraints(true)) }
                .build(JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC").build(unrelatedKeyPair.private)),
        )
        assertFailsWith<Exception> {
            validator.validateCertChain(
                chainDer = listOf(leafCert.encoded),
                trustAnchorsDer = listOf(unrelatedCa.encoded),
            )
        }
    }

    @Test
    fun validateCertChain_throws_whenChainContainsExpiredCertificate() {
        val expiredLeaf = JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(4),
                Date(now.time - 2 * 86_400_000),
                Date(now.time - 86_400_000),
                X500Name("CN=Expired Leaf"), keyGen.generateKeyPair().public,
            ).build(caSigner),
        )
        assertFailsWith<Exception> {
            validator.validateCertChain(
                chainDer = listOf(expiredLeaf.encoded),
                trustAnchorsDer = listOf(caCert.encoded),
            )
        }
    }

    @Test
    fun validateCertChain_passes_forTwoLevelChainWithIntermediateCa() {
        val intermediateKeyPair = keyGen.generateKeyPair()
        val intermediateSigner = JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC")
            .build(intermediateKeyPair.private)
        val intermediateName = X500Name("CN=Intermediate CA")
        val intermediateCert = JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(caName, BigInteger.valueOf(10), now, oneYear, intermediateName, intermediateKeyPair.public)
                .apply { addExtension(Extension.basicConstraints, true, BasicConstraints(0)) }
                .build(caSigner),
        )
        val chainLeaf = JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(intermediateName, BigInteger.valueOf(11), now, oneYear, X500Name("CN=Chain Leaf"), keyGen.generateKeyPair().public)
                .apply { addExtension(Extension.basicConstraints, false, BasicConstraints(false)) }
                .build(intermediateSigner),
        )
        validator.validateCertChain(
            chainDer = listOf(chainLeaf.encoded, intermediateCert.encoded),
            trustAnchorsDer = listOf(caCert.encoded),
        )
    }

    @Test
    fun getSanDnsNames_returnsSingleDnsName_whenOneSanPresent() {
        val cert = buildCertWithSan(listOf("zeta-guard.example.com"))
        val result = validator.getSanDnsNames(cert.encoded)

        assertEquals(listOf("zeta-guard.example.com"), result)
    }

    @Test
    fun getSanDnsNames_returnsAllDnsNames_whenMultipleSansPresent() {
        val cert = buildCertWithSan(listOf("zeta-guard.example.com", "*.example.com", "api.example.com"))
        val result = validator.getSanDnsNames(cert.encoded)
        assertEquals(3, result.size)
        assertTrue("zeta-guard.example.com" in result)
        assertTrue("*.example.com" in result)
        assertTrue("api.example.com" in result)
    }

    @Test
    fun getSanDnsNames_returnsEmptyList_whenNoSanExtensionPresent() {
        val result = validator.getSanDnsNames(leafCert.encoded)

        assertTrue(result.isEmpty())
    }

    @Test
    fun getSanDnsNames_returnsEmptyList_forCaCertWithoutSan() {
        val result = validator.getSanDnsNames(caCert.encoded)

        assertTrue(result.isEmpty())
    }

    @Test
    fun getSanDnsNames_returnsWildcardEntry_whenWildcardSanPresent() {
        val cert = buildCertWithSan(listOf("*.example.com"))
        val result = validator.getSanDnsNames(cert.encoded)

        assertEquals(listOf("*.example.com"), result)
    }

    @Test
    fun getSanDnsNames_preservesExactDnsNameCasing() {
        val cert = buildCertWithSan(listOf("Zeta-Guard.Example.COM"))
        val result = validator.getSanDnsNames(cert.encoded)

        assertTrue(result.any { it.equals("Zeta-Guard.Example.COM", ignoreCase = false) })
    }
}
