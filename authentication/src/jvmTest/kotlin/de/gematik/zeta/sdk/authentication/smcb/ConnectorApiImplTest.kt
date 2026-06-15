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

package de.gematik.zeta.sdk.authentication.smcb

import de.gematik.zeta.sdk.authentication.smcb.model.ExternalAuthenticateResponse
import de.gematik.zeta.sdk.authentication.smcb.model.ReadCardCertificateResponse
import de.gematik.zeta.sdk.authentication.smcb.model.decodeFromSoap
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.http.takeFrom
import io.ktor.serialization.kotlinx.xml.xml
import kotlinx.coroutines.test.runTest
import nl.adaptivity.xmlutil.serialization.XML
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ConnectorApiImplTest {
    data class CapturedRequest(
        val method: String,
        val url: String,
        val headers: Headers,
        val body: String,
        val contentType: ContentType?,
    )

    private val captured = mutableListOf<CapturedRequest>()

    @BeforeTest
    fun setUp() { captured.clear() }

    private val last get() = captured.last()
    private val baseUrl = "http://connector.example.com/"
    private val cardHandle = "card-handle-001"
    private val mandantId = "mandant-001"
    private val clientSysId = "client-sys-001"
    private val workspaceId = "workspace-001"
    private val userId = "user-001"
    private val base64Chall = "dGVzdC1jaGFsbGVuZ2U="

    private val config = SmcbTokenProvider.ConnectorConfig(
        baseUrl = baseUrl,
        mandantId = mandantId,
        clientSystemId = clientSysId,
        workspaceId = workspaceId,
        userId = userId,
        cardHandle = cardHandle,
    )

    private val xml = XML { indentString = ""; autoPolymorphic = false }

    private val readCertSoapResponse = """
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP-ENV:Header/>
            <SOAP-ENV:Body>
                <CERT:ReadCardCertificateResponse xmlns:CERT="http://ws.gematik.de/conn/CertificateService/v6.0">
                    <CONN:Status xmlns:CONN="http://ws.gematik.de/conn/ConnectorCommon/v5.0">
                        <CONN:Result>OK</CONN:Result>
                    </CONN:Status>
                    <CERTCMN:X509DataInfoList xmlns:CERTCMN="http://ws.gematik.de/conn/CertificateServiceCommon/v2.0">
                        <CERTCMN:X509DataInfo>
                            <CERTCMN:CertRef>C.AUT</CERTCMN:CertRef>
                            <CERTCMN:X509Data>
                                <CERTCMN:X509IssuerSerial>
                                    <CERTCMN:X509IssuerName>CN=Test</CERTCMN:X509IssuerName>
                                    <CERTCMN:X509SerialNumber>123</CERTCMN:X509SerialNumber>
                                </CERTCMN:X509IssuerSerial>
                                <CERTCMN:X509SubjectName>CN=Subject</CERTCMN:X509SubjectName>
                                <CERTCMN:X509Certificate>dGVzdENlcnQ=</CERTCMN:X509Certificate>
                            </CERTCMN:X509Data>
                        </CERTCMN:X509DataInfo>
                    </CERTCMN:X509DataInfoList>
                </CERT:ReadCardCertificateResponse>
            </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>
    """.trimIndent()

    private val externalAuthSoapResponse = """
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP-ENV:Header/>
            <SOAP-ENV:Body>
                <SIG:ExternalAuthenticateResponse xmlns:SIG="http://ws.gematik.de/conn/SignatureService/v7.4">
                    <CONN:Status xmlns:CONN="http://ws.gematik.de/conn/ConnectorCommon/v5.0">
                        <CONN:Result>OK</CONN:Result>
                    </CONN:Status>
                    <DSS:SignatureObject xmlns:DSS="urn:oasis:names:tc:dss:1.0:core:schema">
                        <DSS:Base64Signature>c2lnbmF0dXJl</DSS:Base64Signature>
                    </DSS:SignatureObject>
                </SIG:ExternalAuthenticateResponse>
            </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>
    """.trimIndent()

    private fun soapFault(faultCode: String, faultString: String) = """
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP-ENV:Header/>
            <SOAP-ENV:Body>
                <SOAP-ENV:Fault>
                    <faultcode>$faultCode</faultcode>
                    <faultstring>$faultString</faultstring>
                </SOAP-ENV:Fault>
            </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>
    """.trimIndent()

    private fun buildApi(responseBody: String): ConnectorApiImpl {
        val engine = MockEngine { request ->
            captured += CapturedRequest(
                method = request.method.value,
                url = request.url.toString(),
                headers = request.headers,
                body = request.body.toByteArray().decodeToString(),
                contentType = request.body.contentType,
            )
            respond(
                content = responseBody,
                status = HttpStatusCode.OK,
                headers = headersOf("Content-Type", ContentType.Text.Xml.toString()),
            )
        }
        val mockClient = HttpClient(engine) {
            install(DefaultRequest) { url { takeFrom(baseUrl) } }
            install(ContentNegotiation) { xml() }
        }
        return ConnectorApiImpl(config, httpClientFactory = { _ -> mockClient })
    }

    @Test
    fun readCertificate_usesPostMethod() = runTest {
        buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertEquals("POST", last.method)
    }

    @Test
    fun readCertificate_targetsCorrectEndpoint() = runTest {
        buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertTrue(last.url.endsWith("CertificateService"), "Expected CertificateService endpoint, got: ${last.url}")
    }

    @Test
    fun readCertificate_setsXmlContentType() = runTest {
        buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)

        assertEquals(ContentType.Text.Xml, last.contentType?.withoutParameters())
    }

    @Test
    fun readCertificate_setsCorrectSoapAction() = runTest {
        buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertEquals("ReadCardCertificate", last.headers["SOAPAction"])
    }

    @Test
    fun readCertificate_includesCardHandleInBody() = runTest {
        buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertTrue(last.body.contains(cardHandle))
    }

    @Test
    fun readCertificate_includesMandantIdInBody() = runTest {
        buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertTrue(last.body.contains(mandantId))
    }

    @Test
    fun readCertificate_includesCAutCertRefInBody() = runTest {
        buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertTrue(last.body.contains("C.AUT"))
    }

    @Test
    fun readCertificate_includesClientSystemIdInBody_whenProvided() = runTest {
        buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertTrue(last.body.contains(clientSysId))
    }

    @Test
    fun readCertificate_includesWorkspaceIdInBody_whenProvided() = runTest {
        buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertTrue(last.body.contains(workspaceId))
    }

    @Test
    fun readCertificate_sendsWellFormedSoapBody_whenOptionalContextFieldsAreNull() = runTest {
        buildApi(readCertSoapResponse).readCertificate(
            cardHandle, mandantId,
            clientSystemId = null,
            workspaceId = null,
            userId = null,
        )
        assertTrue(last.body.contains(cardHandle))
        assertTrue(last.body.contains(mandantId))
    }

    // ── readCertificate — response parsing ────────────────────────────────────

    @Test
    fun readCertificate_returnsNonNullResponse() = runTest {
        val response = buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertNotNull(response)
    }

    @Test
    fun readCertificate_returnsStatusOk() = runTest {
        val response = buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertEquals("OK", response.status.result)
    }

    @Test
    fun readCertificate_returnsCertificateInResponse() = runTest {
        val response = buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        assertTrue(response.x509DataInfoList.x509DataInfo.isNotEmpty())
        assertEquals("dGVzdENlcnQ=", response.x509DataInfoList.x509DataInfo[0].x509Data.x509Certificate)
    }

    @Test
    fun readCertificate_throwsConnectorError_whenServerReturnsSoapFault() = runTest {
        val error = assertFailsWith<ConnectorError> {
            buildApi(soapFault("SOAP-ENV:Server", "Card not found"))
                .readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        }
        assertEquals("SOAP-ENV:Server", error.faultCode)
        assertEquals("Card not found", error.faultString)
    }

    @Test
    fun externalAuthenticate_usesPostMethod() = runTest {
        buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        assertEquals("POST", last.method)
    }

    @Test
    fun externalAuthenticate_targetsCorrectEndpoint() = runTest {
        buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        assertTrue(last.url.endsWith("AuthSignatureService"), "Expected AuthSignatureService endpoint, got: ${last.url}")
    }

    @Test
    fun externalAuthenticate_setsXmlContentType() = runTest {
        buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)

        assertEquals(ContentType.Text.Xml, last.contentType?.withoutParameters())
    }

    @Test
    fun externalAuthenticate_setsCorrectSoapAction() = runTest {
        buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        assertEquals("ExternalAuthenticate", last.headers["SOAPAction"])
    }

    @Test
    fun externalAuthenticate_includesCardHandleInBody() = runTest {
        buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        assertTrue(last.body.contains(cardHandle))
    }

    @Test
    fun externalAuthenticate_includesMandantIdInBody() = runTest {
        buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        assertTrue(last.body.contains(mandantId))
    }

    @Test
    fun externalAuthenticate_includesChallengeInBody() = runTest {
        buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        assertTrue(last.body.contains(base64Chall))
    }

    @Test
    fun externalAuthenticate_includesEcdsaAlgorithmUriInBody() = runTest {
        buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        assertTrue(last.body.contains("urn:bsi:tr:03111:ecdsa"))
    }

    @Test
    fun externalAuthenticate_sendsWellFormedSoapBody_whenOptionalContextFieldsAreNull() = runTest {
        buildApi(externalAuthSoapResponse).externalAuthenticate(
            cardHandle, mandantId,
            clientSystemId = null,
            workspaceId = null,
            userId = null,
            base64Challenge = base64Chall,
        )
        assertTrue(last.body.contains(cardHandle))
        assertTrue(last.body.contains(base64Chall))
    }

    // ── externalAuthenticate — response parsing ───────────────────────────────

    @Test
    fun externalAuthenticate_returnsNonNullResponse() = runTest {
        val response = buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        assertNotNull(response)
    }

    @Test
    fun externalAuthenticate_returnsStatusOk() = runTest {
        val response = buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        assertEquals("OK", response.status.result)
    }

    @Test
    fun externalAuthenticate_returnsSignatureInResponse() = runTest {
        val response = buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        assertNotNull(response.signatureObject)
        assertEquals("c2lnbmF0dXJl", response.signatureObject.base64Signature)
    }

    @Test
    fun externalAuthenticate_throwsConnectorError_whenServerReturnsSoapFault() = runTest {
        val error = assertFailsWith<ConnectorError> {
            buildApi(soapFault("SOAP-ENV:Client", "Invalid request"))
                .externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        }
        assertEquals("SOAP-ENV:Client", error.faultCode)
        assertEquals("Invalid request", error.faultString)
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Endpoint isolation
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    fun readCertificate_andExternalAuthenticate_useDifferentEndpoints() = runTest {
        buildApi(readCertSoapResponse).readCertificate(cardHandle, mandantId, clientSysId, workspaceId, userId)
        val certUrl = last.url

        buildApi(externalAuthSoapResponse).externalAuthenticate(cardHandle, mandantId, clientSysId, workspaceId, userId, base64Chall)
        val authUrl = last.url

        assertTrue(certUrl.endsWith("CertificateService"))
        assertTrue(authUrl.endsWith("AuthSignatureService"))
    }

    // ═════════════════════════════════════════════════════════════════════════
    // SOAP fault deserialization (unit — no HTTP)
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    fun decodeFromSoap_throwsConnectorError_withServerFaultCode() {
        val error = assertFailsWith<ConnectorError> {
            soapFault("SOAP-ENV:Server", "Card not found")
                .decodeFromSoap(ReadCardCertificateResponse.serializer(), xml)
        }
        assertEquals("SOAP-ENV:Server", error.faultCode)
        assertEquals("Card not found", error.faultString)
    }

    @Test
    fun decodeFromSoap_throwsConnectorError_withClientFaultCode() {
        val error = assertFailsWith<ConnectorError> {
            soapFault("SOAP-ENV:Client", "Invalid request")
                .decodeFromSoap(ExternalAuthenticateResponse.serializer(), xml)
        }
        assertEquals("SOAP-ENV:Client", error.faultCode)
        assertEquals("Invalid request", error.faultString)
    }

    @Test
    fun decodeFromSoap_connectorErrorMessage_containsFaultCodeAndFaultString() {
        val error = assertFailsWith<ConnectorError> {
            soapFault("SOAP-ENV:Client", "Invalid request")
                .decodeFromSoap(ExternalAuthenticateResponse.serializer(), xml)
        }
        assertTrue(error.message?.contains("SOAP-ENV:Client") == true)
        assertTrue(error.message?.contains("Invalid request") == true)
    }
}
