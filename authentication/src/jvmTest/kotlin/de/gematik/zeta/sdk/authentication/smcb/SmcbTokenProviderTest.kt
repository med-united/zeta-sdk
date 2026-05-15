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

import Jwk
import PublicKeyOut
import de.gematik.zeta.sdk.authentication.smcb.model.ExternalAuthenticateResponse
import de.gematik.zeta.sdk.authentication.smcb.model.ReadCardCertificateResponse
import de.gematik.zeta.sdk.authentication.smcb.model.SignatureObject
import de.gematik.zeta.sdk.authentication.smcb.model.Status
import de.gematik.zeta.sdk.authentication.smcb.model.X509Data
import de.gematik.zeta.sdk.authentication.smcb.model.X509DataInfo
import de.gematik.zeta.sdk.authentication.smcb.model.X509DataInfoList
import de.gematik.zeta.sdk.authentication.smcb.model.X509IssuerSerial
import de.gematik.zeta.sdk.authentication.toBase64
import de.gematik.zeta.sdk.crypto.hashWithSha256
import de.gematik.zeta.sdk.tpm.TpmProvider
import derEcdsaToJose
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import joseToDerEcdsa
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.encoding.Base64
import kotlin.io.encoding.Base64.PaddingOption
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

class SmcbTokenProviderTest {
    private val tpmProvider = mockk<TpmProvider>()
    private val connectorApi = mockk<ConnectorApi>()

    private val config = SmcbTokenProvider.ConnectorConfig(
        baseUrl = "baseUrl",
        mandantId = "mandantId",
        clientSystemId = "clientSystemId",
        workspaceId = "workspaceId",
        userId = "userId",
        cardHandle = "cardHandle",
    )

    private val provider = SmcbTokenProvider(
        connectorConfig = config,
        connectorApi = connectorApi,
    )

    private val fixedUuid = Uuid.parseHexDash("45efb7f8-ef00-4ec7-9df8-545dec602dc8")
    private val fixedNow = 1762779601L
    private val fixedExpiration = 30L
    private val fixedCertificate = "certificate".toByteArray()
    private val fixedSignature = joseToDerEcdsa("signature exactly 32 byte length".toByteArray())
    private val fixedKid = "someKid"
    private val expectedChallenge = "dBVkMwlvdFOW2e0b4JEu2ASIl3akBrO0xMh5gMSg9ws"

    private fun stubTpm(
        uuid: Uuid = fixedUuid,
        regNumber: String = "regNumber",
        kid: String = fixedKid,
        cert: ByteArray = fixedCertificate,
    ) {
        val mockJwk = mockk<Jwk>()
        val mockKey = mockk<PublicKeyOut>()
        coEvery { mockJwk.kid } returns kid
        coEvery { mockKey.jwk } returns mockJwk
        coEvery { tpmProvider.randomUuid() } returns uuid
        coEvery { tpmProvider.getRegistrationNumber(cert) } returns regNumber
        coEvery { tpmProvider.getOrGenerateClientInstancePublicKey() } returns mockKey
    }

    private fun stubConnector(
        certificate: ByteArray = fixedCertificate,
        signature: ByteArray = fixedSignature,
        challenge: String = expectedChallenge,
    ) {
        coEvery {
            connectorApi.readCertificate(
                config.cardHandle, config.mandantId,
                config.clientSystemId, config.workspaceId, config.userId,
            )
        } returns buildReadCertResponse(certificate)

        coEvery {
            connectorApi.externalAuthenticate(
                config.cardHandle, config.mandantId,
                config.clientSystemId, config.workspaceId, config.userId,
                challenge,
            )
        } returns buildExternalAuthResponse(signature)
    }

    private fun buildReadCertResponse(certificate: ByteArray) = ReadCardCertificateResponse(
        Status("OK"),
        X509DataInfoList(
            listOf(
                X509DataInfo("", X509Data(X509IssuerSerial("", ""), "", certificate.toBase64(true, false))),
            ),
        ),
    )

    private fun buildExternalAuthResponse(signature: ByteArray) = ExternalAuthenticateResponse(
        Status("OK"),
        SignatureObject(signature.toBase64(true, true)),
    )

    private fun createToken(
        clientId: String = "clientId",
        dpopKey: String = "",
        nonce: ByteArray = "nonce".toByteArray(),
        audience: String = "audience",
        now: Long = fixedNow,
        expiration: Long = fixedExpiration,
    ): String = runBlocking {
        provider.createSubjectToken(clientId, dpopKey, nonce, audience, now, expiration, tpmProvider)
    }

    /** Decodes a base64url segment of a JWT into a JSON object. */
    private fun decodeJwtPart(b64: String) =
        Json.parseToJsonElement(
            Base64.UrlSafe.withPadding(PaddingOption.ABSENT).decode(b64).decodeToString(),
        ).jsonObject

    @Test
    fun createSubjectToken_returnsExpectedToken_withFixedInputs() = runTest {
        stubTpm()
        stubConnector()

        val expectedPayload = "eyJ0eXAiOiJKV1QiLCJraWQiOiJBOVp0MElnMXdjb19Fb3pPck5IekdzbEJZd2xySVBSRnJvUW9XOENETFhJIiwieDVjIjpbIlkyVnlkR2xtYVdOaGRHVT0iXSwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJjbGllbnRJZCIsImV4cCI6MTc2Mjc3OTYzMSwiYXVkIjpbImF1ZGllbmNlIl0sInN1YiI6InJlZ051bWJlciIsImlhdCI6MTc2Mjc3OTYwMSwibm9uY2UiOiJibTl1WTJVIiwianRpIjoiNDVlZmI3ZjgtZWYwMC00ZWM3LTlkZjgtNTQ1ZGVjNjAyZGM4IiwidHlwIjoiQmVhcmVyIiwiY2xpZW50X2tleSI6eyJqa3QiOiJzb21lS2lkIn0sImRwb3Bfa2V5Ijp7ImprdCI6IiJ9fQ"
        val token = createToken()

        assertEquals(
            "$expectedPayload.${derEcdsaToJose(fixedSignature).toBase64(false, false)}",
            token,
        )
    }

    @Test
    fun createSubjectToken_returnsJwtWithThreeParts() = runTest {
        stubTpm(); stubConnector()
        assertEquals(3, createToken().split(".").size)
    }

    @Test
    fun createSubjectToken_headerContainsAlgES256() = runTest {
        stubTpm(); stubConnector()
        val header = decodeJwtPart(createToken().split(".")[0])
        assertEquals("ES256", header["alg"]?.jsonPrimitive?.content)
    }

    @Test
    fun createSubjectToken_headerContainsTypJwt() = runTest {
        stubTpm(); stubConnector()
        val header = decodeJwtPart(createToken().split(".")[0])
        assertEquals("JWT", header["typ"]?.jsonPrimitive?.content)
    }

    @Test
    fun createSubjectToken_headerKidIsCertificateHash() = runTest {
        stubTpm(); stubConnector()
        val expectedKid = Base64.UrlSafe.withPadding(PaddingOption.ABSENT)
            .encode(hashWithSha256(fixedCertificate))
        val header = decodeJwtPart(createToken().split(".")[0])
        assertEquals(expectedKid, header["kid"]?.jsonPrimitive?.content)
    }

    @Test
    fun createSubjectToken_headerX5cContainsBase64EncodedCert() = runTest {
        stubTpm(); stubConnector()
        val header = decodeJwtPart(createToken().split(".")[0])
        val x5c = header["x5c"]?.jsonArray?.first()?.jsonPrimitive?.content
        assertEquals(Base64.encode(fixedCertificate), x5c)
    }

    @Test
    fun createSubjectToken_payloadIatEqualsNow() = runTest {
        stubTpm(); stubConnector()
        val payload = decodeJwtPart(createToken(now = fixedNow).split(".")[1])
        assertEquals(fixedNow.toString(), payload["iat"]?.jsonPrimitive?.content)
    }

    @Test
    fun createSubjectToken_payloadJtiIsUuid() = runTest {
        stubTpm(); stubConnector()
        val payload = decodeJwtPart(createToken().split(".")[1])
        assertEquals(fixedUuid.toString(), payload["jti"]?.jsonPrimitive?.content)
    }

    @Test
    fun createSubjectToken_payloadTypIsBearer() = runTest {
        stubTpm(); stubConnector()
        val payload = decodeJwtPart(createToken().split(".")[1])
        assertEquals("Bearer", payload["typ"]?.jsonPrimitive?.content)
    }

    @Test
    fun createSubjectToken_callsReadCertificate_withAllConfigValues() = runTest {
        stubTpm(); stubConnector()
        createToken()
        coVerify {
            connectorApi.readCertificate(
                config.cardHandle, config.mandantId,
                config.clientSystemId, config.workspaceId, config.userId,
            )
        }
    }

    @Test
    fun createSubjectToken_callsExternalAuthenticate_withAllConfigValues() = runTest {
        stubTpm(); stubConnector()
        createToken()
        coVerify {
            connectorApi.externalAuthenticate(
                config.cardHandle, config.mandantId,
                config.clientSystemId, config.workspaceId, config.userId,
                any(),
            )
        }
    }

    @Test
    fun createSubjectToken_passesHashedTokenAsChallenge_toExternalAuthenticate() = runTest {
        stubTpm(); stubConnector()
        createToken()
        coVerify {
            connectorApi.externalAuthenticate(
                any(), any(), any(), any(), any(),
                expectedChallenge,
            )
        }
    }

    @Test
    fun createSubjectToken_throwsException_whenReadCertificateThrows() = runTest {
        stubTpm()
        coEvery { connectorApi.readCertificate(any(), any(), any(), any(), any()) } throws
            ConnectorError("SOAP-ENV:Server", "Card error", "Card not found")

        assertFailsWith<ConnectorError> {
            createToken()
        }
    }

    @Test
    fun createSubjectToken_throwsException_whenExternalAuthenticateThrows() = runTest {
        stubTpm()
        coEvery { connectorApi.readCertificate(any(), any(), any(), any(), any()) } returns
            buildReadCertResponse(fixedCertificate)
        coEvery { connectorApi.externalAuthenticate(any(), any(), any(), any(), any(), any()) } throws
            ConnectorError("SOAP-ENV:Server", "Sign error", "Signing failed")

        assertFailsWith<ConnectorError> {
            createToken()
        }
    }

    @Test
    fun createSubjectToken_returnsNonNullToken_whenSuccessful() = runTest {
        stubTpm(); stubConnector()
        assertNotNull(createToken())
    }

    @Test
    fun createReadCertificateResponse_buildsResponseWithCorrectCertificate() {
        val cert = "test-cert".toByteArray()
        val response = buildReadCertResponse(cert)
        assertEquals("OK", response.status.result)
        val encodedCert = response.x509DataInfoList.x509DataInfo.first().x509Data.x509Certificate
        assertTrue(encodedCert.isNotEmpty())
        assertTrue(Base64.decode(encodedCert).contentEquals(cert))
    }

    @Test
    fun createExternalAuthenticateResponse_buildsResponseWithCorrectSignature() {
        val sig = "test-sig".toByteArray()
        val response = buildExternalAuthResponse(sig)
        assertEquals("OK", response.status.result)
        assertTrue(response.signatureObject.base64Signature.isNotEmpty())
    }
}
