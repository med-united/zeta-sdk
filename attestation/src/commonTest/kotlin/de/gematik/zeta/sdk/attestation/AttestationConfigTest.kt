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

package de.gematik.zeta.sdk.attestation

import de.gematik.zeta.sdk.attestation.model.AttestationConfig
import de.gematik.zeta.sdk.attestation.model.AttestationStatus
import de.gematik.zeta.sdk.attestation.model.AttestationStatusCallback
import de.gematik.zeta.sdk.attestation.model.AttestationType
import de.gematik.zeta.sdk.network.http.client.ZetaHttpClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class AttestationConfigTest {
    private fun buildZetaHttpClient(): ZetaHttpClient =
        ZetaHttpClient(HttpClient(MockEngine { respond("", HttpStatusCode.OK) }))

    private val fakeService = AttestationService { _ ->
        AttestationResponse(tpmQuote = "quote", attestationKey = "ak", certificateChain = emptyList())
    }

    @Test
    fun software_factory_returnsSoftwareInstance() {
        assertIs<AttestationConfig.Software>(AttestationConfig.software())
    }

    @Test
    fun software_type_isSoftware() {
        assertEquals(AttestationType.SOFTWARE, AttestationConfig.software().type)
    }

    @Test
    fun software_statusCallback_isNull() {
        assertNull(AttestationConfig.software().statusCallback)
    }

    @Test
    fun software_getAttestationService_returnsNull() {
        assertNull(AttestationConfig.software().getAttestationService(buildZetaHttpClient()))
    }

    @Test
    fun software_factory_returnsSameInstance_onMultipleCalls() {
        assertSame(AttestationConfig.software(), AttestationConfig.software())
    }

    @Test
    fun tpmHttp_factory_returnsTpmHttpInstance() {
        assertIs<AttestationConfig.TpmHttp>(AttestationConfig.tpmHttp("https://tpm.example.com"))
    }

    @Test
    fun tpmHttp_type_isTpm2() {
        assertEquals(AttestationType.TPM2, AttestationConfig.tpmHttp("https://tpm.example.com").type)
    }

    @Test
    fun tpmHttp_attestationEndpoint_isSetCorrectly() {
        val config = AttestationConfig.tpmHttp("https://tpm.example.com") as AttestationConfig.TpmHttp

        assertEquals("https://tpm.example.com", config.attestationEndpoint)
    }

    @Test
    fun tpmHttp_pcrSelection_defaultsToListOf23() {
        val config = AttestationConfig.tpmHttp("https://tpm.example.com") as AttestationConfig.TpmHttp

        assertEquals(listOf(23), config.pcrSelection)
    }

    @Test
    fun tpmHttp_pcrSelection_isSetCorrectly_whenProvided() {
        val config = AttestationConfig.tpmHttp(
            attestationEndpoint = "https://tpm.example.com",
            pcrSelection = listOf(0, 1, 7),
        ) as AttestationConfig.TpmHttp

        assertEquals(listOf(0, 1, 7), config.pcrSelection)
    }

    @Test
    fun tpmHttp_websocketEndpoint_isNull_byDefault() {
        val config = AttestationConfig.tpmHttp("https://tpm.example.com") as AttestationConfig.TpmHttp

        assertNull(config.websocketEndpoint)
    }

    @Test
    fun tpmHttp_websocketEndpoint_isSetCorrectly_whenProvided() {
        val config = AttestationConfig.tpmHttp(
            attestationEndpoint = "https://tpm.example.com",
            websocketEndpoint = "wss://tpm.example.com/ws",
        ) as AttestationConfig.TpmHttp

        assertEquals("wss://tpm.example.com/ws", config.websocketEndpoint)
    }

    @Test
    fun tpmHttp_statusCallback_isNull_byDefault() {
        assertNull(AttestationConfig.tpmHttp("https://tpm.example.com").statusCallback)
    }

    @Test
    fun tpmHttp_statusCallback_isSetCorrectly_whenProvided() {
        val callback = AttestationStatusCallback { }
        val config = AttestationConfig.tpmHttp(
            attestationEndpoint = "https://tpm.example.com",
            statusCallback = callback,
        )

        assertSame(callback, config.statusCallback)
    }

    @Test
    fun tpmHttp_getAttestationService_returnsNonNull() {
        val config = AttestationConfig.tpmHttp("https://tpm.example.com")
        assertNotNull(config.getAttestationService(buildZetaHttpClient()))
    }

    @Test
    fun tpmHttp_getAttestationService_returnsNewInstance_onEachCall() {
        val config = AttestationConfig.tpmHttp("https://tpm.example.com")
        val client = buildZetaHttpClient()
        val service1 = config.getAttestationService(client)
        val service2 = config.getAttestationService(client)

        assertTrue(service1 !== service2)
    }

    @Test
    fun tpmCustom_factory_returnsTpmCustomInstance() {
        assertIs<AttestationConfig.TpmCustom>(AttestationConfig.tpmCustom(fakeService))
    }

    @Test
    fun tpmCustom_type_isTpm2() {
        assertEquals(AttestationType.TPM2, AttestationConfig.tpmCustom(fakeService).type)
    }

    @Test
    fun tpmCustom_statusCallback_isNull_byDefault() {
        assertNull(AttestationConfig.tpmCustom(fakeService).statusCallback)
    }

    @Test
    fun tpmCustom_statusCallback_isSetCorrectly_whenProvided() {
        val callback = AttestationStatusCallback { }
        val config = AttestationConfig.tpmCustom(fakeService, statusCallback = callback)

        assertSame(callback, config.statusCallback)
    }

    @Test
    fun tpmCustom_getAttestationService_returnsInjectedService() {
        val config = AttestationConfig.tpmCustom(fakeService)
        val result = config.getAttestationService(buildZetaHttpClient())

        assertSame(fakeService, result)
    }

    @Test
    fun tpmCustom_getAttestationService_returnsSameInstance_onMultipleCalls() {
        val config = AttestationConfig.tpmCustom(fakeService)
        val client = buildZetaHttpClient()

        assertSame(config.getAttestationService(client), config.getAttestationService(client))
    }

    @Test
    fun attestationStatusCallback_receivesOkStatus() {
        val received = mutableListOf<AttestationStatus>()
        val callback = AttestationStatusCallback { received.add(it) }
        callback.onStatusChange(AttestationStatus.OK)

        assertEquals(listOf(AttestationStatus.OK), received.toList())
    }

    @Test
    fun attestationStatusCallback_receivesDegradedStatus_withReason() {
        val received = mutableListOf<AttestationStatus>()
        val callback = AttestationStatusCallback { received.add(it) }
        callback.onStatusChange(AttestationStatus.Degraded("corrupted file"))
        val status = received.first()

        assertIs<AttestationStatus.Degraded>(status)
        assertEquals("corrupted file", status.reason)
    }

    @Test
    fun attestationStatusCallback_receivesKoStatus_withReason() {
        val received = mutableListOf<AttestationStatus>()
        val callback = AttestationStatusCallback { received.add(it) }
        callback.onStatusChange(AttestationStatus.KO("failure"))
        val status = received.first()

        assertIs<AttestationStatus.KO>(status)
        assertEquals("failure", status.reason)
    }

    @Test
    fun attestationStatus_ok_equalsSelf() {
        assertEquals(AttestationStatus.OK, AttestationStatus.OK)
    }

    @Test
    fun attestationStatus_degraded_equalsOtherWithSameReason() {
        assertEquals(AttestationStatus.Degraded("x"), AttestationStatus.Degraded("x"))
    }

    @Test
    fun attestationStatus_degraded_notEqualsOtherWithDifferentReason() {
        assertTrue(AttestationStatus.Degraded("a") != AttestationStatus.Degraded("b"))
    }

    @Test
    fun attestationStatus_ko_equalsOtherWithSameReason() {
        assertEquals(AttestationStatus.KO("err"), AttestationStatus.KO("err"))
    }

    @Test
    fun attestationStatus_ko_notEqualsOtherWithDifferentReason() {
        assertTrue(AttestationStatus.KO("a") != AttestationStatus.KO("b"))
    }
}
