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

import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaCipherSuites
import de.gematik.zeta.sdk.network.http.client.config.tls.ZetaTlsProtocols
import de.gematik.zeta.sdk.network.http.client.config.tls.configureEngine
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import javax.net.ssl.SSLEngine
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ConfigureEngineTest {
    private fun buildMockEngine(
        supportedProtocols: Array<String> = ZetaTlsProtocols.ALLOWED.toTypedArray(),
        supportedCipherSuites: Array<String> = ZetaCipherSuites.FULL_PREFERRED_ORDER.toTypedArray(),
    ): SSLEngine = mockk<SSLEngine>(relaxed = true).also { engine ->
        every { engine.supportedProtocols } returns supportedProtocols
        every { engine.supportedCipherSuites } returns supportedCipherSuites
        every { engine.useClientMode = any() } just Runs
        every { engine.enabledProtocols = any() } just Runs
        every { engine.enabledCipherSuites = any() } just Runs
    }

    @Test
    fun configureEngine_setsClientModeTrue_byDefault() {
        val engine = buildMockEngine()
        configureEngine(engine)
        verify { engine.useClientMode = true }
    }

    @Test
    fun configureEngine_setsClientModeTrue_whenClientModeTrue() {
        val engine = buildMockEngine()
        configureEngine(engine, clientMode = true)
        verify { engine.useClientMode = true }
    }

    @Test
    fun configureEngine_setsClientModeFalse_whenClientModeFalse() {
        val engine = buildMockEngine()
        configureEngine(engine, clientMode = false)
        verify { engine.useClientMode = false }
    }

    @Test
    fun configureEngine_setsAllowedProtocols_filteredBySupportedProtocols() {
        val slot = slot<Array<String>>()
        val engine = buildMockEngine(supportedProtocols = arrayOf("TLSv1.2", "TLSv1.1", "SSLv3"))
        every { engine.enabledProtocols = capture(slot) } just Runs

        configureEngine(engine)

        assertTrue("TLSv1.2" in slot.captured)
        assertFalse("TLSv1.1" in slot.captured)
        assertFalse("SSLv3" in slot.captured)
    }

    @Test
    fun configureEngine_setsBothAllowedProtocols_whenBothSupported() {
        val slot = slot<Array<String>>()
        val engine = buildMockEngine(supportedProtocols = arrayOf("TLSv1.2", "TLSv1.3"))
        every { engine.enabledProtocols = capture(slot) } just Runs

        configureEngine(engine)

        assertTrue("TLSv1.2" in slot.captured)
        assertTrue("TLSv1.3" in slot.captured)
    }

    @Test
    fun configureEngine_setsEmptyProtocols_whenNoSupportedProtocolsAllowed() {
        val slot = slot<Array<String>>()
        val engine = buildMockEngine(supportedProtocols = arrayOf("SSLv2", "SSLv3", "TLSv1"))
        every { engine.enabledProtocols = capture(slot) } just Runs

        configureEngine(engine)

        assertTrue(slot.captured.isEmpty())
    }

    @Test
    fun configureEngine_excludesForbiddenProtocols_evenIfSupported() {
        val slot = slot<Array<String>>()
        val engine = buildMockEngine(
            supportedProtocols = arrayOf("TLSv1.2", "TLSv1", "TLSv1.1", "SSLv3"),
        )
        every { engine.enabledProtocols = capture(slot) } just Runs

        configureEngine(engine)

        assertFalse("TLSv1" in slot.captured)
        assertFalse("TLSv1.1" in slot.captured)
        assertFalse("SSLv3" in slot.captured)
    }

    @Test
    fun configureEngine_setsExactlyAllowedProtocols_asIntersection() {
        val slot = slot<Array<String>>()
        val engine = buildMockEngine(supportedProtocols = ZetaTlsProtocols.ALLOWED.toTypedArray())
        every { engine.enabledProtocols = capture(slot) } just Runs

        configureEngine(engine)

        assertContentEquals(ZetaTlsProtocols.ALLOWED.toTypedArray(), slot.captured)
    }

    @Test
    fun configureEngine_setsAllowedCipherSuites_filteredBySupportedSuites() {
        val slot = slot<Array<String>>()
        val allowed = ZetaCipherSuites.ECDHE_ECDSA_AES128_GCM_SHA256
        val engine = buildMockEngine(supportedCipherSuites = arrayOf(allowed, "TLS_UNKNOWN"))
        every { engine.enabledCipherSuites = capture(slot) } just Runs

        configureEngine(engine)

        assertTrue(allowed in slot.captured)
        assertFalse("TLS_UNKNOWN" in slot.captured)
    }

    @Test
    fun configureEngine_setsEmptyCipherSuites_whenNoneSupported() {
        val slot = slot<Array<String>>()
        val engine = buildMockEngine(supportedCipherSuites = arrayOf("TLS_UNSUPPORTED_SUITE"))
        every { engine.enabledCipherSuites = capture(slot) } just Runs

        configureEngine(engine)

        assertTrue(slot.captured.isEmpty())
    }

    @Test
    fun configureEngine_setsAllSuites_whenAllFullPreferredOrderSupported() {
        val slot = slot<Array<String>>()
        val engine = buildMockEngine(
            supportedCipherSuites = ZetaCipherSuites.FULL_PREFERRED_ORDER.toTypedArray(),
        )
        every { engine.enabledCipherSuites = capture(slot) } just Runs

        configureEngine(engine)

        assertContentEquals(ZetaCipherSuites.FULL_PREFERRED_ORDER.toTypedArray(), slot.captured)
    }

    @Test
    fun configureEngine_setsOnlySupportedSubset_fromFullPreferredOrder() {
        val slot = slot<Array<String>>()
        val oneSuite = arrayOf(
            ZetaCipherSuites.ECDHE_ECDSA_AES128_GCM_SHA256,
        )
        val engine = buildMockEngine(supportedCipherSuites = oneSuite)
        every { engine.enabledCipherSuites = capture(slot) } just Runs

        configureEngine(engine)

        assertContentEquals(oneSuite, slot.captured)
    }

    @Test
    fun configureEngine_usesFULL_PREFERRED_ORDER_notIanaNames_forCipherSuites() {
        val slot = slot<Array<String>>()
        val engine = buildMockEngine(
            supportedCipherSuites = arrayOf(ZetaCipherSuites.ECDHE_ECDSA_AES128_GCM_SHA256),
        )
        every { engine.enabledCipherSuites = capture(slot) } just Runs

        configureEngine(engine)

        assertTrue(ZetaCipherSuites.ECDHE_ECDSA_AES128_GCM_SHA256 in slot.captured)
    }

    @Test
    fun configureEngine_setsAllThreeProperties_inSingleCall() {
        val engine = buildMockEngine()

        configureEngine(engine)

        verify { engine.useClientMode = any() }
        verify { engine.enabledProtocols = any() }
        verify { engine.enabledCipherSuites = any() }
    }

    @Test
    fun configureEngine_clientModeAndFiltering_workIndependently_whenClientModeFalse() {
        val protocolSlot = slot<Array<String>>()
        val cipherSlot = slot<Array<String>>()
        val engine = buildMockEngine(
            supportedProtocols = arrayOf("TLSv1.2", "SSLv3"),
            supportedCipherSuites = arrayOf(ZetaCipherSuites.ECDHE_ECDSA_AES128_GCM_SHA256),
        )
        every { engine.enabledProtocols = capture(protocolSlot) } just Runs
        every { engine.enabledCipherSuites = capture(cipherSlot) } just Runs

        configureEngine(engine, clientMode = false)

        verify { engine.useClientMode = false }
        assertTrue("TLSv1.2" in protocolSlot.captured)
        assertFalse("SSLv3" in protocolSlot.captured)
        assertTrue(ZetaCipherSuites.ECDHE_ECDSA_AES128_GCM_SHA256 in cipherSlot.captured)
    }
}
