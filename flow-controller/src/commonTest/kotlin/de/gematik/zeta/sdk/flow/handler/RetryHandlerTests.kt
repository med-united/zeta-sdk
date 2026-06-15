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

package de.gematik.zeta.sdk.flow.handler

import de.gematik.zeta.sdk.flow.CapabilityResult
import de.gematik.zeta.sdk.flow.FlowNeed
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RetryHandlerTest {

    private val handler = RetryHandler()

    @Test
    fun canHandle_returnsTrue_forRetry() {
        assertTrue(handler.canHandle(FlowNeed.Retry(1000L)))
    }

    @Test
    fun canHandle_returnsFalse_forAuthentication() {
        assertFalse(handler.canHandle(FlowNeed.Authentication))
    }

    @Test
    fun canHandle_returnsFalse_forClientRegistration() {
        assertFalse(handler.canHandle(FlowNeed.ClientRegistration))
    }

    @Test
    fun canHandle_returnsFalse_forAsl() {
        assertFalse(handler.canHandle(FlowNeed.Asl))
    }

    @Test
    fun handle_returnsDone_afterDelay() = runTest {
        val result = handler.handle(FlowNeed.Retry(1000L), createContext())
        assertTrue(result is CapabilityResult.Done)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun handle_respectsDelay_beforeReturning() = runTest {
        val delayMs = 2000L
        handler.handle(FlowNeed.Retry(delayMs), createContext())
        assertEquals(delayMs, currentTime)
    }

    @Test
    fun handle_zeroDelay_returnsDone() = runTest {
        val result = handler.handle(FlowNeed.Retry(0L), createContext())
        assertTrue(result is CapabilityResult.Done)
    }
}
