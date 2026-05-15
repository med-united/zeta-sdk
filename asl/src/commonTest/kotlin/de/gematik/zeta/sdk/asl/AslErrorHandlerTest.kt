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

package de.gematik.zeta.sdk.asl

import de.gematik.zeta.sdk.network.http.client.ZetaHttpResponse
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.cbor.Cbor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

@OptIn(ExperimentalSerializationApi::class)
class AslResponseTest {
    private val cbor = Cbor {}

    @Test
    fun handleMessageResponse_returnsSameResponse_whenStatusOk() = runTest {
        val engine = MockEngine { _ ->
            respond(
                content = ByteArray(0),
                status = HttpStatusCode.OK,
                headers = headersOf(),
            )
        }

        val client = HttpClient(engine)
        val httpResponse = client.get("https://test")

        val response = ZetaHttpResponse(
            status = HttpStatusCode.OK,
            raw = httpResponse,
            headers = emptyMap(),
        )

        val result = handleMessageResponse(response)

        assertSame(response, result)
    }

    @Test
    fun handleMessageResponse_throwsAslException_whenErrorStatus() = runTest {
        val encodedError = cbor.encodeToByteArray(
            AslErrorMessage.serializer(),
            AslErrorMessage(
                errorCode = 123,
                errorMessage = "Bad request",
                messageType = "",
            ),
        )

        val engine = MockEngine { _ ->
            respond(
                content = encodedError,
                status = HttpStatusCode.BadRequest,
                headers = headersOf(),
            )
        }

        val client = HttpClient(engine)
        val httpResponse = client.get("https://test")

        val response = ZetaHttpResponse(
            status = HttpStatusCode.BadRequest,
            raw = httpResponse,
            headers = emptyMap(),
        )

        val ex = assertFailsWith<AslException> {
            handleMessageResponse(response)
        }

        assertEquals("Bad request", ex.message)
        assertSame(response, ex.response)
    }

    @Test
    fun decodeAslError_decodesCorrectly() = runTest {
        val error = AslErrorMessage(
            errorCode = 1,
            errorMessage = "Invalid",
            messageType = "",
        )

        val encoded = cbor.encodeToByteArray(AslErrorMessage.serializer(), error)

        val engine = MockEngine { _ ->
            respond(
                content = encoded,
                status = HttpStatusCode.BadRequest,
                headers = headersOf(),
            )
        }

        val client = HttpClient(engine)
        val httpResponse = client.get("https://test")

        val result = decodeAslError(httpResponse)

        assertEquals(1, result.errorCode)
        assertEquals("Invalid", result.errorMessage)
    }

    @Test
    fun handleMessageResponse_throws_whenInvalidCbor() = runTest {
        val engine = MockEngine { _ ->
            respond(
                content = byteArrayOf(1, 2, 3),
                status = HttpStatusCode.BadRequest,
                headers = headersOf(),
            )
        }

        val client = HttpClient(engine)
        val httpResponse = client.get("https://test")

        val response = ZetaHttpResponse(
            status = HttpStatusCode.BadRequest,
            raw = httpResponse,
            headers = emptyMap(),
        )

        assertFailsWith<Exception> {
            handleMessageResponse(response)
        }
    }
}
