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
package de.gematik.zeta.driver

import de.gematik.zeta.driver.model.ConfigureRequest
import de.gematik.zeta.logging.Log
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.RoutingCall
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.websocket.webSocket
import kotlinx.serialization.json.Json

public val customCaPems: MutableList<String> = mutableListOf()

public fun Application.testDriverRouting(
    manager: TestDriverManager = TestDriverManager(),
) {
    routing {
        route("/proxy/{path...}") {
            handle {
                forward(call, manager.httpClient, manager.config)
            }
        }

        webSocket("/proxy/{path...}") {
            val targetUrl = buildWsTargetUrl(call, manager.config)
            forwardWs(this, manager.sdk, targetUrl, manager.config)
        }

        get("/testdriver-api/authenticate") {
            authenticate(call, manager.sdk)
        }

        get("/testdriver-api/discover") {
            discover(call, manager.sdk)
        }

        get("/testdriver-api/register") {
            register(call, manager.sdk)
        }

        get("/testdriver-api/storage") {
            storage(call, manager)
        }
        get("/testdriver-api/reset") {
            resetDriver(call, manager)
        }

        post("/testdriver-api/configure") {
            configure(call, manager)
        }

        get("/health") {
            call.respondText("alive")
        }
    }
}

private suspend fun resetDriver(call: ApplicationCall, manager: TestDriverManager) {
    try {
        manager.reset()
        reset(call, manager.sdk)
    } catch (e: Exception) {
        Log.e(e) { "Failed to reset TestDriver" }
        call.respond(HttpStatusCode.InternalServerError, "Failed to reset TestDriver: ${e.message}")
    }
}

private suspend fun storage(call: ApplicationCall, manager: TestDriverManager) {
    try {
        val entries = manager.getStorageSnapshot()
        call.respondText(
            Json.encodeToString(NestedUnquotedJson, entries),
            ContentType.Application.Json,
        )
    } catch (ex: Throwable) {
        call.respond(HttpStatusCode.InternalServerError, ex.message.toString())
    }
}

private suspend fun configure(call: RoutingCall, manager: TestDriverManager) {
    try {
        val request = call.receive<ConfigureRequest>()
        manager.configure(request)
        call.respondText("Test driver configured successfully", ContentType.Text.Plain)
    } catch (e: Exception) {
        Log.e(e) { "Failed to configure TestDriver" }
        call.respond(HttpStatusCode.BadRequest, "Failed to configure TestDriver: ${e.message}")
    }
}
