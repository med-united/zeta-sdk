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

package de.gematik.zeta.sdk

import de.gematik.zeta.logging.Log
import de.gematik.zeta.sdk.network.http.client.ZetaHttpClientBuilder
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.close
import io.ktor.websocket.readBytes
import io.ktor.websocket.readText
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.future.await
import kotlinx.coroutines.future.future
import java.util.concurrent.CompletableFuture

object WsClientAsyncExtension {
    @OptIn(DelicateCoroutinesApi::class)
    @JvmStatic
    fun wsAsync(
        sdk: ZetaSdkClient,
        targetUrl: String,
        builder: ZetaHttpClientBuilder.() -> Unit = {},
        customHeaders: Map<String, String>,
        handler: WsAsyncSession.WsHandler,
    ): CompletableFuture<Unit> {
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        return scope.future {
            try {
                sdk.ws(targetUrl, builder, customHeaders = customHeaders) {
                    val asyncSession = WsAsyncSession(this, scope)
                    val handlerFuture = handler.handle(asyncSession)
                    handlerFuture.await()
                    asyncSession.awaitClose().await()
                }
            } finally {
                scope.cancel()
            }
        }
    }

    class WsAsyncSession(
        private val session: WebSocketSession,
        private val scope: CoroutineScope,
    ) {
        private var messageLoopFuture: CompletableFuture<Unit>? = null

        @JvmName("sendTextAsync")
        fun sendText(text: String): CompletableFuture<Unit> {
            return scope.future {
                Log.d { "Sending text frame: $text" }
                session.send(Frame.Text(text))
            }
        }

        @JvmName("sendBinaryAsync")
        fun sendBinary(data: ByteArray): CompletableFuture<Unit> {
            return scope.future {
                Log.d { "Sending binary frame size: ${data.size}" }
                session.send(Frame.Binary(true, data))
            }
        }

        @JvmName("onMessageAsync")
        fun onMessage(listener: WsMessageListener): CompletableFuture<Unit> {
            val future = scope.future {
                try {
                    for (frame in session.incoming) {
                        when (frame) {
                            is Frame.Text -> {
                                val text = frame.readText()
                                Log.d { "Received text frame: $text" }
                                listener.onText(text)
                            }

                            is Frame.Binary -> {
                                val bytes = frame.readBytes()
                                Log.d { "Received binary frame size: ${bytes.size}" }
                                listener.onBinary(bytes)
                            }

                            is Frame.Close -> {
                                Log.d { "Received close frame" }
                                listener.onClose()
                                break
                            }

                            else -> {
                                Log.i { "Ignoring frame: ${frame::class.simpleName}" }
                            }
                        }
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                    Log.e { "Exception during income frame: ${e.printStackTrace()}" }
                    listener.onError(e)
                    throw e
                }
            }
            messageLoopFuture = future
            return future
        }

        @JvmName("closeAsync")
        fun close(): CompletableFuture<Unit> {
            return scope.future {
                Log.d { "Closing websocket session" }
                session.close()
            }
        }

        @JvmName("awaitCloseAsync")
        fun awaitClose(): CompletableFuture<Unit> {
            return messageLoopFuture ?: CompletableFuture.completedFuture(Unit)
        }

        @OptIn(DelicateCoroutinesApi::class)
        fun isActive(): Boolean {
            return !session.outgoing.isClosedForSend && !session.incoming.isClosedForReceive
        }

        fun interface WsHandler {
            fun handle(session: WsAsyncSession): CompletableFuture<Unit>
        }

        interface WsMessageListener {
            fun onText(text: String)
            fun onBinary(data: ByteArray)
            fun onClose()
            fun onError(error: Throwable)
        }
    }
}
