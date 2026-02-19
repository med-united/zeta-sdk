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

import de.gematik.zeta.sdk.WsClientAsyncExtension.WsAsyncSession
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketExtension
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.close
import io.ktor.websocket.readBytes
import io.ktor.websocket.readText
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.coroutines.CoroutineContext
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class WsClientAsyncExtensionTest {
    private lateinit var mockSdkClient: ZetaSdkClient
    private lateinit var mockSession: DefaultClientWebSocketSession
    private lateinit var incomingChannel: Channel<Frame>
    private lateinit var outgoingChannel: Channel<Frame>

    @OptIn(DelicateCoroutinesApi::class)
    @BeforeTest
    fun setup() {
        mockSdkClient = mockk()

        incomingChannel = Channel(Channel.UNLIMITED)
        outgoingChannel = Channel(Channel.UNLIMITED)

        mockSession = mockk {
            every { incoming } returns incomingChannel
            every { outgoing } returns outgoingChannel
        }

        coEvery { mockSession.send(any<Frame>()) } coAnswers {
            outgoingChannel.send(firstArg())
        }

        coEvery { mockSession.close() } coAnswers {
            incomingChannel.close()
            outgoingChannel.close()
        }
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
        incomingChannel.cancel()
        outgoingChannel.cancel()
    }

    @Test
    fun sendText_sendTextCalled_textFrameSent() = runTest {
        // Arrange
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val session = WsAsyncSession(mockSession, scope)

        // Act
        session.sendText("Hello Zeta").get(1, TimeUnit.SECONDS)

        // Assert
        coVerify { mockSession.send(match<Frame.Text> { it.readText() == "Hello Zeta" }) }
        scope.cancel()
    }

    @Test
    fun sendBinary_sendBinaryCalled_binaryFrameSent() = runTest {
        // Arrange
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val session = WsAsyncSession(mockSession, scope)
        val data = byteArrayOf(1, 2, 3, 4, 5)

        // Act
        session.sendBinary(data).get(1, TimeUnit.SECONDS)

        // Assert
        coVerify { mockSession.send(match<Frame.Binary> { it.readBytes().contentEquals(data) }) }
        scope.cancel()
    }

    @OptIn(DelicateCoroutinesApi::class)
    @Test
    fun isActive_sessionOpen_trueReturned() = runTest {
        // Arrange
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val session = WsAsyncSession(mockSession, scope)
        every { mockSession.outgoing.isClosedForSend } returns false
        every { mockSession.incoming.isClosedForReceive } returns false

        // Act
        val result = session.isActive()

        // Assert
        assertTrue(result)
        scope.cancel()
    }

    @OptIn(DelicateCoroutinesApi::class)
    @Test
    fun isActive_sessionClosed_falseReturned() = runTest {
        // Arrange
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val session = WsAsyncSession(mockSession, scope)
        every { mockSession.outgoing.isClosedForSend } returns true
        every { mockSession.incoming.isClosedForReceive } returns true

        // Act
        val result = session.isActive()

        // Assert
        assertFalse(result)
        scope.cancel()
    }

    @Test
    fun awaitClose_messageLoopStarted_sameFutureReturned() = runTest {
        // Arrange
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val session = WsAsyncSession(mockSession, scope)
        val listener = object : WsAsyncSession.WsMessageListener {
            override fun onText(text: String) {}

            override fun onBinary(data: ByteArray) {}

            override fun onClose() {}

            override fun onError(error: Throwable) {}
        }

        // Act
        val messageFuture = session.onMessage(listener)
        val awaitFuture = session.awaitClose()

        // Assert
        assertSame(messageFuture, awaitFuture)

        incomingChannel.send(Frame.Close(CloseReason(CloseReason.Codes.NORMAL, "")))
        awaitFuture.get(2, TimeUnit.SECONDS)
        scope.cancel()
    }

    @Test
    fun awaitClose_messageLoopNotStarted_completedFutureReturned() = runTest {
        // Arrange
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val session = WsAsyncSession(mockSession, scope)

        // Act
        val awaitFuture = session.awaitClose()

        // Assert
        assertTrue(awaitFuture.isDone)
        scope.cancel()
    }

    @Test
    fun wsAsync_sdkThrows_exceptionPropagated() = runTest {
        // Arrange
        val testException = RuntimeException("Connection failed")
        coEvery { mockSdkClient.ws<Unit>(any(), any(), any(), any()) } throws testException

        // Act
        val future = WsClientAsyncExtension.wsAsync(
            mockSdkClient,
            "wss://example.com/ws",
            {},
            emptyMap(),
        ) { session ->
            session.awaitClose()
        }

        // Assert
        val exception = assertFailsWith<Exception> { future.get(2, TimeUnit.SECONDS) }
        assertTrue(exception.cause is RuntimeException)
        assertTrue(
            exception.message?.contains("Connection failed") == true ||
                exception.cause?.message?.contains("Connection failed") == true,
        )
    }

    @Test
    fun onMessage_textFrameDelivered_listenerReceivesText() = runTest {
        // Arrange
        val fake = FakeWebSocketSession()
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val sut = WsAsyncSession(fake, scope)

        val texts = CopyOnWriteArrayList<String>()
        val listener = object : WsAsyncSession.WsMessageListener {
            override fun onText(text: String) {
                texts += text
            }

            override fun onBinary(data: ByteArray) {}

            override fun onClose() {}

            override fun onError(error: Throwable) {}
        }

        // Act
        val loopFuture = sut.onMessage(listener)
        fake.incomingCh.send(Frame.Text("hello"))
        fake.incomingCh.send(Frame.Close())

        loopFuture.get(2, TimeUnit.SECONDS)

        // Assert
        assertEquals(listOf("hello"), texts)
        scope.cancel()
    }

    @Test
    fun onMessage_binaryFrameDelivered_listenerReceivesBinary() = runTest {
        // Arrange
        val fake = FakeWebSocketSession()
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val sut = WsAsyncSession(fake, scope)
        val closed = CountDownLatch(1)

        val binaries = CopyOnWriteArrayList<ByteArray>()
        val listener = object : WsAsyncSession.WsMessageListener {
            override fun onText(text: String) {}
            override fun onBinary(data: ByteArray) {
                binaries += data
            }

            override fun onClose() { closed.countDown() }
            override fun onError(error: Throwable) {}
        }

        // Act
        val loopFuture = sut.onMessage(listener)
        fake.incomingCh.send(Frame.Binary(true, byteArrayOf(1, 2, 3)))
        fake.incomingCh.send(Frame.Close())

        loopFuture.get(2, TimeUnit.SECONDS)

        // Assert
        assertEquals(1, binaries.size)
        assertArrayEquals(byteArrayOf(1, 2, 3), binaries[0])
        scope.cancel()
    }

    @Test
    fun onMessage_closeFrameDelivered_listenerReceivesClose() = runTest {
        // Arrange
        val fake = FakeWebSocketSession()
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val sut = WsAsyncSession(fake, scope)

        val closed = CountDownLatch(1)
        val listener = object : WsAsyncSession.WsMessageListener {
            override fun onText(text: String) {}
            override fun onBinary(data: ByteArray) {}

            override fun onClose() {
                closed.countDown()
            }

            override fun onError(error: Throwable) {}
        }

        // Act
        val loopFuture = sut.onMessage(listener)
        fake.incomingCh.send(Frame.Close(CloseReason(CloseReason.Codes.NORMAL, "")))

        loopFuture.get(2, TimeUnit.SECONDS)

        // Assert
        assertTrue(closed.await(1, TimeUnit.SECONDS))
        scope.cancel()
    }
}

class FakeWebSocketSession(
    override var masking: Boolean = false,
    override var maxFrameSize: Long = Long.MAX_VALUE,
) : WebSocketSession {

    private val job = Job()
    val incomingCh = Channel<Frame>(Channel.UNLIMITED)
    val outgoingCh = Channel<Frame>(Channel.UNLIMITED)

    override val coroutineContext: CoroutineContext = Dispatchers.Unconfined + job

    override val incoming: ReceiveChannel<Frame> get() = incomingCh
    override val outgoing: SendChannel<Frame> get() = outgoingCh

    override val extensions: List<WebSocketExtension<*>> = emptyList()

    override suspend fun send(frame: Frame) {
        outgoingCh.send(frame)
    }

    override suspend fun flush() {}

    @Deprecated(
        "Use cancel() instead.",
        replaceWith = ReplaceWith("cancel()", "kotlinx.coroutines.cancel"),
        level = DeprecationLevel.ERROR,
    )
    override fun terminate() {
        incomingCh.close()
        outgoingCh.close()
        job.cancel()
    }
}
