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

package de.gematik.zeta

import de.gematik.zeta.logging.Log
import de.gematik.zeta.logging.ZetaLogLevel
import de.gematik.zeta.logging.ZetaLogger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class LogTest {

    private val received = mutableListOf<Pair<String, String>>()
    private val captureLogger = object : ZetaLogger {
        override fun d(tag: String?, message: () -> String, throwable: Throwable?) { received += "d" to message() }
        override fun i(tag: String?, message: () -> String, throwable: Throwable?) { received += "i" to message() }
        override fun w(tag: String?, message: () -> String, throwable: Throwable?) { received += "w" to message() }
        override fun e(tag: String?, message: () -> String, throwable: Throwable?) { received += "e" to message() }
    }

    private fun setup() {
        received.clear()
        Log.clearDestinations()
        Log.setLogger(captureLogger)
    }

    @Test
    fun d_logsWithDebugLevel() {
        // Arrange
        setup()
        Log.setLogLevel(ZetaLogLevel.DEBUG)

        // Act
        Log.d { "debug-msg" }

        // Assert
        assertTrue(received.any { it.first == "d" && it.second == "debug-msg" })
    }

    @Test
    fun i_logsWithInfoLevel() {
        // Arrange
        setup()
        Log.setLogLevel(ZetaLogLevel.INFO)

        // Act
        Log.i { "info-msg" }

        // Assert
        assertTrue(received.any { it.first == "i" && it.second == "info-msg" })
    }

    @Test
    fun w_logsWithWarnLevel() {
        // Arrange
        setup()
        Log.setLogLevel(ZetaLogLevel.WARN)

        // Act
        Log.w { "warn-msg" }

        // Assert
        assertTrue(received.any { it.first == "w" && it.second == "warn-msg" })
    }

    @Test
    fun e_logsWithErrorLevel() {
        // Arrange
        setup()

        // Act
        Log.e { "error-msg" }

        // Assert
        assertTrue(received.any { it.first == "e" && it.second == "error-msg" })
    }

    @Test
    fun customLogger_takesPriorityOverDefault() {
        // Arrange
        setup()
        Log.setLogLevel(ZetaLogLevel.DEBUG)

        // Act
        Log.i { "custom" }

        // Assert
        assertTrue(received.any { it.second == "custom" })
    }

    @Test
    fun clearDestinations_removesCustomLogger() {
        // Arrange
        setup()
        Log.clearDestinations()
        Log.setLogLevel(ZetaLogLevel.DEBUG)

        // Act
        Log.i { "after-clear" }

        // Assert
        assertTrue(received.isEmpty())
    }

    @Test
    fun exceptionInCustomLogger_doesNotPropagate() {
        // Arrange
        Log.clearDestinations()

        Log.setLogger(object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) { error("boom") }
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) { error("boom") }
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) { error("boom") }
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) { error("boom") }
        })

        // Act & Assert
        Log.i { "msg" }
    }

    @Test
    fun throwable_isPassedToCustomLogger() {
        // Arrange
        setup()
        val throwables = mutableListOf<Throwable?>()
        Log.setLogger(object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) { throwables += throwable }
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) {}
        })
        val ex = RuntimeException("test-exception")
        Log.setLogLevel(ZetaLogLevel.INFO)
        // Act
        Log.i(throwable = ex) { "msg" }

        // Assert
        assertTrue(throwables.contains(ex))
    }

    @Test
    fun zetaLogger_throwableDefaultsToNull() {
        // Arrange
        val throwables = mutableListOf<Throwable?>()
        val logger = object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) { throwables += throwable }
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) {}
        }
        // Act
        logger.i(tag = null, message = { "msg" })

        // Assert
        assertTrue(throwables.contains(null))
    }

    @Test
    fun zetaLogger_tagCanBeNull() {
        // Arrange
        val tags = mutableListOf<String?>()
        val logger = object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) { tags += tag }
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) {}
        }

        // Act
        logger.i(tag = null, message = { "msg" })

        // Assert
        assertTrue(tags.contains(null))
    }

    @Test
    fun zetaLogger_allLevels_tagCanBeProvided() {
        // Arrange
        val tags = mutableListOf<Pair<String, String?>>()
        val logger = object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) { tags += "d" to tag }
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) { tags += "i" to tag }
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) { tags += "w" to tag }
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) { tags += "e" to tag }
        }

        // Act
        logger.d(tag = "MyTag", { "msg" })
        logger.i(tag = "MyTag", { "msg" })
        logger.w(tag = "MyTag", { "msg" })
        logger.e(tag = "MyTag", { "msg" })

        // Assert
        assertTrue(tags.all { it.second == "MyTag" })

        assertEquals(4, tags.size)
    }

    @Test
    fun d_exceptionInCustomLogger_doesNotPropagate() {
        // Arrange
        Log.clearDestinations()
        Log.setLogger(object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) { error("") }
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) {}
        })

        // Act & Assert
        Log.d { "msg" }
    }

    @Test
    fun i_exceptionInCustomLogger_doesNotPropagate() {
        // Arrange
        Log.clearDestinations()
        Log.setLogger(object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) { error("") }
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) {}
        })

        // Act & Assert
        Log.i { "msg" }
    }

    @Test
    fun w_exceptionInCustomLogger_doesNotPropagate() {
        // Arrange
        Log.clearDestinations()
        Log.setLogger(object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) { error("") }
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) {}
        })

        // Act & Assert
        Log.w { "msg" }
    }

    @Test
    fun e_exceptionInCustomLogger_doesNotPropagate() {
        // Arrange
        Log.clearDestinations()
        Log.setLogger(object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) { error("") }
        })

        // Act & Assert
        Log.e { "msg" }
    }

    @Test
    fun d_customLogger_receivesMessage() {
        // Arrange
        val received = mutableListOf<String>()
        Log.clearDestinations()
        Log.setLogger(object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) { received += message() }
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) {}
        })
        Log.setLogLevel(ZetaLogLevel.DEBUG)

        // Act
        Log.d { "debug-msg" }

        // Assert
        assertTrue(received.contains("debug-msg"))
    }

    @Test
    fun i_customLogger_receivesMessage() {
        // Arrange
        val received = mutableListOf<String>()
        Log.clearDestinations()
        Log.setLogger(object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) { received += message() }
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) {}
        })
        Log.setLogLevel(ZetaLogLevel.INFO)

        // Act
        Log.i { "info-msg" }

        // Assert
        assertTrue(received.contains("info-msg"))
    }

    @Test
    fun w_customLogger_receivesMessage() {
        // Arrange
        val received = mutableListOf<String>()
        Log.clearDestinations()
        Log.setLogger(object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) { received += message() }
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) {}
        })
        Log.setLogLevel(ZetaLogLevel.WARN)

        // Act
        Log.w { "warn-msg" }

        // Assert
        assertTrue(received.contains("warn-msg"))
    }

    @Test
    fun e_customLogger_receivesMessage() {
        // Arrange
        val received = mutableListOf<String>()
        Log.clearDestinations()
        Log.setLogger(object : ZetaLogger {
            override fun d(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun i(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun w(tag: String?, message: () -> String, throwable: Throwable?) {}
            override fun e(tag: String?, message: () -> String, throwable: Throwable?) { received += message() }
        })
        Log.setLogLevel(ZetaLogLevel.ERROR)

        // Act
        Log.e { "error-msg" }

        // Assert
        assertTrue(received.contains("error-msg"))
    }

    @Test
    fun setLogLevel_debug_logsAllLevels() {
        // Arrange
        setup()
        Log.setLogLevel(ZetaLogLevel.DEBUG)

        // Act
        Log.d { "debug-msg" }
        Log.i { "info-msg" }
        Log.w { "warn-msg" }
        Log.e { "error-msg" }

        // Assert
        assertEquals(4, received.size)
    }

    @Test
    fun setLogLevel_info_skipsDEBUG() {
        // Arrange
        setup()
        Log.setLogLevel(ZetaLogLevel.INFO)

        // Act
        Log.d { "debug-msg" }
        Log.i { "info-msg" }

        // Assert
        assertTrue(received.none { it.first == "d" })
        assertTrue(received.any { it.first == "i" })
    }

    @Test
    fun setLogLevel_warn_skipsDebugAndInfo() {
        // Arrange
        setup()
        Log.setLogLevel(ZetaLogLevel.WARN)

        // Act
        Log.d { "debug-msg" }
        Log.i { "info-msg" }
        Log.w { "warn-msg" }

        // Assert
        assertTrue(received.none { it.first == "d" })
        assertTrue(received.none { it.first == "i" })
        assertTrue(received.any { it.first == "w" })
    }

    @Test
    fun setLogLevel_error_onlyLogsErrors() {
        // Arrange
        setup()
        Log.setLogLevel(ZetaLogLevel.ERROR)

        // Act
        Log.d { "debug-msg" }
        Log.i { "info-msg" }
        Log.w { "warn-msg" }
        Log.e { "error-msg" }

        // Assert
        assertEquals(1, received.size)
        assertTrue(received.any { it.first == "e" })
    }

    @Test
    fun setLogLevel_none_logsNothing() {
        // Arrange
        setup()
        Log.setLogLevel(ZetaLogLevel.NONE)

        // Act
        Log.d { "debug-msg" }
        Log.i { "info-msg" }
        Log.w { "warn-msg" }
        Log.e { "error-msg" }

        // Assert
        assertTrue(received.isEmpty())
    }

    @Test
    fun clearDestinations_resetsLogLevelToError() {
        // Arrange
        setup()
        Log.setLogLevel(ZetaLogLevel.DEBUG)
        Log.clearDestinations()
        Log.setLogger(captureLogger)

        // Act
        Log.d { "debug-msg" }
        Log.e { "error-msg" }

        // Assert
        assertTrue(received.none { it.first == "d" })
        assertTrue(received.any { it.first == "e" })
    }

    @Test
    fun initDebugLogger_setsLogLevelToDebug() {
        // Arrange
        setup()
        Log.initDebugLogger()

        // Act
        Log.d { "debug-msg" }

        // Assert
        assertTrue(received.any { it.first == "d" })
    }

    @Test
    fun defaultLogLevel_isError() {
        // Arrange
        Log.clearDestinations()
        Log.setLogger(captureLogger)

        // Act
        Log.d { "debug-msg" }
        Log.i { "info-msg" }
        Log.w { "warn-msg" }
        Log.e { "error-msg" }

        // Assert
        assertEquals(1, received.size)
        assertTrue(received.any { it.first == "e" })
    }
}
