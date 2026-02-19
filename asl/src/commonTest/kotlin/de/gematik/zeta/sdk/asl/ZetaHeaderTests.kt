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

import de.gematik.zeta.longToBytesBigEndian
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ZetaHeaderTest {
    private val keyId = ByteArray(32) { 0x01 }

    private fun buildHeader(
        pu: Environment = Environment.Production,
        kind: Kind = Kind.Response,
        counter: Long = 1L,
        keyId: ByteArray = this.keyId,
    ): ZetaHeader =
        ZetaHeader(
            pu = pu,
            kind = kind,
            counter = counter,
            keyId = keyId,
        )

    @Test
    fun toBytes_throwsException_keyIdNot32Bytes() {
        // Arrange
        val header = buildHeader(keyId = ByteArray(16) { 0x01 })

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            header.toBytes()
        }
    }

    @Test
    fun toBytes_returnsCorrectLength_validHeader() {
        // Arrange
        val header = buildHeader()

        // Act
        val result = header.toBytes()

        // Assert
        assertEquals(HEADER_LEN, result.size)
    }

    @Test
    fun toBytes_setsVersionByte_validHeader() {
        // Arrange
        val header = buildHeader()

        // Act
        val result = header.toBytes()

        // Assert
        assertEquals(0x02.toByte(), result[VERSION_OFFSET])
    }

    @Test
    fun toBytes_setPuByteToZero_environmentTesting() {
        // Arrange
        val header = buildHeader(pu = Environment.Testing)

        // Act
        val result = header.toBytes()

        // Assert
        assertEquals(0.toByte(), result[PU_OFFSET])
    }

    @Test
    fun toBytes_setPuByteToOne_environmentProduction() {
        // Arrange
        val header = buildHeader(pu = Environment.Production)

        // Act
        val result = header.toBytes()

        // Assert
        assertEquals(1.toByte(), result[PU_OFFSET])
    }

    @Test
    fun toBytes_setsKindByte_kindRequest() {
        // Arrange
        val header = buildHeader(kind = Kind.Request)

        // Act
        val result = header.toBytes()

        // Assert
        assertEquals(Kind.Request.v, result[KIND_OFFSET])
    }

    @Test
    fun toBytes_setsKindByte_kindResponse() {
        // Arrange
        val header = buildHeader(kind = Kind.Response)

        // Act
        val result = header.toBytes()

        // Assert
        assertEquals(Kind.Response.v, result[KIND_OFFSET])
    }

    @Test
    fun toBytes_setsCounterBytes_validCounter() {
        // Arrange
        val counter = 42L
        val header = buildHeader(counter = counter)

        // Act
        val result = header.toBytes()

        // Assert
        val expectedCounterBytes = longToBytesBigEndian(counter)
        for (i in 0 until 8) {
            assertEquals(expectedCounterBytes[i], result[CTR_OFFSET + i])
        }
    }

    @Test
    fun toBytes_setsKeyIdBytes_validKeyId() {
        // Arrange
        val header = buildHeader()

        // Act
        val result = header.toBytes()

        // Assert
        for (i in 0 until 32) {
            assertEquals(keyId[i], result[KEYID_OFFSET + i])
        }
    }

    @Test
    fun from_throwsException_dataTooShort() {
        // Arrange
        val tooShort = ByteArray(HEADER_LEN - 1)

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            ZetaHeader.from(tooShort)
        }
    }

    @Test
    fun from_throwsException_invalidVersion() {
        // Arrange
        val bytes = buildHeader().toBytes()
        bytes[VERSION_OFFSET] = 0x01.toByte()

        // Act & Assert
        assertFailsWith<IllegalArgumentException> {
            ZetaHeader.from(bytes)
        }
    }

    @Test
    fun from_throwsException_invalidPuByte() {
        // Arrange
        val bytes = buildHeader().toBytes()
        bytes[PU_OFFSET] = 0x05.toByte()

        // Act & Assert
        assertFailsWith<IllegalStateException> {
            ZetaHeader.from(bytes)
        }
    }

    @Test
    fun from_throwsException_invalidKindByte() {
        // Arrange
        val bytes = buildHeader().toBytes()
        bytes[KIND_OFFSET] = 0x05.toByte()

        // Act & Assert
        assertFailsWith<IllegalStateException> {
            ZetaHeader.from(bytes)
        }
    }

    @Test
    fun from_parsesCorrectly_puTesting() {
        // Arrange
        val bytes = buildHeader(pu = Environment.Testing).toBytes()

        // Act
        val result = ZetaHeader.from(bytes)

        // Assert
        assertEquals(Environment.Testing, result.pu)
    }

    @Test
    fun from_parsesCorrectly_puProduction() {
        // Arrange
        val bytes = buildHeader(pu = Environment.Production).toBytes()

        // Act
        val result = ZetaHeader.from(bytes)

        // Assert
        assertEquals(Environment.Production, result.pu)
    }

    @Test
    fun from_parsesCorrectly_kindRequest() {
        // Arrange
        val bytes = buildHeader(kind = Kind.Request).toBytes()

        // Act
        val result = ZetaHeader.from(bytes)

        // Assert
        assertEquals(Kind.Request, result.kind)
    }

    @Test
    fun from_parsesCorrectly_kindResponse() {
        // Arrange
        val bytes = buildHeader(kind = Kind.Response).toBytes()

        // Act
        val result = ZetaHeader.from(bytes)

        // Assert
        assertEquals(Kind.Response, result.kind)
    }

    @Test
    fun from_parsesCorrectly_counter() {
        // Arrange
        val counter = 999L
        val bytes = buildHeader(counter = counter).toBytes()

        // Act
        val result = ZetaHeader.from(bytes)

        // Assert
        assertEquals(counter, result.counter)
    }

    @Test
    fun from_parsesCorrectly_keyId() {
        // Arrange
        val bytes = buildHeader().toBytes()

        // Act
        val result = ZetaHeader.from(bytes)

        // Assert
        assertEquals(keyId.toList(), result.keyId.toList())
    }

    @Test
    fun roundTrip_fromParsesWhatToBytesProduces_testingRequest() {
        // Arrange
        val original = buildHeader(pu = Environment.Testing, kind = Kind.Request, counter = 7L)

        // Act
        val parsed = ZetaHeader.from(original.toBytes())

        // Assert
        assertEquals(original.version, parsed.version)
        assertEquals(original.pu, parsed.pu)
        assertEquals(original.kind, parsed.kind)
        assertEquals(original.counter, parsed.counter)
        assertEquals(original.keyId.toList(), parsed.keyId.toList())
    }

    @Test
    fun roundTrip_productionResponse() {
        // Arrange
        val original = buildHeader(pu = Environment.Production, kind = Kind.Response, counter = 123L)

        // Act
        val parsed = ZetaHeader.from(original.toBytes())

        // Assert
        assertEquals(original.version, parsed.version)
        assertEquals(original.pu, parsed.pu)
        assertEquals(original.kind, parsed.kind)
        assertEquals(original.counter, parsed.counter)
        assertEquals(original.keyId.toList(), parsed.keyId.toList())
    }
}
