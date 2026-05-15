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

import de.gematik.zeta.sdk.attestation.model.PlatformProductId
import de.gematik.zeta.sdk.attestation.model.PlatformProductId.Companion.PLATFORM_ANDROID
import de.gematik.zeta.sdk.attestation.model.PlatformProductId.Companion.PLATFORM_APPLE
import de.gematik.zeta.sdk.attestation.model.PlatformProductId.Companion.PLATFORM_LINUX
import de.gematik.zeta.sdk.attestation.model.PlatformProductId.Companion.PLATFORM_WINDOWS
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PlatformProductIdSerializerTest {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private fun decode(jsonString: String): PlatformProductId =
        json.decodeFromString(PlatformProductId.serializer(), jsonString)

    @Test
    fun selectDeserializer_returnsAndroidProductId_whenPlatformIsAndroid() {
        val result = decode(
            """{"platform":"$PLATFORM_ANDROID","package_name":"de.example.app","sha256_cert_fingerprints":["AA:BB:CC"]}""",
        )
        assertIs<PlatformProductId.AndroidProductId>(result)
    }

    @Test
    fun selectDeserializer_deserializesAndroidFields_correctly() {
        val result = decode(
            """{"platform":"$PLATFORM_ANDROID","package_name":"de.example.app","sha256_cert_fingerprints":["AA:BB:CC","DD:EE:FF"]}""",
        ) as PlatformProductId.AndroidProductId
        assertEquals("de.example.app", result.packageName)
        assertEquals(listOf("AA:BB:CC", "DD:EE:FF"), result.sha256CertFingerprints)
        assertEquals("android_app", result.namespace) // default value
    }

    @Test
    fun selectDeserializer_deserializesAndroidEmptyFingerprints_correctly() {
        val result = decode(
            """{"platform":"$PLATFORM_ANDROID","package_name":"de.example.app","sha256_cert_fingerprints":[]}""",
        ) as PlatformProductId.AndroidProductId
        assertTrue(result.sha256CertFingerprints.isEmpty())
    }

    @Test
    fun selectDeserializer_returnsAppleProductId_whenPlatformIsApple() {
        val result = decode(
            """{"platform":"$PLATFORM_APPLE","platform_type":"ios","app_bundle_ids":["de.example.app"]}""",
        )
        assertIs<PlatformProductId.AppleProductId>(result)
    }

    @Test
    fun selectDeserializer_deserializesAppleFields_correctly() {
        val result = decode(
            """{"platform":"$PLATFORM_APPLE","platform_type":"ios","app_bundle_ids":["de.example.app","de.example.app.ext"]}""",
        ) as PlatformProductId.AppleProductId
        assertEquals("ios", result.platformType)
        assertEquals(listOf("de.example.app", "de.example.app.ext"), result.appBundleIds)
    }

    @Test
    fun selectDeserializer_returnsWindowsProductId_whenPlatformIsWindows() {
        val result = decode(
            """{"platform":"$PLATFORM_WINDOWS","store_id":"9WZDNCRFJ3Q2","package_family_name":"ZetaApp_abc123"}""",
        )
        assertIs<PlatformProductId.WindowsProductId>(result)
    }

    @Test
    fun selectDeserializer_deserializesWindowsFields_correctly() {
        val result = decode(
            """{"platform":"$PLATFORM_WINDOWS","store_id":"9WZDNCRFJ3Q2","package_family_name":"ZetaApp_abc123"}""",
        ) as PlatformProductId.WindowsProductId
        assertEquals("9WZDNCRFJ3Q2", result.storeId)
        assertEquals("ZetaApp_abc123", result.packageFamilyName)
    }

    @Test
    fun selectDeserializer_returnsLinuxProductId_whenPlatformIsLinux() {
        val result = decode(
            """{"platform":"$PLATFORM_LINUX","packaging_type":"deb","application_id":"de.gematik.zeta","version":"2.0.0"}""",
        )
        assertIs<PlatformProductId.LinuxProductId>(result)
    }

    @Test
    fun selectDeserializer_deserializesLinuxFields_correctly() {
        val result = decode(
            """{"platform":"$PLATFORM_LINUX","packaging_type":"deb","application_id":"de.gematik.zeta","version":"2.0.0"}""",
        ) as PlatformProductId.LinuxProductId
        assertEquals("deb", result.packagingType)
        assertEquals("de.gematik.zeta", result.applicationId)
        assertEquals("2.0.0", result.version)
    }

    @Test
    fun selectDeserializer_throwsSerializationException_whenPlatformIsUnknown() {
        assertFailsWith<SerializationException> {
            decode("""{"platform":"webassembly","package_name":"foo"}""")
        }
    }

    @Test
    fun selectDeserializer_exceptionMessage_containsUnknownPlatformValue() {
        val ex = assertFailsWith<SerializationException> {
            decode("""{"platform":"webassembly","package_name":"foo"}""")
        }
        assertEquals(ex.message?.contains("webassembly"), true, "Exception message should include the unknown platform value: ${ex.message}")
    }

    @Test
    fun selectDeserializer_throwsSerializationException_whenPlatformFieldMissing() {
        assertFailsWith<SerializationException> {
            decode("""{"package_name":"foo","version":"1.0"}""")
        }
    }

    @Test
    fun selectDeserializer_throwsSerializationException_whenPlatformIsNull() {
        assertFailsWith<SerializationException> {
            decode("""{"platform":null,"package_name":"foo"}""")
        }
    }

    @Test
    fun selectDeserializer_throwsSerializationException_whenPlatformIsEmpty() {
        assertFailsWith<SerializationException> {
            decode("""{"platform":"","package_name":"foo"}""")
        }
    }

    @Test
    fun selectDeserializer_throwsSerializationException_whenPlatformIsCaseMismatched() {
        assertFailsWith<SerializationException> {
            decode("""{"platform":"Linux","package_name":"foo"}""")
        }
    }

    @Test
    fun serializer_roundTrip_android() {
        val original = PlatformProductId.AndroidProductId(
            platform = "android",
            packageName = "de.gematik.zeta",
            sha256CertFingerprints = listOf("AA:BB:CC", "DD:EE:FF"),
        )
        val encoded = json.encodeToString(PlatformProductId.serializer(), original)
        val decoded = decode(encoded) as PlatformProductId.AndroidProductId

        assertEquals(original.packageName, decoded.packageName)
        assertEquals(original.sha256CertFingerprints, decoded.sha256CertFingerprints)
        assertEquals(original.namespace, decoded.namespace)
    }

    @Test
    fun serializer_roundTrip_apple() {
        val original = PlatformProductId.AppleProductId(
            platform = "apple",
            platformType = "macos",
            appBundleIds = listOf("de.gematik.zeta.mac"),
        )
        val encoded = json.encodeToString(PlatformProductId.serializer(), original)
        val decoded = decode(encoded) as PlatformProductId.AppleProductId

        assertEquals(original.platformType, decoded.platformType)
        assertEquals(original.appBundleIds, decoded.appBundleIds)
    }

    @Test
    fun serializer_roundTrip_windows() {
        val original = PlatformProductId.WindowsProductId(
            platform = "windows",
            storeId = "9WZDNCRFJ3Q2",
            packageFamilyName = "ZetaApp_abc123",
        )
        val encoded = json.encodeToString(PlatformProductId.serializer(), original)
        val decoded = decode(encoded) as PlatformProductId.WindowsProductId

        assertEquals(original.storeId, decoded.storeId)
        assertEquals(original.packageFamilyName, decoded.packageFamilyName)
    }

    @Test
    fun serializer_roundTrip_linux() {
        val original = PlatformProductId.LinuxProductId(
            platform = "linux",
            packagingType = "rpm",
            applicationId = "de.gematik.zeta",
            version = "3.1.0",
        )
        val encoded = json.encodeToString(PlatformProductId.serializer(), original)
        val decoded = decode(encoded) as PlatformProductId.LinuxProductId

        assertEquals(original.packagingType, decoded.packagingType)
        assertEquals(original.applicationId, decoded.applicationId)
        assertEquals(original.version, decoded.version)
    }
}
