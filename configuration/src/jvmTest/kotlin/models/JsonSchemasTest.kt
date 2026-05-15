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

package models

import de.gematik.zeta.sdk.configuration.models.AUTHORIZATION_SERVER_SCHEMA_JSON
import de.gematik.zeta.sdk.configuration.models.PROTECTED_RESOURCE_SCHEMA_JSON
import kotlin.test.Test
import kotlin.test.assertEquals

class SchemaResourceTest {

    @Test
    fun authorizationServerSchema_matchesResourceFile() {
        // Arrange
        val resourceContent = object {}.javaClass
            .getResourceAsStream("/as-well-known.json")!!
            .bufferedReader()
            .readText()
            .trim()

        // Act & Assert
        assertEquals(resourceContent, AUTHORIZATION_SERVER_SCHEMA_JSON.trim())
    }

    @Test
    fun protectedResourceSchema_matchesResourceFile() {
        // Arrange
        val resourceContent = object {}.javaClass
            .getResourceAsStream("/opr-well-known.json")!!
            .bufferedReader()
            .readText()
            .trim()

        // Act & Assert
        assertEquals(resourceContent, PROTECTED_RESOURCE_SCHEMA_JSON.trim())
    }
}
