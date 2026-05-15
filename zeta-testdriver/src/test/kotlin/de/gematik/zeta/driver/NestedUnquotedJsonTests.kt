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

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs

class NestedUnquotedJsonTest {
    private fun serialize(element: kotlinx.serialization.json.JsonElement) =
        Json.encodeToString(NestedUnquotedJson, element)

    private fun deserialize(json: String) =
        Json.decodeFromString(NestedUnquotedJson, json)

    @Test
    fun normalize_leavesPlainString_whenValueIsRegularText() {
        val input = buildJsonObject { put("key", JsonPrimitive("hello")) }
        val result = deserialize(serialize(input))
        assertEquals("hello", result.jsonObject["key"]!!.jsonPrimitive.content)
    }

    @Test
    fun normalize_leavesPlainString_whenValueContainsSpaces() {
        val input = buildJsonObject { put("key", JsonPrimitive("hello world")) }
        val result = deserialize(serialize(input))
        assertEquals("hello world", result.jsonObject["key"]!!.jsonPrimitive.content)
    }

    @Test
    fun normalize_unquotesBoolean_whenStringValueIsTrue() {
        val input = buildJsonObject { put("flag", JsonPrimitive("true")) }
        val result = deserialize(serialize(input))
        assertIs<JsonPrimitive>(result.jsonObject["flag"])
        assertEquals(true, result.jsonObject["flag"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun normalize_unquotesBoolean_whenStringValueIsFalse() {
        val input = buildJsonObject { put("flag", JsonPrimitive("false")) }
        val result = deserialize(serialize(input))
        assertEquals(false, result.jsonObject["flag"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun normalize_unquotesNull_whenStringValueIsNull() {
        val input = buildJsonObject { put("key", JsonPrimitive("null")) }
        val result = deserialize(serialize(input))
        assertEquals(JsonNull, result.jsonObject["key"])
    }

    @Test
    fun normalize_unquotesInteger_whenStringValueIsNumber() {
        val input = buildJsonObject { put("n", JsonPrimitive("42")) }
        val result = deserialize(serialize(input))
        assertEquals(42, result.jsonObject["n"]!!.jsonPrimitive.int)
    }

    @Test
    fun normalize_unquotesNegativeNumber_whenStringStartsWithMinus() {
        val input = buildJsonObject { put("n", JsonPrimitive("-7")) }
        val result = deserialize(serialize(input))
        assertEquals(-7, result.jsonObject["n"]!!.jsonPrimitive.int)
    }

    @Test
    fun normalize_unquotesPositiveNumber_whenStringStartsWithPlus() {
        val input = buildJsonObject { put("n", JsonPrimitive("+3")) }
        val result = deserialize(serialize(input))
        assertEquals(3, result.jsonObject["n"]!!.jsonPrimitive.int)
    }

    @Test
    fun normalize_parsesNestedObject_whenStringValueIsJsonObject() {
        val input = buildJsonObject { put("nested", JsonPrimitive("""{"a":1}""")) }
        val result = deserialize(serialize(input))
        val nested = result.jsonObject["nested"]
        assertIs<JsonObject>(nested)
        assertEquals(1, nested.jsonObject["a"]!!.jsonPrimitive.int)
    }

    @Test
    fun normalize_parsesNestedArray_whenStringValueIsJsonArray() {
        val input = buildJsonObject { put("list", JsonPrimitive("""[1,2,3]""")) }
        val result = deserialize(serialize(input))
        val list = result.jsonObject["list"]
        assertIs<JsonArray>(list)
        assertEquals(listOf(1, 2, 3), list.jsonArray.map { it.jsonPrimitive.int })
    }

    @Test
    fun normalize_parsesArrayOfObjects_whenStringValueIsJsonArrayOfObjects() {
        val input = buildJsonObject { put("items", JsonPrimitive("""[{"x":1},{"x":2}]""")) }
        val result = deserialize(serialize(input))
        val items = result.jsonObject["items"]!!.jsonArray
        assertEquals(2, items.size)
        assertEquals(1, items[0].jsonObject["x"]!!.jsonPrimitive.int)
        assertEquals(2, items[1].jsonObject["x"]!!.jsonPrimitive.int)
    }

    @Test
    fun normalize_trimsWhitespace_beforeParsingStringValue() {
        val input = buildJsonObject { put("flag", JsonPrimitive("  true  ")) }
        val result = deserialize(serialize(input))
        assertEquals(true, result.jsonObject["flag"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun normalize_trimsWhitespace_beforeParsingJsonObject() {
        val input = buildJsonObject { put("obj", JsonPrimitive("""  {"a":1}  """)) }
        val result = deserialize(serialize(input))
        assertIs<JsonObject>(result.jsonObject["obj"])
    }

    @Test
    fun normalize_leavesStringUnchanged_whenValueLooksLikeJsonButIsMalformed() {
        val input = buildJsonObject { put("bad", JsonPrimitive("{not valid json}")) }
        val result = deserialize(serialize(input))
        assertIs<JsonPrimitive>(result.jsonObject["bad"])
        assertFalse(result.jsonObject["bad"]!!.jsonPrimitive.isString.not())
    }

    @Test
    fun normalize_leavesIntegerPrimitive_whenValueIsAlreadyAnInt() {
        val input = buildJsonObject { put("n", JsonPrimitive(99)) }
        val result = deserialize(serialize(input))
        assertEquals(99, result.jsonObject["n"]!!.jsonPrimitive.int)
    }

    @Test
    fun normalize_leavesBooleanPrimitive_whenValueIsAlreadyABoolean() {
        val input = buildJsonObject { put("b", JsonPrimitive(true)) }
        val result = deserialize(serialize(input))
        assertEquals(true, result.jsonObject["b"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun normalize_recursesIntoObject_whenOuterObjectContainsNestedStringifiedValues() {
        val input = buildJsonObject {
            put(
                "outer",
                buildJsonObject {
                    put("inner", JsonPrimitive("true"))
                },
            )
        }
        val result = deserialize(serialize(input))
        val inner = result.jsonObject["outer"]!!.jsonObject["inner"]
        assertEquals(true, inner!!.jsonPrimitive.boolean)
    }

    @Test
    fun normalize_recursesIntoArray_whenArrayContainsStringifiedValues() {
        val input = buildJsonArray {
            add(JsonPrimitive("1"))
            add(JsonPrimitive("true"))
            add(JsonPrimitive("hello"))
        }
        val result = deserialize(Json.encodeToString(NestedUnquotedJson, input))
        assertEquals(1, result.jsonArray[0].jsonPrimitive.int)
        assertEquals(true, result.jsonArray[1].jsonPrimitive.boolean)
        assertEquals("hello", result.jsonArray[2].jsonPrimitive.content)
    }
}
