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

package de.gematik.zeta.sdk.network.http.client

import io.ktor.client.HttpClient
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.head
import io.ktor.client.request.options
import io.ktor.client.request.patch
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType

public object HttpClientAsync {
    private fun HttpRequestBuilder.applyHeaders(headers: Map<String, String>) {
        headers.forEach { (key, value) -> this.headers.append(key, value) }
    }

    public suspend fun HttpClient.get(url: String, headers: Map<String, String>): HttpResponseWrapper =
        HttpResponseWrapper.from(get(url) { applyHeaders(headers) })

    public suspend fun HttpClient.post(url: String, body: String?, headers: Map<String, String>): HttpResponseWrapper =
        HttpResponseWrapper.from(
            post(url) {
                contentType(ContentType.Application.Json)
                applyHeaders(headers)
                body?.let { setBody(it) }
            },
        )

    public suspend fun HttpClient.put(url: String, body: String?, headers: Map<String, String>): HttpResponseWrapper =
        HttpResponseWrapper.from(
            put(url) {
                contentType(ContentType.Application.Json)
                applyHeaders(headers)
                body?.let { setBody(it) }
            },
        )

    public suspend fun HttpClient.patch(url: String, body: String?, headers: Map<String, String>): HttpResponseWrapper =
        HttpResponseWrapper.from(
            patch(url) {
                contentType(ContentType.Application.Json)
                applyHeaders(headers)
                body?.let { setBody(it) }
            },
        )

    public suspend fun HttpClient.delete(url: String, headers: Map<String, String>): HttpResponseWrapper =
        HttpResponseWrapper.from(delete(url) { applyHeaders(headers) })

    public suspend fun HttpClient.head(url: String, headers: Map<String, String>): HttpResponseWrapper =
        HttpResponseWrapper.from(head(url) { applyHeaders(headers) })

    public suspend fun HttpClient.options(url: String, headers: Map<String, String>): HttpResponseWrapper =
        HttpResponseWrapper.from(options(url) { applyHeaders(headers) })
}
