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

import de.gematik.zeta.logging.Log
import de.gematik.zeta.sdk.crypto.OcspHandler
import de.gematik.zeta.sdk.crypto.OcspHandlerImpl
import de.gematik.zeta.sdk.crypto.OcspRequestData
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.ContentType
import io.ktor.http.contentType

public class CertificateRevokedException(message: String, cause: Throwable? = null) :
    Exception(message, cause)

internal class RevocationChecker(
    private val ocspHandler: OcspHandler = OcspHandlerImpl(),
    private val httpClient: HttpClient = HttpClient(),
) {
    suspend fun checkRevocation(certDer: ByteArray, issuerDer: ByteArray) {
        val ocspSuccess = try {
            checkOCSP(certDer, issuerDer)
            Log.i { "OCSP validation successful" }
            true
        } catch (e: Exception) {
            Log.w { "OCSP check failed: ${e.message}" }
            false
        }

        if (!ocspSuccess) {
            try {
                checkCRL(certDer, issuerDer)
                Log.i { "CRL validation successful" }
            } catch (e: Exception) {
                Log.w { "CRL check failed: ${e.message}" }

                throw CertificateRevokedException(
                    "Revocation check failed: OCSP and CRL both unavailable or invalid", e,
                )
            }
        }
    }

    private suspend fun checkOCSP(certDer: ByteArray, issuerDer: ByteArray) {
        val ocspRequestData = ocspHandler.prepareOcspRequest(certDer, issuerDer)
        val ocspResponseDer = sendOcspRequest(ocspRequestData)
        ocspHandler.validate(ocspResponseDer, certDer, issuerDer)
    }

    private suspend fun sendOcspRequest(requestData: OcspRequestData): ByteArray {
        val response = httpClient.post(requestData.url) {
            contentType(ContentType.parse("application/ocsp-request"))
            setBody(requestData.requestDer)
        }
        return response.bodyAsBytes()
    }

    private suspend fun checkCRL(certDer: ByteArray, issuerDer: ByteArray) {
        val crlUrl = ocspHandler.extractCrlUrl(certDer)
            ?: throw CertificateRevokedException("No CRL distribution point found")

        val crlDer = downloadCRL(crlUrl)
        ocspHandler.validateCrl(crlDer, certDer, issuerDer)
    }

    private suspend fun downloadCRL(crlUrl: String): ByteArray {
        val response = httpClient.get(crlUrl)
        return response.bodyAsBytes()
    }

    fun close() {
        httpClient.close()
    }
}
