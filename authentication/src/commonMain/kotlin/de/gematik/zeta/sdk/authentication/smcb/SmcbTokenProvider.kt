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

package de.gematik.zeta.sdk.authentication.smcb

import kotlin.io.encoding.Base64

class SmcbTokenProvider(
    private val connectorConfig: ConnectorConfig,
    private val connectorApi: ConnectorApi = ConnectorApiImpl(connectorConfig),
) : BaseSmcbTokenProvider() {

    override suspend fun readCertificate(): ByteArray {
        val response = connectorApi.readCertificate(
            connectorConfig.cardHandle,
            connectorConfig.mandantId,
            connectorConfig.clientSystemId,
            connectorConfig.workspaceId,
            connectorConfig.userId,
        )
        val certificate = response.x509DataInfoList.x509DataInfo
            .firstOrNull()?.x509Data?.x509Certificate.orEmpty()
        return Base64.decode(certificate)
    }

    override suspend fun externalAuthenticate(base64Challenge: String): ByteArray {
        val response = connectorApi.externalAuthenticate(
            connectorConfig.cardHandle,
            connectorConfig.mandantId,
            connectorConfig.clientSystemId,
            connectorConfig.workspaceId,
            connectorConfig.userId,
            base64Challenge,
        )
        return Base64.decode(response.signatureObject.base64Signature)
    }

    data class ConnectorConfig(
        val baseUrl: String,
        val mandantId: String,
        val clientSystemId: String,
        val workspaceId: String,
        val userId: String,
        val cardHandle: String,
    )
}
