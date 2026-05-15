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

package de.gematik.zeta.sdk.network.http.client.config.tls

public object ZetaTlsCurves {
    public const val P256: String = "secp256r1"
    public const val P256_ALIAS: String = "prime256v1"
    public const val P256_IANA: String = "P-256"
    public const val P384: String = "secp384r1"
    public const val P384_IANA: String = "P-384"
    public const val BRAINPOOL_P256R1: String = "brainpoolP256r1"
    public const val BRAINPOOL_P384R1: String = "brainpoolP384r1"

    public val ALLOWED: List<String> = listOf(
        P256,
        P256_ALIAS,
        P256_IANA,
        P384,
        P384_IANA,
        BRAINPOOL_P256R1,
        BRAINPOOL_P384R1,
    )
}
