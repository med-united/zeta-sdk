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

public object ZetaSignatureAlgorithms {
    public val ALLOWED: List<String> = listOf(
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pkcs1_sha256", // Required for certificate chain validation
    )

    public val FORBIDDEN_HASH_FUNCTIONS: List<String> = listOf(
        "sha1", "md5", "sha224",
    )

    public val ALLOWED_KEY_ALGORITHMS: Set<String> = setOf("EC")

    public const val MIN_EC_KEY_BITS: Int = 256
}
