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

@file:OptIn(ExperimentalForeignApi::class)

package de.gematik.zeta.client.config

import de.gematik.zeta.client.CliArgs
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import okio.FileSystem
import okio.Path.Companion.toPath
import platform.posix.getenv

private const val zetaEnvFile: String = "ZETA_ENV_FILE"
public actual fun getConfig(key: String): String? =
    getenv(key)?.toKString()
        ?: values[key]

private val values: Map<String, String> by lazy {
    val path = CliArgs.get(zetaEnvFile)
        ?: getenv(zetaEnvFile)?.toKString()

    checkNotNull(path)

    if (!FileSystem.SYSTEM.exists(path.toPath())) return@lazy emptyMap()

    FileSystem.SYSTEM
        .read(path.toPath()) { generateSequence { readUtf8Line() }.toList() }
        .filter { it.isNotBlank() && !it.startsWith("#") }
        .mapNotNull { line ->
            val parts = line.split("=", limit = 2)
            if (parts.size == 2) parts[0].trim() to parts[1].trim() else null
        }
        .toMap()
}
