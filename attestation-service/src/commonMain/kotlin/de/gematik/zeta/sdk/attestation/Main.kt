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

import AttestationService
import ServiceConfig
import de.gematik.zeta.sdk.attestation.config.CliArgs
import de.gematik.zeta.sdk.attestation.config.Config
import de.gematik.zeta.sdk.attestation.config.Config.getConfig
import de.gematik.zeta.sdk.attestation.interfaces.FileHashCalculator
import de.gematik.zeta.sdk.attestation.interfaces.FileIntegrity
import de.gematik.zeta.sdk.attestation.interfaces.FileIntegrity.Companion.PCR_ID
import de.gematik.zeta.sdk.attestation.interfaces.FileScanner
import de.gematik.zeta.sdk.attestation.interfaces.ProcessMonitor
import de.gematik.zeta.sdk.attestation.server.AttestationServer
import de.gematik.zeta.sdk.attestation.tpm.TpmAccess

fun main(args: Array<String>) {
    CliArgs.init(args)
    val configFile = CliArgs.get("config-file")
    checkNotNull(configFile) { "Command line argument '--config-file' is missing" }

    Config.init(configFile)
    val files = getConfig("FILES")?.split(",")?.map { it.trim() }
    val serverPort = getConfig("SERVER_PORT")?.toInt() ?: 8081
    val pcrId = getConfig("PCR_ID")?.toInt() ?: PCR_ID
    val allowedExecutables = getConfig("ALLOWED_EXECUTABLES")?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
    checkNotNull(files) { "Config property 'FILES' is missing" }

    val config = ServiceConfig(
        files = files,
        port = serverPort,
        pcrId = pcrId,
        resetFileIntegrity = CliArgs.contains("reset-file-integrity"),
        allowedExecutables = allowedExecutables,
    )

    // Prepare components
    val tpm = TpmAccess()
    if (!tpm.isAvailable()) {
        println("TMP not available")
    } else {
        println("TMP available")
    }
    // testPCR(tpm)
    // testGetQuote(tpm)
    // testTPMKeyStorage(tpm)

    val processMonitor = ProcessMonitor(config.allowedExecutables)

    val hashCalculator = FileHashCalculator

    val fileScanner = FileScanner()

    val fileIntegrity = FileIntegrity(
        tpm = tpm,
        fileScanner = fileScanner,
        hashCalculator = hashCalculator,
        config = config,
    )

    // Start server
    val service = AttestationService(
        tpm = tpm,
        monitor = processMonitor,
        fileScanner = fileScanner,
        fileIntegrity = fileIntegrity,
        config = config,
    )
    service.initialize()

    val server = AttestationServer(config, service)
    server.start()
}

fun testPCR(tpm: TpmAccess) {
    val initial = tpm.readPCRs(listOf(10))
    println("Initial: ${initial[23]?.toHexString()}")

    val hash = byteArrayOf(
        0x6c.toByte(), 0xa1.toByte(), 0x3d.toByte(), 0x52.toByte(),
        0x6c.toByte(), 0xa1.toByte(), 0x3d.toByte(), 0x52.toByte(),
        0x6c.toByte(), 0xa1.toByte(), 0x3d.toByte(), 0x52.toByte(),
        0x6c.toByte(), 0xa1.toByte(), 0x3d.toByte(), 0x52.toByte(),
        0x6c.toByte(), 0xa1.toByte(), 0x3d.toByte(), 0x52.toByte(),
        0x6c.toByte(), 0xa1.toByte(), 0x3d.toByte(), 0x52.toByte(),
        0x6c.toByte(), 0xa1.toByte(), 0x3d.toByte(), 0x52.toByte(),
        0x6c.toByte(), 0xa1.toByte(), 0x3d.toByte(), 0x52.toByte(),
    )

    tpm.extendPCR(23, hash)

    val updated = tpm.readPCRs(listOf(23))
    println("After extend:  ${updated[23]?.toHexString()}")

    tpm.resetPCR(23)
    val reset = tpm.readPCRs(listOf(23))

    println("After reset:  ${reset[23]?.toHexString()}")
}

fun testGetQuote(tpm: TpmAccess) {
    println("TEST GENERATE QUOTE")

    try {
        if (!tpm.isAvailable()) {
            println("TPM not available")
            return
        }
        println("TPM is available")

        val nonce = generateRandomNonce(32)

        val result = tpm.generateQuote(nonce, listOf(23))
        println("QUOTE:" + result.quote)
        println("SIGNATURE:" + result.signature)
        println("ATTESTATION KEY:" + result.attestationKey)
    } catch (e: Exception) {
        println(e.message)
    }
}

fun generateRandomNonce(size: Int): ByteArray {
    return ByteArray(size) {
        (kotlin.random.Random.nextInt(256)).toByte()
    }
}
