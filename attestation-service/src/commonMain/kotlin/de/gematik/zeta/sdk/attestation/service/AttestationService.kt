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

import de.gematik.zeta.sdk.attestation.interfaces.FileIntegrity
import de.gematik.zeta.sdk.attestation.interfaces.FileScanner
import de.gematik.zeta.sdk.attestation.interfaces.ProcessMonitor
import de.gematik.zeta.sdk.attestation.model.AttestationRequest
import de.gematik.zeta.sdk.attestation.model.AttestationResponse
import de.gematik.zeta.sdk.attestation.model.FileMonitorRequest
import de.gematik.zeta.sdk.attestation.model.HealthCheck
import de.gematik.zeta.sdk.attestation.model.ProcessPidResponse
import de.gematik.zeta.sdk.attestation.model.QuoteResponse
import de.gematik.zeta.sdk.attestation.model.VerifyIntegrityRequest
import de.gematik.zeta.sdk.attestation.model.VerifyIntegrityResponse
import de.gematik.zeta.sdk.attestation.service.ErrorCode
import de.gematik.zeta.sdk.attestation.service.ServiceError
import de.gematik.zeta.sdk.attestation.service.TpmException
import de.gematik.zeta.sdk.attestation.tpm.TpmAccess
import io.ktor.http.RequestConnectionPoint
import kotlin.io.encoding.Base64
import kotlin.time.Clock

class AttestationService(
    private val monitor: ProcessMonitor,
    private val fileScanner: FileScanner,
    private val fileIntegrity: FileIntegrity,
    private val tpm: TpmAccess,
    private val config: ServiceConfig,
) {
    private val startTime = Clock.System.now()

    fun initialize() {
        val akPubKey = tpm.provisionAttestationKey()
        fileIntegrity.initialize(config.resetFileIntegrity)
        println("AK initialized, size: ${akPubKey.size}")
    }

    fun buildAttestationResponse(
        request: AttestationRequest,
        origin: RequestConnectionPoint,
    ): AttestationResponse {
        val quoteResult = getQuote(request.attestationChallenge, request.pcrSelection, origin)
        if (quoteResult.error != null) {
            return AttestationResponse(error = quoteResult.error)
        }

        val akPubKeyPem = b64UrlNoPadding().encode(quoteResult.attestationKey)
        val quoteBase64 = b64UrlNoPadding().encode(quoteResult.quote)

        val quoteSignatureBase64 = b64UrlNoPadding().encode(quoteResult.signature)

        val eventLog = tpm.getEventLog()
        val eventLogBase64 = b64UrlNoPadding().encode(eventLog)

        val ekCerts = tpm.getEKCertificateChain()
        val ekCertsPem = ekCerts.map { b64UrlNoPadding().encode(it) }

        return AttestationResponse(
            tpmAttestationKey = akPubKeyPem,
            tpmQuote = quoteBase64,
            tpmQuoteSignature = quoteSignatureBase64,
            tpmEventLog = eventLogBase64,
            tpmEkCertificateChain = ekCertsPem,
            error = null,
        )
    }

    private fun b64UrlNoPadding(): Base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

    private fun getQuote(attestationChallenge: String, pcrSelection: List<Int>, origin: RequestConnectionPoint): QuoteResponse {
        if (attestationChallenge.isEmpty()) {
            return QuoteResponse(error = ServiceError(ErrorCode.INVALID_ARGUMENT, "attestationChallenge is empty"))
        }

        if (pcrSelection.isEmpty()) {
            return QuoteResponse(error = ServiceError(ErrorCode.INVALID_ARGUMENT, "prcSelection is empty"))
        }

        val attChallengeBytes = try {
            Base64.decode(attestationChallenge)
        } catch (_: IllegalArgumentException) {
            return QuoteResponse(error = ServiceError(code = ErrorCode.INVALID_ARGUMENT, message = "attestationChallenge must be base64"))
        }

        if (!tpm.isAvailable()) {
            return QuoteResponse(error = ServiceError(ErrorCode.TPM_NOT_AVAILABLE, "TPM not available"))
        }

        if (!fileIntegrity.isIntact()) {
            return QuoteResponse(error = ServiceError(ErrorCode.INTERNAL_ERROR, "Filesystem integrity violated"))
        }

        if (!monitor.isProcessAllowed(origin)) {
            return QuoteResponse(error = ServiceError(ErrorCode.PROCESS_NOT_ALLOWED, "Client process not allowed"))
        }

        return try {
            val result = tpm.generateQuote(
                attChallengeBytes = attChallengeBytes,
                pcrSelection = pcrSelection,
            )

            QuoteResponse(
                quote = result.quote,
                signature = result.signature,
                attestationKey = result.attestationKey,
                error = null,
            )
        } catch (tpmEx: TpmException) {
            QuoteResponse(error = ServiceError(code = ErrorCode.TPM_QUOTE_ERROR, message = tpmEx.message ?: "Unexpected error"))
        } catch (e: Exception) {
            println("Unexpected error: ${e.message}")
            QuoteResponse(error = ServiceError(code = ErrorCode.INTERNAL_ERROR, message = "Internal error"))
        }
    }

    fun verifyIntegrity(request: VerifyIntegrityRequest): VerifyIntegrityResponse {
        return fileIntegrity.verifyIntegrity(request.filePaths)
    }

    fun currentIntegrityState(): VerifyIntegrityResponse {
        return fileIntegrity.verifyIntegrity(config.files)
    }

    fun subscribeIntegrity(onUpdate: (VerifyIntegrityResponse) -> Unit): () -> Unit {
        return fileIntegrity.subscribe(onUpdate)
    }

    fun health(): HealthCheck {
        val uptime = (Clock.System.now() - startTime).inWholeSeconds

        return HealthCheck(
            status = "OK",
            tpmAvaliable = tpm.isAvailable(),
            processRunning = monitor.isRunning("attestation-service"),
            uptime = uptime,
        )
    }

    fun processPid(origin: RequestConnectionPoint): ProcessPidResponse {
        println("processPid: local = ${origin.localHost}:${origin.localPort}, remote = ${origin.remoteHost}:${origin.remotePort}")
        val processPid = monitor.findSocketAndPid(origin)
        val processName = monitor.getProcessName(processPid)
        return ProcessPidResponse(processPid?.toLong(), processName)
    }

    fun fileMonitor(request: FileMonitorRequest, onModified: (String, String) -> Unit) {
        val files = request.filePaths
        fileScanner.startMonitoring(files) { file, event ->
            println("onModified: $file, $event")
            onModified(file, event)
        }
    }

    fun stopFileMonitor() {
        fileScanner.stopMonitoring()
    }
}

data class ServiceConfig(
    val files: List<String>,
    val port: Int,
    val pcrId: Int,
    val resetFileIntegrity: Boolean,
    val allowedExecutables: List<String> = emptyList(),
)
