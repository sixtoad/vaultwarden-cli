package dev.vaultwarden.companionslice

import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.Executors

/**
 * `dev.vaultwarden.companionSlice/approvalKey` on Android: the same closed
 * contract as `ProductionSigner.swift` (read, create, delete, sign, cancel,
 * availability; replies `{outcome, publicKey, signature}`).
 *
 * A signature exists only after BiometricPrompt authenticated the
 * `CryptoObject` wrapping THIS operation's `Signature`: the Keystore key
 * admits one operation per authentication (validity 0), so neither an earlier
 * authentication nor another request's prompt can produce it. Cancellation,
 * any prompt error, backgrounding and screen off reply without a signature.
 */
class ApprovalKeyChannel(private val activity: FragmentActivity, messenger: BinaryMessenger) {
    private val channel = MethodChannel(messenger, NAME)
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val gate = SignerGate()

    init {
        channel.setMethodCallHandler(::handle)
    }

    fun biometricAvailable(): Boolean =
        BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    /** Lifecycle cancellation (`LifecycleTrigger`). */
    fun cancelActive() = gate.cancelActive()

    fun dispose() {
        gate.cancelActive()
        channel.setMethodCallHandler(null)
        worker.shutdown()
    }

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "availability" -> result.success(if (biometricAvailable()) AVAILABLE else "unavailable")
            "cancel" -> {
                val args = call.arguments as? Map<*, *>
                val session = args?.get("session") as? String
                val token = (args?.get("token") as? Number)?.toLong()
                if (args?.size == 2 && session != null && token != null) gate.cancel(session, token)
                result.success(null)
            }
            "read", "create", "delete" -> {
                val binding = binding(call.arguments, emptySet())
                if (!gate.idle || binding == null) return invalid(result)
                val method = call.method
                val available = method == "create" && biometricAvailable()
                worker.execute {
                    val reply = when (method) {
                        "read" -> ApprovalKeyStore.read(binding)
                        "create" -> ApprovalKeyStore.create(binding, available)
                        else -> ApprovalKeyStore.delete(binding)
                    }
                    main.post { result.success(reply.encode()) }
                }
            }
            "sign" -> sign(call, result)
            else -> result.notImplemented()
        }
    }

    private fun sign(call: MethodCall, result: MethodChannel.Result) {
        val args = call.arguments as? Map<*, *>
        val binding = binding(args, setOf("session", "token", "purpose", "transcript"))
        val session = args?.get("session") as? String
        val token = (args?.get("token") as? Number)?.toLong()
        val purpose = (args?.get("purpose") as? String)?.let { name -> ApprovalPurpose.entries.firstOrNull { it.name == name } }
        val transcript = args?.get("transcript") as? ByteArray
        if (!gate.idle || binding == null || session == null || token == null || purpose == null ||
            transcript == null || transcript.size > ApprovalTranscript.MAX_BYTES) return invalid(result)
        val operation = Operation(result)
        if (!gate.begin(session, token) { operation.cancel() }) return invalid(result)
        operation.onFinish = { gate.finish(session, token) }
        worker.execute {
            val (prepared, failure) = ApprovalKeyStore.prepare(binding, purpose, transcript)
            main.post {
                if (prepared == null) return@post operation.reply(failure ?: KeyReply(KeyOutcome.failed))
                operation.prompt(binding, purpose, transcript, prepared)
            }
        }
    }

    /** One open signature; replies exactly once. Main thread only. */
    private inner class Operation(private val result: MethodChannel.Result) {
        var onFinish: () -> Unit = {}
        private var done = false
        private var cancelled = false
        private var prompt: BiometricPrompt? = null

        fun cancel() {
            if (done) return
            cancelled = true
            // Reply now: not every androidx/OS pair reports ERROR_CANCELED after
            // cancelAuthentication, and a late success must find `done` set.
            prompt?.cancelAuthentication()
            reply(KeyReply(KeyOutcome.cancelled))
        }

        fun reply(value: KeyReply) {
            if (done) return
            done = true
            prompt = null
            onFinish()
            result.success(value.encode())
        }

        fun prompt(binding: ApprovalBinding, purpose: ApprovalPurpose, transcript: ByteArray,
                   prepared: ApprovalKeyStore.Prepared) {
            if (cancelled || done) return reply(KeyReply(KeyOutcome.cancelled))
            // Never prompt for a review the user can no longer see.
            if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) || activity.isFinishing) {
                return reply(KeyReply(KeyOutcome.cancelled))
            }
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    reply(KeyReply(AuthErrors.classify(errorCode)))
                }

                override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
                    val authorized = authResult.cryptoObject?.signature
                    // A biometric that did not unlock THIS Signature approves nothing,
                    // and a lifecycle cancel after the touch still wins.
                    if (authorized == null || cancelled || done) return reply(KeyReply(KeyOutcome.cancelled))
                    worker.execute {
                        val signed = ApprovalKeyStore.complete(binding, purpose, transcript, prepared, authorized)
                        main.post { reply(if (cancelled) KeyReply(KeyOutcome.cancelled) else signed) }
                    }
                }
                // onAuthenticationFailed (an unrecognised finger): the prompt stays open.
            }
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(if (purpose == ApprovalPurpose.approve) APPROVE_TITLE else ENROLL_TITLE)
                .setSubtitle(SUBTITLE)
                .setNegativeButtonText(CANCEL)
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setConfirmationRequired(true)
                .build()
            val biometricPrompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            prompt = biometricPrompt
            biometricPrompt.authenticate(info, BiometricPrompt.CryptoObject(prepared.signature))
        }
    }

    private fun invalid(result: MethodChannel.Result) =
        result.error("invalid_request", "Invalid or overlapping key operation", null)

    private fun binding(arguments: Any?, keys: Set<String>): ApprovalBinding? {
        val args = arguments as? Map<*, *> ?: return null
        if (args.keys != keys + setOf("providerIdentity", "approvalClient")) return null
        val provider = args["providerIdentity"] as? String ?: return null
        val client = args["approvalClient"] as? String ?: return null
        return ApprovalBinding.of(provider, client)
    }

    companion object {
        const val NAME = "dev.vaultwarden.companionSlice/approvalKey"

        /**
         * The `availability` reply when a BIOMETRIC_STRONG authenticator is
         * enrolled. Android never replies `deviceCredential`: the key does not
         * admit a PIN/pattern (`ApprovalKeySpec`).
         */
        const val AVAILABLE = "biometric"

        // Generic copy: the request itself is reviewed in the app, never in the prompt.
        const val APPROVE_TITLE = "Approve one provider request"
        const val ENROLL_TITLE = "Enroll this phone's approval key"
        const val SUBTITLE = "Confirm with your fingerprint or face"
        const val CANCEL = "Cancel"
    }
}
