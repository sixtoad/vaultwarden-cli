package dev.vaultwarden.companionslice

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.Executors

/**
 * `dev.vaultwarden.companionSlice/provider` on Android: the contract of
 * `ProviderAdapter.swift` (configuration, setup, send, settle; native
 * `invalidate` on lifecycle). Presentation and protocol state stay in
 * Flutter/Rust; this owns file selection, the client identity and TLS.
 */
class ProviderChannel(private val activity: FragmentActivity, messenger: BinaryMessenger) {
    private val channel = MethodChannel(messenger, NAME)
    private val settings = ProviderSettings(activity.noBackupFilesDir)
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val managementGate = ManagementTransportGate { SystemClock.elapsedRealtime() }
    private var active = false
    private var setup: PendingSetup? = null

    private class PendingSetup(val endpoint: java.net.URI, val pin: String, val passphrase: String,
                               val result: MethodChannel.Result) {
        var ca: ByteArray? = null
    }

    init {
        channel.setMethodCallHandler(::handle)
    }

    private val foreground: Boolean
        get() = activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) && !activity.isFinishing

    /** Lifecycle (`LifecycleTrigger`): discard prepared tickets and tell Dart. */
    fun invalidate(trigger: LifecycleTrigger) {
        managementGate.invalidate()
        // The system file picker of an open setup stops this activity; setup
        // requires no pending request, so only the picker's own stop is
        // withheld from Dart. Screen off and destruction always reach it.
        if (setup != null && trigger == LifecycleTrigger.STOP) return
        channel.invokeMethod("invalidate", trigger.reason)
    }

    fun dispose() {
        channel.setMethodCallHandler(null)
        worker.shutdown()
    }

    private fun fail(result: MethodChannel.Result, error: Throwable?) {
        val code = (error as? SettingsException)?.code ?: "provider_unavailable"
        // Never return exception text, paths, request bodies or passwords.
        result.error(code, "Provider setup, trust or transport unavailable.", null)
    }

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        try {
            when (call.method) {
                "configuration" -> worker.execute {
                    val reply = runCatching { settings.metadata() }
                    main.post { reply.fold({ result.success(it) }, { fail(result, it) }) }
                }
                "setup" -> beginSetup(call, result)
                "send" -> send(call, result)
                "settle" -> {
                    val id = call.arguments as? String
                    if (id == null || !Wire.validRequestId(id)) return fail(result, null)
                    worker.execute {
                        val outcome = runCatching {
                            val saved = settings.load()
                            val next = saved.recovery.settle(id) ?: throw SettingsException("provider_unavailable")
                            settings.save(saved.copy(recovery = next))
                        }
                        main.post { outcome.fold({ result.success(null) }, { fail(result, it) }) }
                    }
                }
                else -> result.notImplemented()
            }
        } catch (error: Exception) {
            fail(result, error)
        }
    }

    private fun beginSetup(call: MethodCall, result: MethodChannel.Result) {
        val args = call.arguments as? Map<*, *>
        val endpoint = (args?.get("endpoint") as? String)?.let(ProviderRules::endpoint)
        val pin = args?.get("pin") as? String
        val passphrase = args?.get("passphrase") as? String
        if (active || setup != null || !foreground || args?.keys != setOf("endpoint", "pin", "passphrase") ||
            endpoint == null || pin == null || !Wire.validHex(pin, 64) ||
            passphrase == null || passphrase.toByteArray().size > 4096 || settings.hasPending()) return fail(result, null)
        setup = PendingSetup(endpoint, pin, passphrase, result)
        pick(REQUEST_CA)
    }

    private fun pick(request: Int) {
        // Storage Access Framework: the user chooses the file; no storage permission.
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
        @Suppress("DEPRECATION") activity.startActivityForResult(intent, request)
    }

    /** Forwarded from `MainActivity.onActivityResult`; true when it was ours. */
    fun onActivityResult(request: Int, code: Int, data: Intent?): Boolean {
        if (request != REQUEST_CA && request != REQUEST_IDENTITY) return false
        val pending = setup ?: return true
        val uri = data?.data
        if (code != Activity.RESULT_OK || uri == null) {
            setup = null
            fail(pending.result, null)
            return true
        }
        worker.execute {
            val bytes = runCatching { read(uri, if (request == REQUEST_CA) 65_536 else 1_048_576) }.getOrNull()
            main.post {
                if (bytes == null) { setup = null; return@post fail(pending.result, null) }
                if (request == REQUEST_CA) {
                    pending.ca = bytes
                    pick(REQUEST_IDENTITY)
                } else {
                    install(pending, bytes)
                }
            }
        }
        return true
    }

    private fun install(pending: PendingSetup, pkcs12: ByteArray) {
        worker.execute {
            val outcome = runCatching {
                val ca = pending.ca ?: throw SettingsException("provider_configuration_invalid")
                // Validate routing and trust before importing anything.
                PinnedTrustManager(PinnedTrustManager.certificate(ca), pending.pin)
                if (settings.hasPending()) throw SettingsException("provider_unavailable")
                val (alias, _) = ClientIdentity.import(pkcs12, pending.passphrase)
                    ?: throw SettingsException("provider_identity_unavailable")
                settings.save(ProviderSettings.Saved(pending.endpoint, ca, pending.pin, alias, RecoveryState()))
                settings.metadata()
            }
            pkcs12.fill(0)
            main.post {
                setup = null
                outcome.fold({ pending.result.success(it) }, { fail(pending.result, it) })
            }
        }
    }

    private fun read(uri: Uri, maximum: Int): ByteArray {
        val bytes = activity.contentResolver.openInputStream(uri)!!.use { input ->
            val buffer = java.io.ByteArrayOutputStream()
            val chunk = ByteArray(8192)
            while (true) {
                val n = input.read(chunk)
                if (n < 0) break
                if (buffer.size() + n > maximum) throw SettingsException("oversized")
                buffer.write(chunk, 0, n)
            }
            buffer.toByteArray()
        }
        if (bytes.isEmpty()) throw SettingsException("oversized")
        return bytes
    }

    private fun send(call: MethodCall, result: MethodChannel.Result) {
        val body = call.arguments as? ByteArray
        if (active || body == null || body.size > ProviderRules.MAX_REQUEST) return fail(result, null)
        val epoch = managementGate.begin(body, foreground) ?: return fail(result, null)
        active = true
        worker.execute {
            val outcome = runCatching {
                val saved = settings.load()
                val identity = ClientIdentity.keyManager(saved.identityAlias) ?: throw SettingsException("provider_identity_unavailable")
                val transport = PinnedTransport(saved.endpoint, PinnedTrustManager(PinnedTrustManager.certificate(saved.ca), saved.pin), identity)
                // Persist the recovery marker before sending: even a crash leaves it uncertain.
                val next = saved.recovery.beforeSend(body) ?: throw SettingsException("provider_unavailable")
                if (next != saved.recovery) settings.save(saved.copy(recovery = next))
                transport.send(body)
            }
            main.post {
                active = false
                outcome.fold({ response ->
                    if (managementGate.finish(body, response, epoch, foreground)) result.success(response) else fail(result, null)
                }, { fail(result, it) })
            }
        }
    }

    companion object {
        const val NAME = "dev.vaultwarden.companionSlice/provider"
        const val REQUEST_CA = 0x5601
        const val REQUEST_IDENTITY = 0x5602
    }
}
