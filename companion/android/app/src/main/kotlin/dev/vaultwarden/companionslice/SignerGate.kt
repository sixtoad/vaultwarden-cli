package dev.vaultwarden.companionslice

/**
 * Admission state of the approval-key channel; a port of
 * `ProductionSignerGate` (ProductionApprovalContract.swift). At most one
 * signature is open; read, create and delete wait for it. Tokens are
 * strictly increasing within one Dart session (16 random bytes, hex); a new
 * session restarts the numbering. Cancel acts only on the open signature of
 * the same session and token. Not thread-safe: call on the main thread.
 */
class SignerGate {
    private var session = ""
    private var lastToken = 0L
    private var active: Triple<String, Long, () -> Unit>? = null

    val idle: Boolean get() = active == null

    fun begin(session: String, token: Long, cancel: () -> Unit): Boolean {
        if (active != null || !validSession(session) || token <= 0 || token > 0xffffffffL) return false
        if (session != this.session) {
            this.session = session
            lastToken = 0
        }
        if (token <= lastToken) return false
        lastToken = token
        active = Triple(session, token, cancel)
        return true
    }

    fun finish(session: String, token: Long) {
        val open = active ?: return
        if (open.first == session && open.second == token) active = null
    }

    fun cancel(session: String, token: Long) {
        val open = active ?: return
        if (open.first == session && open.second == token) open.third()
    }

    /** Backgrounding, screen off, activity destruction: cancel whatever is open. */
    fun cancelActive() {
        active?.third?.invoke()
    }

    companion object {
        fun validSession(value: String): Boolean = Wire.validHex(value, 32)
    }
}

/**
 * The Android lifecycle signals that cancel an open prompt and invalidate
 * provider state. [reason] is the provider channel's `invalidate` argument
 * (`docs/mobile-clients.md`: `inactive` or `close`); [deviceSignal] is what
 * the `.../lifecycle` channel sends Dart (`locked`), if anything.
 *
 * `onPause` and window-focus loss are deliberately absent: BiometricPrompt
 * itself takes window focus (and pauses the activity on some devices), so
 * either would cancel every prompt. Flutter already reports them as
 * `AppLifecycleState.inactive`. `onStop` (no longer visible: home, recents,
 * another app, the lock screen over it), screen off and destruction all fire
 * before anything else can be shown.
 */
enum class LifecycleTrigger(val reason: String, val deviceSignal: String?) {
    STOP("inactive", null),
    SCREEN_OFF("inactive", "locked"),
    DESTROY("close", null),
}
