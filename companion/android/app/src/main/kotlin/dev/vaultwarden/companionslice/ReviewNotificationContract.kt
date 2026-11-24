package dev.vaultwarden.companionslice

/**
 * Review-request notification rules (#61), ported from
 * `ReviewNotificationContract.swift`. The only text a notification shows is
 * fixed here, natively; Flutter supplies only an opaque 22-character token,
 * which maps to the request in Flutter memory. A notification has no action
 * buttons: a tap opens a FRESH review of that request and never approves.
 */
object ReviewNotificationContract {
    const val TITLE = "Approval companion"
    const val BODY = "A request needs your review."
    const val CHANNEL_ID = "review-requests"
    const val CHANNEL_NAME = "Review requests"
    const val EXTRA_TOKEN = "dev.vaultwarden.companionSlice.reviewToken"
    const val ACTION_OPEN = "dev.vaultwarden.companionSlice.OPEN_REVIEW"
    const val NOTIFICATION_ID = 0x5160

    /** 16 random bytes, base64url: request ids are 43 characters, so never a token. */
    fun validToken(value: String): Boolean =
        value.length == 22 && value.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }

    /** `post` arguments: exactly `{"token": <valid token>}`. */
    fun token(fromPost: Any?): String? {
        val map = fromPost as? Map<*, *> ?: return null
        val token = map["token"] as? String ?: return null
        return if (map.size == 1 && validToken(token)) token else null
    }

    /** `withdraw` arguments: exactly `{"tokens": [1..256 valid tokens]}`. */
    fun tokens(fromWithdraw: Any?): List<String>? {
        val map = fromWithdraw as? Map<*, *> ?: return null
        val list = map["tokens"] as? List<*> ?: return null
        if (map.size != 1 || list.size !in 1..256) return null
        val tokens = list.map { it as? String ?: return null }
        return if (tokens.all(::validToken)) tokens else null
    }

    /** Taps that arrived before Flutter listened, oldest first; a repeat moves to the end. */
    class PendingOpens {
        private val tokens = ArrayDeque<String>()
        fun enqueue(token: String) {
            if (!validToken(token)) return
            tokens.remove(token)
            tokens.addLast(token)
            while (tokens.size > LIMIT) tokens.removeFirst()
        }
        fun drain(): List<String> = tokens.toList().also { tokens.clear() }
        companion object { const val LIMIT = 8 }
    }

    /**
     * The permission prompt runs only right after the Settings toggle armed it
     * (one-shot, within 10 s, app in front). A refusal disarms too.
     */
    class AuthorizationGate {
        private var armedAt: Long? = null
        fun arm(nowMillis: Long) { armedAt = nowMillis }
        fun consume(nowMillis: Long, appActive: Boolean): Boolean {
            val armed = armedAt
            armedAt = null
            if (armed == null || !appActive) return false
            val age = nowMillis - armed
            return age in 0..WINDOW_MILLIS
        }
        companion object { const val WINDOW_MILLIS = 10_000L }
    }

    /**
     * Status names shared with Flutter. Android 13+ needs a runtime grant;
     * before the user was ever asked it is `notDetermined`.
     */
    fun statusName(enabledBySystem: Boolean, runtimeGranted: Boolean, needsRuntime: Boolean, asked: Boolean): String = when {
        needsRuntime && !runtimeGranted -> if (asked) "denied" else "notDetermined"
        enabledBySystem -> "authorized"
        else -> "denied"
    }
}
