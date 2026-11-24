package dev.vaultwarden.companionslice

import org.json.JSONObject
import java.net.URI

/**
 * Provider configuration and response rules, ported from
 * `macos/Sources/CompanionCore` (`ProviderConfiguration`, `RequestDelegate`,
 * `RequestTimeoutPolicy`, `ErrorResponse`). Pure JVM: unit tests pin them.
 */
object ProviderRules {
    const val MAX_REQUEST = 16_384
    const val MAX_RESPONSE = 1_048_576
    val allowedStatus = setOf(200, 400, 403, 409, 422, 429, 503)
    private val errorStatus = mapOf(
        "invalid_request" to 400, "unauthorized" to 403, "stale" to 409,
        "authentication_failed" to 422, "rate_limited" to 429, "unavailable" to 503,
    )

    /** https only, a host, no userinfo/query/fragment, path "", "/" or "/v1/companion"; normalised to /v1/companion. */
    fun endpoint(text: String): URI? {
        if (text.length > 2048 || text.any { it.isWhitespace() || it == '\\' }) return null
        val uri = try { URI(text) } catch (_: Exception) { return null }
        val host = uri.host
        if (uri.scheme != "https" || host.isNullOrEmpty() || uri.rawUserInfo != null ||
            uri.rawQuery != null || uri.rawFragment != null ||
            (uri.port != -1 && uri.port !in 1..65535) ||
            uri.rawPath !in setOf("", "/", "/v1/companion")) return null
        return try { URI("https", null, host, uri.port, "/v1/companion", null, null) } catch (_: Exception) { null }
    }

    /** Only an exact v1 unlock (no other members) gets the longer wait; it grants no authority. */
    fun timeoutSeconds(body: ByteArray): Int {
        val json = parse(body) ?: return 5
        val password = json.opt("password") as? String ?: return 5
        val version = json.opt("version")
        return if (json.length() == 3 && json.opt("command") == "unlock" && version is Int && version == 1 &&
            password.isNotEmpty() && password.toByteArray().size <= 4096) 60 else 5
    }

    /**
     * HTTP status and JSON body form one protocol response: a 200 must not
     * carry `error`, any other status must be the exact v1 error envelope
     * whose error maps to that status.
     */
    fun acceptsResponse(status: Int, contentType: String?, contentEncoding: String?, body: ByteArray): Boolean {
        if (status !in allowedStatus || body.size > MAX_RESPONSE || contentEncoding != null) return false
        if (contentType?.substringBefore(';')?.trim()?.lowercase() != "application/json") return false
        val json = parse(body) ?: return false
        if (status == 200) return !json.has("error")
        val version = json.opt("version")
        val error = json.opt("error") as? String ?: return false
        return json.length() == 2 && version is Int && version == 1 && errorStatus[error] == status
    }

    fun parse(body: ByteArray): JSONObject? = try {
        JSONObject(String(body, Charsets.UTF_8))
    } catch (_: Exception) {
        null
    }
}

/**
 * The object's member names. Android's org.json has no public `keySet()`
 * (it is `@hide`, absent from android.jar); `keys()` is public API on Android
 * and in the Maven org.json the unit tests run against.
 * `OrgJsonAndroidApiTest` refuses the Maven-only members in main sources.
 */
internal fun JSONObject.memberNames(): Set<String> = keys().asSequence().toSet()

/**
 * The durable recovery marker (`ProviderSettings.beforeSend`/`settle` on
 * macOS): a sent decision stays uncertain until Dart settles it, and while it
 * is unresolved only its own `status` may be sent and the configuration may
 * not be replaced. Same for an administrative revocation (`identity_revoke`).
 * The marker holds no password, ticket or review.
 */
data class RecoveryState(val pendingId: String? = null, val managementKind: String? = null,
                         val managementId: String? = null, val managementAction: String? = null) {
    val hasPending: Boolean get() = pendingId != null || managementAction != null

    /** The state to persist BEFORE the body is sent, or null to refuse sending it. */
    fun beforeSend(body: ByteArray): RecoveryState? {
        val json = ProviderRules.parse(body) ?: return null
        val command = json.opt("command") as? String ?: return null
        if (pendingId != null && (command != "status" || json.opt("request_id") != pendingId)) return null
        if (managementAction != null) {
            val target = json.optJSONObject("target") ?: return null
            if (command != "identity_status" || json.opt("version") != 2 || json.memberNames() != setOf("version", "command", "target", "action_id") ||
                target.memberNames() != setOf("kind", "id") || target.opt("kind") != managementKind ||
                target.opt("id") != managementId || json.opt("action_id") != managementAction) return null
        }
        var next = this
        if (command == "identity_revoke") {
            val target = json.optJSONObject("target") ?: return null
            val kind = target.opt("kind") as? String
            val id = target.opt("id") as? String
            val action = json.opt("action_id") as? String
            val ticket = json.opt("ticket") as? String
            val password = json.opt("password") as? String
            if (hasPending || json.memberNames() != setOf("version", "command", "target", "action_id", "ticket", "password") ||
                json.opt("version") != 2 || target.memberNames() != setOf("kind", "id") ||
                kind == null || id == null || action == null || ticket == null || !Wire.validHex(ticket, 64) ||
                password.isNullOrEmpty() || password.toByteArray().size > 4096 || !validManagement(kind, id, action)) return null
            next = next.copy(managementKind = kind, managementId = id, managementAction = action)
        }
        if (command == "decision") {
            val id = json.opt("request_id") as? String
            if (id == null || !Wire.validRequestId(id)) return null
            next = next.copy(pendingId = id)
        }
        return next
    }

    /** The state after Dart settled [id], or null to refuse. */
    fun settle(id: String): RecoveryState? = when {
        managementAction != null -> if (managementAction == id && pendingId == null) RecoveryState() else null
        pendingId == id -> copy(pendingId = null)
        else -> null
    }

    fun managementJson(): String = if (managementAction == null) "" else JSONObject()
        .put("target", JSONObject().put("kind", managementKind).put("id", managementId))
        .put("action_id", managementAction).toString()

    companion object {
        fun validManagement(kind: String, id: String, action: String): Boolean = Wire.validRequestId(action) &&
            ((kind == "approval_client" && Wire.validHex(id, 64)) || (kind == "requester_agent" && Wire.validRequestId(id)))
    }
}

/**
 * Lifecycle binding for administrative tickets (`ManagementTransportGate`):
 * a ticket prepared in the foreground is usable once, within 55 s, and any
 * lifecycle invalidation (background, screen off) discards it. [now] is a
 * monotonic clock in milliseconds (`SystemClock.elapsedRealtime`).
 */
class ManagementTransportGate(private val now: () -> Long) {
    private var epoch = 0L
    private var prepared: Map<String, String>? = null
    private var deadline = 0L

    fun invalidate() {
        epoch += 1; prepared = null; deadline = 0
    }

    /** Returns the epoch to hand to [finish], or null to refuse the send. */
    fun begin(body: ByteArray, foreground: Boolean): Long? {
        val json = ProviderRules.parse(body) ?: return null
        when (json.opt("command") as? String ?: return null) {
            "identity_prepare" -> {
                invalidate()
                if (!foreground) return null
                deadline = now() + 55_000
            }
            "identity_revoke" -> {
                val expected = prepared
                val expires = deadline
                invalidate() // one send attempt
                if (!foreground || now() >= expires || expected == null || binding(json) != expected) return null
            }
            "identity_list", "identity_detail" -> invalidate()
        }
        return epoch
    }

    /** False refuses the response (it is not handed to Dart). */
    fun finish(request: ByteArray, response: ByteArray, started: Long, foreground: Boolean): Boolean {
        val body = ProviderRules.parse(request) ?: return false
        if (body.opt("command") != "identity_prepare") return true
        if (!foreground || started != epoch || now() >= deadline) return false
        val reply = ProviderRules.parse(response) ?: return true
        val identity = reply.optJSONObject("identity") ?: return true
        val target = body.optJSONObject("target") ?: return true
        if (reply.opt("version") != 2 || identity.opt("kind") != target.opt("kind") || identity.opt("id") != target.opt("id")) return true
        reply.put("target", target)
        prepared = binding(reply)
        return true
    }

    private fun binding(value: JSONObject): Map<String, String>? {
        val target = value.optJSONObject("target") ?: return null
        val kind = target.opt("kind") as? String ?: return null
        val id = target.opt("id") as? String ?: return null
        val action = value.opt("action_id") as? String ?: return null
        val ticket = value.opt("ticket") as? String ?: return null
        if (!Wire.validHex(ticket, 64) || !RecoveryState.validManagement(kind, id, action)) return null
        return mapOf("kind" to kind, "id" to id, "action_id" to action, "ticket" to ticket)
    }
}
