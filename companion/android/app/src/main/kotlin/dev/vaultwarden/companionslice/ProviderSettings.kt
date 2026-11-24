package dev.vaultwarden.companionslice

import android.util.AtomicFile
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.net.URI

class SettingsException(val code: String) : Exception(code)

/**
 * Provider configuration in `noBackupFilesDir` (excluded from backup and
 * device transfer), never in shared preferences. Holds the endpoint, the
 * provider CA (DER), the leaf pin, the client identity's Keystore alias and
 * the recovery marker; no password, ticket or review.
 */
class ProviderSettings(directory: File) {
    data class Saved(val endpoint: URI, val ca: ByteArray, val pin: String, val identityAlias: String, val recovery: RecoveryState)

    private val file = AtomicFile(File(File(directory, "provider"), "configuration-v1.json"))

    val exists: Boolean get() = file.baseFile.exists()

    fun load(): Saved {
        val bytes = try { file.readFully() } catch (_: Exception) { throw SettingsException("provider_configuration_unreadable") }
        try {
            if (bytes.size > 131_072) throw IllegalStateException()
            val json = JSONObject(String(bytes, Charsets.UTF_8))
            val endpoint = ProviderRules.endpoint(json.getString("endpoint"))!!
            val ca = Base64.decode(json.getString("ca"), Base64.NO_WRAP)
            PinnedTrustManager.certificate(ca)
            val pin = json.getString("pin").also { require(Wire.validHex(it, 64)) }
            val alias = json.getString("identityAlias").also { require(it.startsWith(ClientIdentity.ALIAS_PREFIX)) }
            val pending = json.optString("pendingId", "").ifEmpty { null }
            val management = json.optJSONObject("management")
            val recovery = RecoveryState(
                pendingId = pending,
                managementKind = management?.getString("kind"),
                managementId = management?.getString("id"),
                managementAction = management?.getString("action_id"),
            )
            if (pending != null) require(Wire.validRequestId(pending))
            if (management != null) {
                require(pending == null && RecoveryState.validManagement(recovery.managementKind!!, recovery.managementId!!, recovery.managementAction!!))
            }
            return Saved(endpoint, ca, pin, alias, recovery)
        } catch (_: Exception) {
            throw SettingsException("provider_configuration_invalid")
        }
    }

    fun save(saved: Saved) {
        file.baseFile.parentFile?.mkdirs()
        val json = JSONObject()
            .put("endpoint", saved.endpoint.toString())
            .put("ca", Base64.encodeToString(saved.ca, Base64.NO_WRAP))
            .put("pin", saved.pin)
            .put("identityAlias", saved.identityAlias)
        saved.recovery.pendingId?.let { json.put("pendingId", it) }
        if (saved.recovery.managementAction != null) {
            json.put("management", JSONObject().put("kind", saved.recovery.managementKind)
                .put("id", saved.recovery.managementId).put("action_id", saved.recovery.managementAction))
        }
        val stream = file.startWrite()
        try {
            stream.write(json.toString().toByteArray(Charsets.UTF_8))
            file.finishWrite(stream)
        } catch (error: Exception) {
            file.failWrite(stream)
            throw error
        }
    }

    fun hasPending(): Boolean = exists && load().recovery.hasPending

    /** The `configuration` reply the Dart `NativeProviderPlatform._parse` accepts. */
    fun metadata(): Map<String, Any> {
        if (!exists) return mapOf("configured" to false)
        val saved = load()
        val fingerprint = ClientIdentity.fingerprint(saved.identityAlias) ?: throw SettingsException("provider_identity_unavailable")
        return mapOf(
            "configured" to true,
            "endpoint" to saved.endpoint.toString(),
            "pin" to saved.pin,
            "fingerprint" to fingerprint,
            "uncertainId" to (saved.recovery.pendingId ?: ""),
            "managementRecovery" to saved.recovery.managementJson(),
        )
    }
}
