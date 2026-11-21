package dev.vaultwarden.companionslice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProviderRulesTest {
    private val id = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
    private val action = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk"
    private val ticket = "4c".repeat(32)
    private val client = "2e".repeat(32)

    private fun bytes(text: String) = text.toByteArray()

    @Test fun endpointsAreHttpsToTheCompanionPathOnly() {
        assertEquals("https://p.example:8443/v1/companion", ProviderRules.endpoint("https://p.example:8443")!!.toString())
        assertEquals("https://p.example/v1/companion", ProviderRules.endpoint("https://p.example/")!!.toString())
        assertEquals("https://127.0.0.1/v1/companion", ProviderRules.endpoint("https://127.0.0.1/v1/companion")!!.toString())
        listOf(
            "http://p.example", "https://", "https://u:p@p.example", "https://p.example/?a=1",
            "https://p.example/#x", "https://p.example/other", "https://p.example /", "https://p.example\\x",
            "https://p.example:0", "ftp://p.example", "https://p.example/v1/companion/",
            "https://" + "a".repeat(2050),
        ).forEach { assertNull(it, ProviderRules.endpoint(it)) }
    }

    @Test fun onlyAnExactUnlockWaitsLonger() {
        assertEquals(60, ProviderRules.timeoutSeconds(bytes("""{"command":"unlock","password":"pw","version":1}""")))
        assertEquals(5, ProviderRules.timeoutSeconds(bytes("""{"command":"unlock","password":"","version":1}""")))
        assertEquals(5, ProviderRules.timeoutSeconds(bytes("""{"command":"unlock","password":"pw","version":1,"x":1}""")))
        assertEquals(5, ProviderRules.timeoutSeconds(bytes("""{"command":"unlock","password":"pw","version":1.0}""")))
        assertEquals(5, ProviderRules.timeoutSeconds(bytes("""{"command":"status","password":"pw","version":1}""")))
        assertEquals(5, ProviderRules.timeoutSeconds(bytes("""{"command":"unlock","password":"pw","password":"x","version":1}""")))
        assertEquals(5, ProviderRules.timeoutSeconds(bytes("not json")))
    }

    @Test fun statusAndBodyFormOneResponse() {
        val json = "application/json"
        assertTrue(ProviderRules.acceptsResponse(200, json, null, bytes("""{"version":1}""")))
        assertTrue(ProviderRules.acceptsResponse(200, "application/json; charset=utf-8", null, bytes("{}")))
        assertFalse(ProviderRules.acceptsResponse(200, json, null, bytes("""{"error":"stale"}""")))
        assertTrue(ProviderRules.acceptsResponse(409, json, null, bytes("""{"version":1,"error":"stale"}""")))
        assertFalse("error under the wrong status", ProviderRules.acceptsResponse(400, json, null, bytes("""{"version":1,"error":"stale"}""")))
        assertFalse(ProviderRules.acceptsResponse(503, json, null, bytes("""{"version":1,"error":"unavailable","x":1}""")))
        assertFalse(ProviderRules.acceptsResponse(500, json, null, bytes("{}")))
        assertFalse(ProviderRules.acceptsResponse(302, json, null, bytes("{}")))
        assertFalse(ProviderRules.acceptsResponse(200, "text/html", null, bytes("{}")))
        assertFalse(ProviderRules.acceptsResponse(200, json, "gzip", bytes("{}")))
        assertFalse(ProviderRules.acceptsResponse(200, json, null, bytes("[]")))
        assertFalse(ProviderRules.acceptsResponse(200, json, null, ByteArray(ProviderRules.MAX_RESPONSE + 1)))
    }

    @Test fun aDecisionStaysUncertainUntilSettled() {
        val start = RecoveryState()
        assertEquals(start, start.beforeSend(bytes("""{"version":1,"command":"status"}""")))
        val pending = start.beforeSend(bytes("""{"version":1,"command":"decision","request_id":"$id","ticket":"$ticket","decision":"approve"}"""))!!
        assertEquals(id, pending.pendingId)
        assertTrue(pending.hasPending)
        // While uncertain only that request's status may be sent.
        assertNull(pending.beforeSend(bytes("""{"version":1,"command":"list"}""")))
        assertNull(pending.beforeSend(bytes("""{"version":1,"command":"status","request_id":"$action"}""")))
        assertEquals(pending, pending.beforeSend(bytes("""{"version":1,"command":"status","request_id":"$id"}""")))
        assertNull(pending.settle(action))
        assertEquals(RecoveryState(), pending.settle(id))
        assertNull(start.beforeSend(bytes("""{"version":1,"command":"decision","request_id":"short"}""")))
        assertNull(start.beforeSend(bytes("not json")))
    }

    @Test fun anAdministrativeRevocationIsRecordedWithoutItsSecrets() {
        val revoke = """{"version":2,"command":"identity_revoke","target":{"kind":"approval_client","id":"$client"},"action_id":"$action","ticket":"$ticket","password":"pw"}"""
        val marked = RecoveryState().beforeSend(bytes(revoke))!!
        assertEquals(action, marked.managementAction)
        assertFalse(marked.managementJson().contains("pw"))
        assertFalse(marked.managementJson().contains(ticket))
        assertNull("only its identity_status", marked.beforeSend(bytes("""{"version":1,"command":"status","request_id":"$id"}""")))
        val status = """{"version":2,"command":"identity_status","target":{"kind":"approval_client","id":"$client"},"action_id":"$action"}"""
        assertEquals(marked, marked.beforeSend(bytes(status)))
        assertNull(marked.settle(id))
        assertEquals(RecoveryState(), marked.settle(action))
        assertNull(RecoveryState().beforeSend(bytes(revoke.replace("\"pw\"", "\"\""))))
        assertNull(RecoveryState().beforeSend(bytes(revoke.replace("approval_client", "requester_agent"))))
    }

    @Test fun preparedTicketsDieWithTheForeground() {
        var now = 0L
        val gate = ManagementTransportGate { now }
        val prepare = bytes("""{"version":2,"command":"identity_prepare","target":{"kind":"approval_client","id":"$client"}}""")
        val reply = bytes("""{"version":2,"identity":{"kind":"approval_client","id":"$client"},"action_id":"$action","ticket":"$ticket"}""")
        val revoke = bytes("""{"version":2,"command":"identity_revoke","target":{"kind":"approval_client","id":"$client"},"action_id":"$action","ticket":"$ticket","password":"pw"}""")

        assertNull("background prepare", gate.begin(prepare, foreground = false))
        var epoch = gate.begin(prepare, foreground = true)!!
        assertTrue(gate.finish(prepare, reply, epoch, foreground = true))
        assertNotNull(gate.begin(revoke, foreground = true))
        assertNull("one attempt", gate.begin(revoke, foreground = true))

        epoch = gate.begin(prepare, foreground = true)!!
        assertTrue(gate.finish(prepare, reply, epoch, foreground = true))
        gate.invalidate() // screen off or background
        assertNull(gate.begin(revoke, foreground = true))

        epoch = gate.begin(prepare, foreground = true)!!
        gate.invalidate()
        assertFalse("a response after invalidation is refused", gate.finish(prepare, reply, epoch, foreground = true))

        epoch = gate.begin(prepare, foreground = true)!!
        assertTrue(gate.finish(prepare, reply, epoch, foreground = true))
        now += 55_000
        assertNull("expired", gate.begin(revoke, foreground = true))
    }
}
