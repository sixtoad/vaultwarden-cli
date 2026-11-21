package dev.vaultwarden.companionslice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GateAndContractTest {
    private val session = "0123456789abcdef0123456789abcdef"
    private val other = "fedcba9876543210fedcba9876543210"

    @Test fun oneSignatureAtATimeWithIncreasingTokens() {
        val gate = SignerGate()
        var cancelled = 0
        assertTrue(gate.begin(session, 1) { cancelled++ })
        assertFalse("overlap", gate.begin(session, 2) {})
        assertFalse(gate.idle)
        gate.finish(session, 1)
        assertTrue(gate.idle)
        assertFalse("replay", gate.begin(session, 1) {})
        assertTrue(gate.begin(session, 5) {})
        gate.finish(session, 5)
        assertFalse("older", gate.begin(session, 4) {})
        assertTrue("a new session restarts numbering", gate.begin(other, 1) {})
        gate.finish(other, 1)
        assertFalse(gate.begin("ABCDEF0123456789abcdef0123456789", 9) {})
        assertFalse(gate.begin(session, 0) {})
        assertFalse(gate.begin(session, 0x1_0000_0000L) {})
        assertEquals(0, cancelled)
    }

    @Test fun cancelActsOnlyOnTheOpenSignature() {
        val gate = SignerGate()
        var cancelled = 0
        assertTrue(gate.begin(session, 3) { cancelled++ })
        gate.cancel(session, 2)
        gate.cancel(other, 3)
        assertEquals(0, cancelled)
        gate.cancel(session, 3)
        assertEquals(1, cancelled)
        gate.cancelActive()
        assertEquals("lifecycle cancel", 2, cancelled)
        gate.finish(other, 3)
        assertFalse("another session cannot finish it", gate.idle)
        gate.finish(session, 3)
        gate.cancelActive()
        assertEquals("nothing open", 2, cancelled)
    }

    @Test fun lifecycleTriggersMatchTheContract() {
        assertEquals("inactive", LifecycleTrigger.STOP.reason)
        assertEquals("inactive", LifecycleTrigger.SCREEN_OFF.reason)
        assertEquals("close", LifecycleTrigger.DESTROY.reason)
        assertEquals("locked", LifecycleTrigger.SCREEN_OFF.deviceSignal)
        assertNull(LifecycleTrigger.STOP.deviceSignal)
    }

    @Test fun notificationTokensAreNeverRequestIds() {
        assertTrue(ReviewNotificationContract.validToken("A".repeat(22)))
        assertFalse(ReviewNotificationContract.validToken("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"))
        assertFalse(ReviewNotificationContract.validToken("A".repeat(21) + "="))
        assertEquals("A".repeat(22), ReviewNotificationContract.token(mapOf("token" to "A".repeat(22))))
        assertNull(ReviewNotificationContract.token(mapOf("token" to "A".repeat(22), "title" to "x")))
        assertNull(ReviewNotificationContract.token(mapOf("token" to "short")))
        assertEquals(listOf("A".repeat(22)), ReviewNotificationContract.tokens(mapOf("tokens" to listOf("A".repeat(22)))))
        assertNull(ReviewNotificationContract.tokens(mapOf("tokens" to emptyList<String>())))
        assertNull(ReviewNotificationContract.tokens(mapOf("tokens" to List(257) { "A".repeat(22) })))
        assertNull(ReviewNotificationContract.tokens(mapOf("tokens" to listOf("A".repeat(22), 1))))
    }

    @Test fun notificationCopyIsGeneric() {
        assertEquals("Approval companion", ReviewNotificationContract.TITLE)
        assertEquals("A request needs your review.", ReviewNotificationContract.BODY)
    }

    @Test fun pendingOpensKeepTheLatestEight() {
        val opens = ReviewNotificationContract.PendingOpens()
        val tokens = (0 until 10).map { it.toString().padStart(22, 'A') }
        tokens.forEach(opens::enqueue)
        opens.enqueue(tokens[3])
        opens.enqueue("not a token")
        assertEquals(listOf(tokens[2]) + tokens.drop(4) + tokens[3], opens.drain())
        assertEquals(emptyList<String>(), opens.drain())
    }

    @Test fun permissionPromptNeedsAFreshArmInTheForeground() {
        val gate = ReviewNotificationContract.AuthorizationGate()
        assertFalse(gate.consume(0, true))
        gate.arm(1_000)
        assertTrue(gate.consume(11_000, true))
        assertFalse("one-shot", gate.consume(11_000, true))
        gate.arm(0)
        assertFalse("too late", gate.consume(10_001, true))
        gate.arm(0)
        assertFalse("background", gate.consume(1, false))
        assertFalse("a refusal disarms", gate.consume(2, true))
    }

    @Test fun permissionStatusNames() {
        assertEquals("notDetermined", ReviewNotificationContract.statusName(false, false, true, false))
        assertEquals("denied", ReviewNotificationContract.statusName(false, false, true, true))
        assertEquals("authorized", ReviewNotificationContract.statusName(true, true, true, true))
        assertEquals("authorized", ReviewNotificationContract.statusName(true, false, false, false))
        assertEquals("denied", ReviewNotificationContract.statusName(false, true, false, false))
    }
}
