package dev.vaultwarden.companionslice

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.view.WindowManager
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Android approval client (#60 phase 1). A FlutterFragmentActivity because
 * BiometricPrompt needs a FragmentActivity. The activity owns the lifecycle
 * signals (`LifecycleTrigger`): leaving the screen, screen off and
 * destruction cancel an open approval prompt and invalidate provider state,
 * so a backgrounded or locked phone never approves a request it no longer
 * shows. There is no synthetic signer channel and no desktop installation
 * channel on Android: Dart sees `MissingPluginException` and reports them
 * unavailable.
 */
class MainActivity : FlutterFragmentActivity() {
    private var approvalKey: ApprovalKeyChannel? = null
    private var provider: ProviderChannel? = null
    private var notifications: ReviewNotifications? = null
    private var screenOffRegistered = false
    private var lifecycleChannel: MethodChannel? = null

    private val screenOff = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == Intent.ACTION_SCREEN_OFF) trigger(LifecycleTrigger.SCREEN_OFF)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Request content never appears in screenshots, screen recordings or Recents.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        // A protected system broadcast: delivered to a not-exported receiver.
        ContextCompat.registerReceiver(this, screenOff, IntentFilter(Intent.ACTION_SCREEN_OFF), ContextCompat.RECEIVER_NOT_EXPORTED)
        screenOffRegistered = true
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val messenger = flutterEngine.dartExecutor.binaryMessenger
        approvalKey = ApprovalKeyChannel(this, messenger)
        provider = ProviderChannel(this, messenger)
        notifications = ReviewNotifications(this, messenger).also { it.onIntent(intent) }
        // Native -> Dart only (`signal`: `locked`); Dart never calls it.
        lifecycleChannel = MethodChannel(messenger, LIFECYCLE_CHANNEL)
    }

    override fun cleanUpFlutterEngine(flutterEngine: FlutterEngine) {
        approvalKey?.dispose()
        provider?.dispose()
        notifications?.dispose()
        approvalKey = null
        provider = null
        notifications = null
        lifecycleChannel = null
        super.cleanUpFlutterEngine(flutterEngine)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        notifications?.onIntent(intent)
    }

    override fun onStop() {
        trigger(LifecycleTrigger.STOP)
        super.onStop()
    }

    override fun onDestroy() {
        trigger(LifecycleTrigger.DESTROY)
        if (screenOffRegistered) {
            unregisterReceiver(screenOff)
            screenOffRegistered = false
        }
        super.onDestroy()
    }

    private fun trigger(trigger: LifecycleTrigger) {
        approvalKey?.cancelActive()
        provider?.invalidate(trigger)
        trigger.deviceSignal?.let { lifecycleChannel?.invokeMethod("signal", it) }
    }

    @Deprecated("Storage Access Framework results for provider setup")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (provider?.onActivityResult(requestCode, resultCode, data) == true) return
        @Suppress("DEPRECATION") super.onActivityResult(requestCode, resultCode, data)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        if (notifications?.onPermissionResult(requestCode) == true) return
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    }

    companion object {
        const val LIFECYCLE_CHANNEL = "dev.vaultwarden.companionSlice/lifecycle"
    }
}
