package dev.vaultwarden.companionslice

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.SystemClock
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * `dev.vaultwarden.companionSlice/notifications` on Android, the contract of
 * `ReviewNotificationAdapter.swift`. Posts only the fixed generic copy, on the
 * lock screen too (the public version is the same generic text), with no
 * actions; a tap brings the activity forward and hands Flutter the token.
 *
 * `watching` is accepted and does nothing: Android keeps no process alive for
 * the Flutter watch timer, so notifications arrive only while the app process
 * runs. A push channel is outside phase 1.
 */
class ReviewNotifications(private val activity: FragmentActivity, messenger: BinaryMessenger) {
    private val channel = MethodChannel(messenger, NAME)
    private val manager = activity.getSystemService(NotificationManager::class.java)
    private val preferences = activity.getSharedPreferences("review-notifications", Context.MODE_PRIVATE)
    private val pendingOpens = ReviewNotificationContract.PendingOpens()
    private val authorization = ReviewNotificationContract.AuthorizationGate()
    private var listening = false
    private var permissionResult: MethodChannel.Result? = null

    init {
        channel.setMethodCallHandler(::handle)
        manager.createNotificationChannel(
            NotificationChannel(ReviewNotificationContract.CHANNEL_ID, ReviewNotificationContract.CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH).apply { lockscreenVisibility = Notification.VISIBILITY_PRIVATE },
        )
    }

    fun dispose() {
        channel.setMethodCallHandler(null)
        permissionResult?.success(status())
        permissionResult = null
    }

    private val needsRuntime: Boolean get() = Build.VERSION.SDK_INT >= 33

    private fun status(): String = ReviewNotificationContract.statusName(
        enabledBySystem = manager.areNotificationsEnabled(),
        runtimeGranted = !needsRuntime || ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED,
        needsRuntime = needsRuntime,
        asked = preferences.getBoolean(ASKED, false),
    )

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "status" -> result.success(status())
            "armAuthorization" -> {
                authorization.arm(SystemClock.elapsedRealtime())
                result.success(null)
            }
            "requestAuthorization" -> {
                val front = activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
                if (!authorization.consume(SystemClock.elapsedRealtime(), front) || permissionResult != null) {
                    return result.error("not_armed", null, null)
                }
                if (!needsRuntime || status() != "notDetermined") return result.success(status())
                preferences.edit().putBoolean(ASKED, true).apply()
                permissionResult = result
                ActivityCompat.requestPermissions(activity, arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_PERMISSION)
            }
            "enabled" -> result.success(preferences.getBoolean(ENABLED, false))
            "setEnabled" -> {
                val value = call.arguments as? Boolean ?: return result.error("invalid", null, null)
                preferences.edit().putBoolean(ENABLED, value).apply()
                if (!value) manager.cancelAll()
                result.success(null)
            }
            "post" -> {
                val token = ReviewNotificationContract.token(call.arguments) ?: return result.error("invalid", null, null)
                try {
                    manager.notify(token, ReviewNotificationContract.NOTIFICATION_ID, build(token))
                    result.success(null)
                } catch (_: SecurityException) {
                    result.error("post_failed", null, null)
                }
            }
            "withdraw" -> {
                val tokens = ReviewNotificationContract.tokens(call.arguments) ?: return result.error("invalid", null, null)
                tokens.forEach { manager.cancel(it, ReviewNotificationContract.NOTIFICATION_ID) }
                result.success(null)
            }
            "watching" -> {
                if (call.arguments !is Boolean) return result.error("invalid", null, null)
                result.success(null)
            }
            "listen" -> {
                listening = true
                result.success(pendingOpens.drain())
            }
            else -> result.notImplemented()
        }
    }

    private fun build(token: String): Notification {
        // The token is in the intent only to find the request in Flutter memory;
        // a unique data URI keeps one PendingIntent per token.
        val intent = Intent(activity, MainActivity::class.java)
            .setAction(ReviewNotificationContract.ACTION_OPEN)
            .setData(Uri.fromParts("review", token, null))
            .putExtra(ReviewNotificationContract.EXTRA_TOKEN, token)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pending = PendingIntent.getActivity(activity, token.hashCode(), intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        fun generic() = Notification.Builder(activity, ReviewNotificationContract.CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(ReviewNotificationContract.TITLE)
            .setContentText(ReviewNotificationContract.BODY)
        return generic()
            .setContentIntent(pending)
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(generic().build())
            .build()
    }

    /** A notification tap (cold start or `onNewIntent`). Opening never approves. */
    fun onIntent(intent: Intent?) {
        if (intent?.action != ReviewNotificationContract.ACTION_OPEN) return
        val token = intent.getStringExtra(ReviewNotificationContract.EXTRA_TOKEN) ?: return
        if (!ReviewNotificationContract.validToken(token)) return
        if (listening) channel.invokeMethod("open", token) else pendingOpens.enqueue(token)
    }

    /** Forwarded from `MainActivity.onRequestPermissionsResult`; true when it was ours. */
    fun onPermissionResult(request: Int): Boolean {
        if (request != REQUEST_PERMISSION) return false
        permissionResult?.success(status())
        permissionResult = null
        return true
    }

    companion object {
        const val NAME = "dev.vaultwarden.companionSlice/notifications"
        const val REQUEST_PERMISSION = 0x5603
        private const val ENABLED = "reviewNotificationsEnabled"
        private const val ASKED = "permissionAsked"
    }
}
