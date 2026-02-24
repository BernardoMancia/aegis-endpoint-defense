package com.aegis.agent

import android.app.*
import android.content.*
import android.hardware.camera2.*
import android.location.*
import android.os.*
import android.os.PowerManager.WakeLock
import androidx.core.app.NotificationCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.*
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.*

/**
 * AegisHeartbeatService — Foreground Service persistente para o agente Android.
 * Funções: heartbeat periódico, coleta de GPS/battery/apps, execução de tarefas C2.
 */
class HeartbeatService : Service() {

    companion object {
        const val CHANNEL_ID       = "aegis_channel"
        const val CHANNEL_NAME     = "Aegis Protection"
        const val NOTIFICATION_ID  = 1001
        const val ACTION_STOP      = "com.aegis.STOP"

        // Configuração — altere pelo .env ou via SharedPreferences
        var SERVER_URL  = "http://192.168.1.100:5000"
        var API_TOKEN   = "aegis-default-token-mude-agora"
        var HEARTBEAT_MS = 15_000L  // 15 segundos
    }

    private lateinit var executor: ScheduledExecutorService
    private lateinit var wakeLock: WakeLock
    private var locationManager: LocationManager? = null
    private var lastLocation: Location? = null
    private var batteryLevel: Int = -1

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        acquireWakeLock()
        setupLocationListener()
        loadConfig()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, buildNotification("🛡️ Aegis ativo — Protegendo dispositivo"))
        startHeartbeatLoop()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        executor.shutdownNow()
        if (::wakeLock.isInitialized && wakeLock.isHeld) wakeLock.release()
        locationManager?.removeUpdates(locationListener)
        // Reagenda o serviço para reiniciar via AlarmManager
        scheduleRestart()
    }

    // -------------------------------------------------------------------------
    // Configuração persistente
    // -------------------------------------------------------------------------

    private fun loadConfig() {
        val prefs = getSharedPreferences("aegis_config", MODE_PRIVATE)
        SERVER_URL   = prefs.getString("server_url", SERVER_URL) ?: SERVER_URL
        API_TOKEN    = prefs.getString("api_token", API_TOKEN)   ?: API_TOKEN
        HEARTBEAT_MS = prefs.getLong("heartbeat_ms", HEARTBEAT_MS)
    }

    fun saveConfig(serverUrl: String, apiToken: String, heartbeatMs: Long) {
        val prefs = getSharedPreferences("aegis_config", MODE_PRIVATE)
        with(prefs.edit()) {
            putString("server_url", serverUrl)
            putString("api_token", apiToken)
            putLong("heartbeat_ms", heartbeatMs)
            apply()
        }
    }

    // -------------------------------------------------------------------------
    // Heartbeat Loop
    // -------------------------------------------------------------------------

    private fun startHeartbeatLoop() {
        executor = Executors.newScheduledThreadPool(2)
        executor.scheduleWithFixedDelay({
            try {
                val command = sendHeartbeat()
                command?.let { processCommand(it) }
                updateNotification("🛡️ Online · ${getCurrentTime()}")
            } catch (e: Exception) {
                updateNotification("⚠️ Offline — tentando reconectar...")
                logError("Heartbeat falhou: ${e.message}")
            }
        }, 0, HEARTBEAT_MS, TimeUnit.MILLISECONDS)

        // Coleta de bateria a cada 30s
        executor.scheduleWithFixedDelay({
            batteryLevel = getBatteryLevel()
        }, 5, 30, TimeUnit.SECONDS)
    }

    /**
     * Envia heartbeat ao servidor C2 com telemetria do dispositivo.
     * Retorna o comando pendente (se houver) ou null.
     */
    private fun sendHeartbeat(): JSONObject? {
        val deviceId  = getDeviceId()
        val installedApps = getInstalledApps(limit = 30)
        val payload = JSONObject().apply {
            put("original_hostname", deviceId)
            put("hostname", "${Build.MODEL}_${Build.SERIAL?.take(6) ?: "unknown"}")
            put("platform", "android")
            put("os_info", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · ${Build.MANUFACTURER} ${Build.MODEL}")
            put("agent_version", "1.0.0")
            put("extra_data", JSONObject().apply {
                put("battery", batteryLevel)
                put("gps", lastLocation?.let {
                    JSONObject().apply {
                        put("lat", it.latitude)
                        put("lng", it.longitude)
                        put("accuracy", it.accuracy)
                        put("timestamp", it.time)
                    }
                })
                put("installed_apps", installedApps)
                put("android_id", deviceId)
                put("model", Build.MODEL)
                put("manufacturer", Build.MANUFACTURER)
            })
        }

        val response = httpPost("$SERVER_URL/api/heartbeat", payload.toString()) ?: return null
        val jsonResp = JSONObject(response)
        return jsonResp.optJSONObject("pending_command")
    }

    // -------------------------------------------------------------------------
    // Execução de Comandos C2
    // -------------------------------------------------------------------------

    private fun processCommand(cmd: JSONObject) {
        val action = cmd.optString("command", "").uppercase()
        logInfo("[C2] Executando comando: $action")

        when (action) {
            "VIBRATE"    -> vibrateDevice(cmd.optLong("duration_ms", 3000))
            "FLASHLIGHT" -> toggleFlashlight(cmd.optBoolean("on", true))
            "LOCK_SCREEN" -> lockScreen()
            "GET_LOCATION" -> forceLocationUpdate()
            "GET_APPS"   -> sendInstalledApps()
            "RING"       -> vibrateDevice(10_000)
            "MESSAGE"    -> showNotification(
                cmd.optString("title", "Aegis"),
                cmd.optString("body", "Mensagem do SOC")
            )
        }
    }

    private fun vibrateDevice(durationMs: Long) {
        try {
            val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vm = getSystemService(VIBRATOR_MANAGER_SERVICE) as VibratorManager
                vm.defaultVibrator
            } else {
                @Suppress("DEPRECATION")
                getSystemService(VIBRATOR_SERVICE) as Vibrator
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                vibrator.vibrate(VibrationEffect.createOneShot(durationMs, VibrationEffect.DEFAULT_AMPLITUDE))
            } else {
                @Suppress("DEPRECATION")
                vibrator.vibrate(durationMs)
            }
            logInfo("[CMD] Vibração por ${durationMs}ms")
        } catch (e: Exception) { logError("Vibrate falhou: ${e.message}") }
    }

    private fun toggleFlashlight(on: Boolean) {
        try {
            val cm = getSystemService(CAMERA_SERVICE) as CameraManager
            val cameraId = cm.cameraIdList.firstOrNull() ?: return
            cm.setTorchMode(cameraId, on)
            logInfo("[CMD] Flashlight: ${if (on) "ON" else "OFF"}")
        } catch (e: Exception) { logError("Flashlight falhou: ${e.message}") }
    }

    private fun lockScreen() {
        try {
            val dpm = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager
            dpm.lockNow()
            logInfo("[CMD] Tela bloqueada")
        } catch (e: Exception) { logError("LockScreen falhou: ${e.message}") }
    }

    private fun forceLocationUpdate() {
        try {
            locationManager?.requestSingleUpdate(
                LocationManager.GPS_PROVIDER, locationListener, mainLooper
            )
        } catch (e: Exception) { logError("LocationUpdate falhou: ${e.message}") }
    }

    private fun sendInstalledApps() {
        executor.submit {
            try {
                val apps = getInstalledApps(limit = 100)
                val payload = JSONObject().apply {
                    put("original_hostname", getDeviceId())
                    put("installed_apps", apps)
                    put("battery", batteryLevel)
                }
                httpPost("$SERVER_URL/api/ingest_android", payload.toString())
            } catch (e: Exception) { logError("sendInstalledApps falhou: ${e.message}") }
        }
    }

    // -------------------------------------------------------------------------
    // Coleta de Dados do Dispositivo
    // -------------------------------------------------------------------------

    private fun getDeviceId(): String {
        val prefs = getSharedPreferences("aegis_config", MODE_PRIVATE)
        var id = prefs.getString("device_id", null)
        if (id == null) {
            id = "android_${Build.MODEL.replace(" ","_")}_${System.currentTimeMillis().toString(16)}"
            prefs.edit().putString("device_id", id).apply()
        }
        return id
    }

    private fun getBatteryLevel(): Int {
        val batteryIntent = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = batteryIntent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryIntent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        return if (level >= 0 && scale > 0) (level * 100 / scale.toFloat()).toInt() else -1
    }

    private fun getInstalledApps(limit: Int = 30): JSONArray {
        val array = JSONArray()
        try {
            val packages = packageManager.getInstalledApplications(0)
            packages.take(limit).forEach { info ->
                val appInfo = JSONObject().apply {
                    put("package", info.packageName)
                    put("name", packageManager.getApplicationLabel(info).toString())
                }
                array.put(appInfo)
            }
        } catch (e: Exception) { logError("getInstalledApps: ${e.message}") }
        return array
    }

    // -------------------------------------------------------------------------
    // GPS / Location
    // -------------------------------------------------------------------------

    private fun setupLocationListener() {
        try {
            locationManager = getSystemService(LOCATION_SERVICE) as LocationManager
            locationManager?.requestLocationUpdates(
                LocationManager.GPS_PROVIDER, 30_000L, 10f, locationListener
            )
        } catch (e: SecurityException) {
            logError("Permissão de localização negada: ${e.message}")
        }
    }

    private val locationListener = object : LocationListener {
        override fun onLocationChanged(location: Location) { lastLocation = location }
        override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
        override fun onProviderEnabled(provider: String) {}
        override fun onProviderDisabled(provider: String) {}
    }

    // -------------------------------------------------------------------------
    // HTTP Client
    // -------------------------------------------------------------------------

    private fun httpPost(urlStr: String, body: String): String? {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
                requestMethod    = "POST"
                doOutput         = true
                connectTimeout   = 10_000
                readTimeout      = 15_000
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Authorization", "Bearer $API_TOKEN")
            }
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            if (conn.responseCode in 200..299) {
                conn.inputStream.bufferedReader().use { it.readText() }
            } else {
                logError("HTTP ${conn.responseCode} para $urlStr")
                null
            }
        } catch (e: Exception) {
            logError("httpPost falhou ($urlStr): ${e.message}")
            null
        } finally {
            conn?.disconnect()
        }
    }

    // -------------------------------------------------------------------------
    // Notificações
    // -------------------------------------------------------------------------

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Canal do Aegis EDR — Proteção ativa do dispositivo"
                setShowBadge(false)
            }
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val stopIntent = PendingIntent.getService(
            this, 0, Intent(this, HeartbeatService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Aegis EDR")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setSilent(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Parar", stopIntent)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun showNotification(title: String, body: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val notif = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(body)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setAutoCancel(true)
            .build()
        nm.notify(System.currentTimeMillis().toInt(), notif)
    }

    // -------------------------------------------------------------------------
    // Restart via AlarmManager (persistência após kill)
    // -------------------------------------------------------------------------

    private fun scheduleRestart() {
        val restartIntent = PendingIntent.getService(
            this, 1,
            Intent(this, HeartbeatService::class.java),
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
        )
        val alarmManager = getSystemService(ALARM_SERVICE) as AlarmManager
        alarmManager.set(AlarmManager.ELAPSED_REALTIME_WAKEUP,
            SystemClock.elapsedRealtime() + 5_000L, restartIntent)
    }

    // -------------------------------------------------------------------------
    // WakeLock
    // -------------------------------------------------------------------------

    private fun acquireWakeLock() {
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "aegis:heartbeat")
        wakeLock.acquire(24 * 60 * 60 * 1000L)  // 24h máximo
    }

    // -------------------------------------------------------------------------
    // Logging
    // -------------------------------------------------------------------------

    private fun getCurrentTime(): String {
        val sdf = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
        return sdf.format(java.util.Date())
    }

    private fun logInfo(msg: String) {
        android.util.Log.i("AegisAgent", msg)
    }

    private fun logError(msg: String) {
        android.util.Log.e("AegisAgent", msg)
    }
}
