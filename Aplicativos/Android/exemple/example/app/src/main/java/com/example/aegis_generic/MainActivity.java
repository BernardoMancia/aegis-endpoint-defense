package com.example.aegis_generic;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.camera2.CameraManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivity extends AppCompatActivity {

    private static final String SERVER_IP = "0.0.0.0"; 
    private static final int SERVER_PORT = 0000;
    private static final String API_TOKEN = "";
    
    private TextView statusText;
    private double latitude = 0.0;
    private double longitude = 0.0;
    private boolean flashState = false;
    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        statusText = new TextView(this);
        setContentView(statusText);
        
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.CAMERA}, 1);
        } else {
            startTracking();
        }

        new Thread(this::heartbeatLoop).start();
    }

    private void startTracking() {
        try {
            LocationManager lm = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                lm.requestLocationUpdates(LocationManager.GPS_PROVIDER, 5000, 10, new LocationListener() {
                    @Override public void onLocationChanged(@NonNull Location l) { latitude = l.getLatitude(); longitude = l.getLongitude(); }
                    @Override public void onStatusChanged(String p, int s, Bundle e) {}
                    @Override public void onProviderEnabled(@NonNull String p) {}
                    @Override public void onProviderDisabled(@NonNull String p) {}
                });
            }
        } catch (Exception e) {}
    }

    private void heartbeatLoop() {
        while (true) {
            sendHeartbeat();
            try { Thread.sleep(5000); } catch (Exception e) { break; }
        }
    }

    private void sendHeartbeat() {
        try {
            URL url = new URL("http://" + SERVER_IP + ":" + SERVER_PORT + "/api/heartbeat");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            JSONObject json = new JSONObject();
            json.put("token", API_TOKEN);
            json.put("hostname", Build.MODEL);
            json.put("device_type", "android");
            json.put("os_version", "Android " + Build.VERSION.RELEASE);
            JSONObject gps = new JSONObject(); gps.put("lat", latitude); gps.put("lng", longitude);
            json.put("gps", gps);

            try (OutputStream os = conn.getOutputStream()) { os.write(json.toString().getBytes("utf-8")); }

            if (conn.getResponseCode() == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) response.append(line);
                
                JSONObject res = new JSONObject(response.toString());
                if (res.has("command")) handleCommand(res.getString("command"));
                
                updateUI("Connected: Secure");
            } else { updateUI("Error: " + conn.getResponseCode()); }
            conn.disconnect();
        } catch (Exception e) { updateUI("Connection Failed"); }
    }

    private void handleCommand(String cmd) {
        if (cmd.equals("vibrate")) {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) v.vibrate(VibrationEffect.createOneShot(1000, VibrationEffect.DEFAULT_AMPLITUDE));
            else v.vibrate(1000);
        } else if (cmd.equals("flash_toggle")) {
            toggleFlash();
        }
    }

    private void toggleFlash() {
        try {
            CameraManager cm = (CameraManager) getSystemService(Context.CAMERA_SERVICE);
            String cid = cm.getCameraIdList()[0];
            flashState = !flashState;
            cm.setTorchMode(cid, flashState);
        } catch (Exception e) {}
    }

    private void updateUI(String msg) {
        handler.post(() -> statusText.setText("AEGIS MOBILE (GENERIC)\n----------------\n" + msg));
    }
}