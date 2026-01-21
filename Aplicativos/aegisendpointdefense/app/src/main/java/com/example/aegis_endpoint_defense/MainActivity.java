package com.example.aegis_endpoint_defense;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivity extends AppCompatActivity {

    private static final String SERVER_IP = "82.112.245.99";
    private static final int SERVER_PORT = 7070;
    private static final String API_TOKEN = "aegis_secure_8f2a9b1c7d3e4f5a6b0c8d1e9f2a3b4c";
    
    private TextView statusText;
    private double latitude = 0.0;
    private double longitude = 0.0;
    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        statusText = new TextView(this);
        statusText.setTextSize(16);
        statusText.setPadding(40, 40, 40, 40);
        statusText.setText("Initializing Aegis Mobile Agent...");
        setContentView(statusText);

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, 1);
        } else {
            startTracking();
        }

        startHeartbeatLoop();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == 1 && grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            startTracking();
        }
    }

    private void startTracking() {
        try {
            LocationManager locationManager = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 5000, 10, new LocationListener() {
                    @Override
                    public void onLocationChanged(@NonNull Location location) {
                        latitude = location.getLatitude();
                        longitude = location.getLongitude();
                        updateUI("GPS Updated: " + latitude + ", " + longitude);
                    }
                    @Override public void onStatusChanged(String provider, int status, Bundle extras) {}
                    @Override public void onProviderEnabled(@NonNull String provider) {}
                    @Override public void onProviderDisabled(@NonNull String provider) {}
                });
            }
        } catch (Exception e) {
            updateUI("GPS Error: " + e.getMessage());
        }
    }

    private void startHeartbeatLoop() {
        new Thread(() -> {
            while (true) {
                sendHeartbeat();
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }).start();
    }

    private void sendHeartbeat() {
        try {
            URL url = new URL("http://" + SERVER_IP + ":" + SERVER_PORT + "/api/heartbeat");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);

            JSONObject json = new JSONObject();
            json.put("token", API_TOKEN);
            json.put("hostname", Build.MODEL + " (" + Build.MANUFACTURER + ")");
            json.put("device_type", "android");
            json.put("os_version", "Android " + Build.VERSION.RELEASE);
            
            JSONObject gps = new JSONObject();
            gps.put("lat", latitude);
            gps.put("lng", longitude);
            json.put("gps", gps);
            
            json.put("battery", 85); 

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = json.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            int code = conn.getResponseCode();
            
            if (code == 200) {
                updateUI("Connected to Server (" + SERVER_IP + ")\nStatus: Secure\nGPS: " + latitude + " / " + longitude);
            } else {
                updateUI("Server Error: " + code);
            }

            conn.disconnect();

        } catch (Exception e) {
            updateUI("Connection Failed: " + e.getMessage());
        }
    }

    private void updateUI(String msg) {
        handler.post(() -> statusText.setText("AEGIS EDR MOBILE v5.0\n----------------------\n" + msg));
    }
}