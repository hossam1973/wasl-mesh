package com.wasl.nearby;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import androidx.core.app.NotificationCompat;

/**
 * Keeps the app process alive while the screen is off so the phone keeps relaying mesh traffic
 * (Nearby Connections + IP mesh live in this process). Shows a persistent notification, as Android requires.
 */
public class MeshForegroundService extends Service {
    static final String CHANNEL = "wasl_mesh_relay";
    private PowerManager.WakeLock wakeLock;

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CHANNEL) == null) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "تمرير الشبكة", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("يبقي وَصْل حلقة وصل للرسائل أثناء قفل الشاشة");
            nm.createNotificationChannel(ch);
        }
        Intent open = getPackageManager().getLaunchIntentForPackage(getPackageName());
        PendingIntent pi = open == null ? null : PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n = new NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(getApplicationInfo().icon)
            .setContentTitle("وَصْل يعمل كحلقة وصل")
            .setContentText("يمرّر الرسائل للأجهزة القريبة دون إنترنت")
            .setOngoing(true).setContentIntent(pi).setPriority(NotificationCompat.PRIORITY_LOW).build();
        if (Build.VERSION.SDK_INT >= 34) startForeground(7, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        else startForeground(7, n);
        if (wakeLock == null) {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "wasl:mesh-relay");
            wakeLock.setReferenceCounted(false);
            wakeLock.acquire(6 * 60 * 60 * 1000L);       // re-acquired on each start; bounded for battery safety
        }
        return START_STICKY;
    }

    @Override public void onDestroy() { if (wakeLock != null && wakeLock.isHeld()) wakeLock.release(); super.onDestroy(); }
}
