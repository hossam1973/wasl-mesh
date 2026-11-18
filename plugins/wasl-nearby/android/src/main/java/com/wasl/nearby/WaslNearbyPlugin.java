package com.wasl.nearby;

import android.Manifest;
import android.content.ContentValues;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Base64;

import androidx.annotation.NonNull;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.PermissionState;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.Permission;
import com.getcapacitor.annotation.PermissionCallback;
import com.google.android.gms.nearby.Nearby;
import com.google.android.gms.nearby.connection.AdvertisingOptions;
import com.google.android.gms.nearby.connection.ConnectionInfo;
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback;
import com.google.android.gms.nearby.connection.ConnectionResolution;
import com.google.android.gms.nearby.connection.ConnectionsClient;
import com.google.android.gms.nearby.connection.ConnectionsStatusCodes;
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo;
import com.google.android.gms.nearby.connection.DiscoveryOptions;
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback;
import com.google.android.gms.nearby.connection.Payload;
import com.google.android.gms.nearby.connection.PayloadCallback;
import com.google.android.gms.nearby.connection.PayloadTransferUpdate;
import com.google.android.gms.nearby.connection.Strategy;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Phone-to-phone mesh links with Google Nearby Connections (P2P_CLUSTER: many-to-many).
 * Nearby picks Bluetooth LE / Bluetooth Classic for discovery and upgrades to Wi-Fi Direct or
 * a Wi-Fi hotspot for bandwidth automatically. No internet, no SIM.
 * Trust is not handled here: the web layer exchanges signed identity cards and encrypts end to end.
 */
@CapacitorPlugin(
    name = "WaslNearby",
    permissions = {
        @Permission(alias = "location", strings = { Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION }),
        @Permission(alias = "bluetooth", strings = { "android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_ADVERTISE", "android.permission.BLUETOOTH_CONNECT" }),
        @Permission(alias = "wifi", strings = { "android.permission.NEARBY_WIFI_DEVICES" })
    }
)
public class WaslNearbyPlugin extends Plugin {
    private static final String SERVICE_ID = "com.wasl.mesh";
    private ConnectionsClient client;
    private String myName = "wasl";
    private final Set<String> connected = new HashSet<>();
    private boolean running = false;
    private IpMesh ip;

    private final IpMesh.Events ipEvents = new IpMesh.Events() {
        @Override public void connected(String id) { JSObject o = new JSObject(); o.put("id", id); notifyListeners("connected", o); }
        @Override public void data(String id, byte[] b) { JSObject o = new JSObject(); o.put("id", id); o.put("data", Base64.encodeToString(b, Base64.NO_WRAP)); notifyListeners("data", o); }
        @Override public void disconnected(String id) { JSObject o = new JSObject(); o.put("id", id); notifyListeners("disconnected", o); }
        @Override public void kissData(String id, byte[] b) { JSObject o = new JSObject(); o.put("id", id); o.put("data", Base64.encodeToString(b, Base64.NO_WRAP)); notifyListeners("kissData", o); }
        @Override public void kissClosed(String id) { JSObject o = new JSObject(); o.put("id", id); notifyListeners("kissClosed", o); }
        @Override public void error(String where, String message) { emitError(where, message); }
    };

    private IpMesh ip() { if (ip == null) ip = new IpMesh(getContext(), ipEvents); return ip; }

    /** IP mesh (Wi-Fi, Ethernet, microwave, AREDN): auto-discovery on the local network + listening port. */
    @PluginMethod
    public void ipStart(PluginCall call) {
        final String name = call.getString("name", "wasl");
        ip().pool.execute(() -> {
            try {
                int port = ip().start(name);
                JSObject o = new JSObject(); o.put("port", port); o.put("addresses", new JSArray(IpMesh.localAddresses()));
                call.resolve(o);
            } catch (Exception e) { call.reject("ip_start_failed", e.getMessage()); }
        });
    }

    /** Dial a remote site by address, e.g. across a routed microwave link. */
    @PluginMethod
    public void ipConnect(PluginCall call) {
        final String host = call.getString("host"); final Integer port = call.getInt("port");
        if (host == null || port == null) { call.reject("bad_args"); return; }
        ip().pool.execute(() -> { ip().dial(host, port); call.resolve(); });
    }

    /** TCP connection to a KISS modem: VARA HF (8100), ARDOP, Direwolf (8001). */
    @PluginMethod
    public void kissConnect(PluginCall call) {
        final String host = call.getString("host"); final Integer port = call.getInt("port");
        if (host == null || port == null) { call.reject("bad_args"); return; }
        ip().pool.execute(() -> {
            try { JSObject o = new JSObject(); o.put("id", ip().kissConnect(host, port)); call.resolve(o); }
            catch (Exception e) { call.reject("modem_unreachable", e.getMessage()); }
        });
    }

    @PluginMethod
    public void kissSend(PluginCall call) {
        final String id = call.getString("id"), data = call.getString("data");
        if (id == null || data == null) { call.reject("bad_args"); return; }
        final byte[] b = Base64.decode(data, Base64.NO_WRAP);
        ip().pool.execute(() -> { if (ip().kissSend(id, b)) call.resolve(); else call.reject("send_failed"); });
    }

    @PluginMethod
    public void kissClose(PluginCall call) { String id = call.getString("id"); if (id != null) ip().kissClose(id); call.resolve(); }

    /** Save a file to Downloads (manual carrier bundles on USB / SD card). */
    @PluginMethod
    public void saveFile(PluginCall call) {
        String name = call.getString("name", "wasl.bin"), data = call.getString("data");
        if (data == null) { call.reject("bad_args"); return; }
        byte[] b = Base64.decode(data, Base64.NO_WRAP);
        try {
            JSObject r = new JSObject();
            if (Build.VERSION.SDK_INT >= 29) {
                ContentValues v = new ContentValues();
                v.put(MediaStore.Downloads.DISPLAY_NAME, name);
                v.put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream");
                Uri u = getContext().getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
                if (u == null) throw new Exception("cannot create file");
                try (OutputStream o = getContext().getContentResolver().openOutputStream(u)) { if (o == null) throw new Exception("cannot open file"); o.write(b); }
                r.put("path", "Download/" + name);
            } else {
                File dir = getContext().getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                File f = new File(dir, name);
                try (FileOutputStream o = new FileOutputStream(f)) { o.write(b); }
                r.put("path", f.getAbsolutePath());
            }
            call.resolve(r);
        } catch (Exception e) { call.reject("save_failed", e.getMessage()); }
    }

    private String[] neededAliases() {
        List<String> a = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= 31) a.add("bluetooth");
        if (Build.VERSION.SDK_INT >= 33) a.add("wifi"); else a.add("location");
        return a.toArray(new String[0]);
    }

    @PluginMethod
    public void start(PluginCall call) {
        myName = call.getString("name", "wasl");
        for (String alias : neededAliases()) {
            if (getPermissionState(alias) != PermissionState.GRANTED) {
                requestPermissionForAliases(neededAliases(), call, "permissionsDone");
                return;
            }
        }
        begin(call);
    }

    @PermissionCallback
    private void permissionsDone(PluginCall call) {
        for (String alias : neededAliases()) {
            if (getPermissionState(alias) != PermissionState.GRANTED) {
                call.reject("permission_denied", "Nearby devices permission is required");
                return;
            }
        }
        begin(call);
    }

    private void begin(PluginCall call) {
        if (client == null) client = Nearby.getConnectionsClient(getContext());
        if (running) { call.resolve(); return; }
        running = true;
        AdvertisingOptions ao = new AdvertisingOptions.Builder().setStrategy(Strategy.P2P_CLUSTER).build();
        DiscoveryOptions dop = new DiscoveryOptions.Builder().setStrategy(Strategy.P2P_CLUSTER).build();
        client.startAdvertising(myName, SERVICE_ID, lifecycle, ao)
            .addOnFailureListener(e -> emitError("advertise", e.getMessage()));
        client.startDiscovery(SERVICE_ID, discovery, dop)
            .addOnFailureListener(e -> emitError("discover", e.getMessage()));
        call.resolve();
    }

    @PluginMethod
    public void send(PluginCall call) {
        String id = call.getString("id"), data = call.getString("data");
        if (id != null && data != null && id.startsWith("ip:")) {
            final byte[] b = Base64.decode(data, Base64.NO_WRAP);
            ip().pool.execute(() -> { if (ip().send(id, b)) call.resolve(); else call.reject("send_failed"); });
            return;
        }
        if (client == null || id == null || data == null || !connected.contains(id)) { call.reject("not_connected"); return; }
        byte[] bytes = Base64.decode(data, Base64.NO_WRAP);
        if (bytes.length > ConnectionsClient.MAX_BYTES_DATA_SIZE) { call.reject("too_large"); return; }
        client.sendPayload(id, Payload.fromBytes(bytes))
            .addOnSuccessListener(v -> call.resolve())
            .addOnFailureListener(e -> call.reject("send_failed", e.getMessage()));
    }

    @PluginMethod
    public void stop(PluginCall call) {
        if (client != null) { client.stopAdvertising(); client.stopDiscovery(); client.stopAllEndpoints(); }
        if (ip != null) ip.stop();
        connected.clear(); running = false;
        call.resolve();
    }

    private void emitError(String where, String msg) {
        JSObject o = new JSObject(); o.put("where", where); o.put("message", msg);
        notifyListeners("error", o);
    }

    private final EndpointDiscoveryCallback discovery = new EndpointDiscoveryCallback() {
        @Override public void onEndpointFound(@NonNull String id, @NonNull DiscoveredEndpointInfo info) {
            JSObject o = new JSObject(); o.put("id", id); o.put("name", info.getEndpointName());
            notifyListeners("found", o);
            // only one side dials, to avoid simultaneous-connect collisions
            if (myName.compareTo(info.getEndpointName()) < 0 && !connected.contains(id)) {
                client.requestConnection(myName, id, lifecycle)
                    .addOnFailureListener(e -> emitError("connect", e.getMessage()));
            }
        }
        @Override public void onEndpointLost(@NonNull String id) {
            JSObject o = new JSObject(); o.put("id", id); notifyListeners("lost", o);
        }
    };

    private final ConnectionLifecycleCallback lifecycle = new ConnectionLifecycleCallback() {
        @Override public void onConnectionInitiated(@NonNull String id, @NonNull ConnectionInfo info) {
            client.acceptConnection(id, payloads);
        }
        @Override public void onConnectionResult(@NonNull String id, @NonNull ConnectionResolution res) {
            int code = res.getStatus().getStatusCode();
            if (code == ConnectionsStatusCodes.STATUS_OK) {
                connected.add(id);
                JSObject o = new JSObject(); o.put("id", id); notifyListeners("connected", o);
            }
        }
        @Override public void onDisconnected(@NonNull String id) {
            connected.remove(id);
            JSObject o = new JSObject(); o.put("id", id); notifyListeners("disconnected", o);
        }
    };

    private final PayloadCallback payloads = new PayloadCallback() {
        @Override public void onPayloadReceived(@NonNull String id, @NonNull Payload p) {
            if (p.getType() != Payload.Type.BYTES || p.asBytes() == null) return;
            JSObject o = new JSObject(); o.put("id", id); o.put("data", Base64.encodeToString(p.asBytes(), Base64.NO_WRAP));
            notifyListeners("data", o);
        }
        @Override public void onPayloadTransferUpdate(@NonNull String id, @NonNull PayloadTransferUpdate u) { }
    };
}
