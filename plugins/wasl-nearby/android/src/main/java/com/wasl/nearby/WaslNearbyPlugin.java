package com.wasl.nearby;

import android.Manifest;
import android.os.Build;
import android.util.Base64;

import androidx.annotation.NonNull;

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
