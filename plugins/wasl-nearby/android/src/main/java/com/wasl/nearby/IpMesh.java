package com.wasl.nearby;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Mesh links over any IP network: Wi-Fi without internet, Ethernet, point-to-point microwave
 * bridges, AREDN / OLSR / BATMAN mesh routers. Peers on the same broadcast domain find each other
 * with DNS-SD (_waslip._tcp); routed sites are reached by address. Frames: 4-byte length + payload.
 * Also opens raw TCP byte streams to KISS modems (VARA HF, ARDOP, Direwolf).
 */
class IpMesh {
    interface Events {
        void connected(String id);
        void data(String id, byte[] bytes);
        void disconnected(String id);
        void kissData(String id, byte[] bytes);
        void kissClosed(String id);
        void error(String where, String message);
    }

    static final String TYPE = "_waslip._tcp";
    final ExecutorService pool = Executors.newCachedThreadPool();
    private final Context ctx;
    private final Events ev;
    private String name;
    private ServerSocket server;
    private NsdManager nsd;
    private NsdManager.RegistrationListener reg;
    private NsdManager.DiscoveryListener disc;
    private final Map<String, Conn> conns = new ConcurrentHashMap<>();
    private final Map<String, Socket> kiss = new ConcurrentHashMap<>();
    private final Set<String> dialed = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Deque<NsdServiceInfo> resolveQ = new ArrayDeque<>();
    private boolean resolving = false;

    private static class Conn {
        final Socket socket; final DataOutputStream out;
        Conn(Socket s) throws IOException { socket = s; out = new DataOutputStream(s.getOutputStream()); }
        synchronized void send(byte[] b) throws IOException { out.writeInt(b.length); out.write(b); out.flush(); }
    }

    IpMesh(Context ctx, Events ev) { this.ctx = ctx; this.ev = ev; }

    int start(String name) throws IOException {
        if (server != null) return server.getLocalPort();
        this.name = name;
        server = new ServerSocket(0);
        final ServerSocket srv = server;
        pool.execute(() -> {
            while (!srv.isClosed()) {
                try { attach(srv.accept()); } catch (IOException e) { break; }
            }
        });
        try { register(srv.getLocalPort()); discover(); } catch (Exception e) { ev.error("ip-discovery", String.valueOf(e.getMessage())); }
        return srv.getLocalPort();
    }

    private void register(int port) {
        nsd = (NsdManager) ctx.getSystemService(Context.NSD_SERVICE);
        NsdServiceInfo si = new NsdServiceInfo();
        si.setServiceName(name); si.setServiceType(TYPE); si.setPort(port);
        reg = new NsdManager.RegistrationListener() {
            @Override public void onRegistrationFailed(NsdServiceInfo s, int code) { ev.error("ip-register", "code " + code); }
            @Override public void onUnregistrationFailed(NsdServiceInfo s, int code) { }
            @Override public void onServiceRegistered(NsdServiceInfo s) { }
            @Override public void onServiceUnregistered(NsdServiceInfo s) { }
        };
        nsd.registerService(si, NsdManager.PROTOCOL_DNS_SD, reg);
    }

    private void discover() {
        disc = new NsdManager.DiscoveryListener() {
            @Override public void onStartDiscoveryFailed(String t, int code) { ev.error("ip-discover", "code " + code); }
            @Override public void onStopDiscoveryFailed(String t, int code) { }
            @Override public void onDiscoveryStarted(String t) { }
            @Override public void onDiscoveryStopped(String t) { }
            @Override public void onServiceLost(NsdServiceInfo s) { }
            @Override public void onServiceFound(NsdServiceInfo s) {
                String n = s.getServiceName();
                // only the lexically smaller name dials, so each pair opens a single connection
                if (n == null || n.equals(name) || name.compareTo(n) >= 0 || dialed.contains(n)) return;
                enqueueResolve(s);
            }
        };
        nsd.discoverServices(TYPE, NsdManager.PROTOCOL_DNS_SD, disc);
    }

    private synchronized void enqueueResolve(NsdServiceInfo s) { resolveQ.add(s); nextResolve(); }

    @SuppressWarnings("deprecation")
    private synchronized void nextResolve() {
        if (resolving || resolveQ.isEmpty()) return;
        resolving = true;
        NsdServiceInfo s = resolveQ.poll();
        nsd.resolveService(s, new NsdManager.ResolveListener() {
            @Override public void onResolveFailed(NsdServiceInfo si, int code) { finish(); }
            @Override public void onServiceResolved(NsdServiceInfo r) {
                dialed.add(r.getServiceName());
                final InetAddress host = r.getHost(); final int port = r.getPort();
                if (host != null) pool.execute(() -> dial(host.getHostAddress(), port));
                finish();
            }
            private void finish() { synchronized (IpMesh.this) { resolving = false; } nextResolve(); }
        });
    }

    void dial(String host, int port) {
        try {
            Socket s = new Socket();
            s.connect(new InetSocketAddress(host, port), 10000);
            attach(s);
        } catch (IOException e) { ev.error("ip-connect", host + ":" + port + " " + e.getMessage()); }
    }

    private void attach(Socket s) throws IOException {
        s.setTcpNoDelay(true); s.setKeepAlive(true);
        final String id = "ip:" + s.getInetAddress().getHostAddress() + ":" + s.getPort();
        final Conn c = new Conn(s);
        conns.put(id, c);
        ev.connected(id);
        pool.execute(() -> {
            try {
                DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
                while (true) {
                    int n = in.readInt();
                    if (n <= 0 || n > 4 * 1024 * 1024) break;
                    byte[] b = new byte[n]; in.readFully(b);
                    ev.data(id, b);
                }
            } catch (IOException ignored) {
            } finally {
                conns.remove(id);
                try { s.close(); } catch (IOException ignored) { }
                ev.disconnected(id);
            }
        });
    }

    boolean send(String id, byte[] b) {
        Conn c = conns.get(id);
        if (c == null) return false;
        try { c.send(b); return true; } catch (IOException e) { return false; }
    }

    /* raw TCP byte stream to a KISS modem */
    String kissConnect(String host, int port) throws IOException {
        Socket s = new Socket();
        s.connect(new InetSocketAddress(host, port), 10000);
        s.setTcpNoDelay(true);
        final String id = "kiss:" + host + ":" + port;
        Socket old = kiss.put(id, s);
        if (old != null) try { old.close(); } catch (IOException ignored) { }
        pool.execute(() -> {
            byte[] buf = new byte[4096];
            try {
                InputStream in = s.getInputStream();
                int n;
                while ((n = in.read(buf)) > 0) { byte[] b = new byte[n]; System.arraycopy(buf, 0, b, 0, n); ev.kissData(id, b); }
            } catch (IOException ignored) {
            } finally {
                if (kiss.get(id) == s) kiss.remove(id);
                ev.kissClosed(id);
            }
        });
        return id;
    }

    boolean kissSend(String id, byte[] b) {
        Socket s = kiss.get(id);
        if (s == null) return false;
        try { OutputStream o = s.getOutputStream(); synchronized (s) { o.write(b); o.flush(); } return true; }
        catch (IOException e) { return false; }
    }

    void kissClose(String id) { Socket s = kiss.remove(id); if (s != null) try { s.close(); } catch (IOException ignored) { } }

    void stop() {
        try { if (nsd != null && disc != null) nsd.stopServiceDiscovery(disc); } catch (Exception ignored) { }
        try { if (nsd != null && reg != null) nsd.unregisterService(reg); } catch (Exception ignored) { }
        try { if (server != null) server.close(); } catch (IOException ignored) { }
        for (Conn c : conns.values()) try { c.socket.close(); } catch (IOException ignored) { }
        for (Socket s : kiss.values()) try { s.close(); } catch (IOException ignored) { }
        conns.clear(); kiss.clear(); dialed.clear(); server = null;
    }

    static List<String> localAddresses() {
        List<String> out = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                for (InetAddress a : Collections.list(ni.getInetAddresses()))
                    if (a instanceof Inet4Address) out.add(a.getHostAddress());
            }
        } catch (Exception ignored) { }
        return out;
    }
}
