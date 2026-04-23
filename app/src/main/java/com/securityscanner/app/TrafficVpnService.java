package com.securityscanner.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class TrafficVpnService extends VpnService {

    private static final String TAG = "TrafficVPN";
    private static final String CHANNEL_ID = "vpn_channel";
    private static final int NOTIFICATION_ID = 1001;
    private static final int MTU = 1500;
    public static final String ACTION_STOP = "com.securityscanner.app.STOP_VPN";

    private ParcelFileDescriptor tunFd;
    private volatile boolean running = false;
    private Thread vpnThread;
    private final ConcurrentHashMap<String, TcpRelay> tcpConnections = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, DatagramSocket> udpRelays = new ConcurrentHashMap<>();

    // Cache for UID -> package name
    private final ConcurrentHashMap<Integer, String> uidPackageCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Integer, String> uidAppCache = new ConcurrentHashMap<>();

    public interface TrafficListener {
        void onNewTraffic(TrafficRecord record);
    }
    private static TrafficListener trafficListener;

    public static void setTrafficListener(TrafficListener listener) {
        trafficListener = listener;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIFICATION_ID, buildNotification());

        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpnInternal();
            return START_NOT_STICKY;
        }

        running = true;
        startVpn();
        return START_STICKY;
    }

    private void stopVpnInternal() {
        running = false;
        stopForeground(true);
        stopSelf();

        new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
            for (TcpRelay relay : tcpConnections.values()) {
                relay.close();
            }
            tcpConnections.clear();
            for (DatagramSocket socket : udpRelays.values()) {
                try { socket.close(); } catch (Exception ignored) {}
            }
            udpRelays.clear();
            if (vpnThread != null) vpnThread.interrupt();
            try {
                if (tunFd != null) tunFd.close();
            } catch (Exception ignored) {}
            tunFd = null;
        }, 100);
    }

    private void startVpn() {
        VpnService.Builder builder = new VpnService.Builder()
                .setSession("Security Scanner Live")
                .addAddress("10.8.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
                .setBlocking(true)
                .setMtu(MTU);

        try {
            tunFd = builder.establish();
        } catch (Exception e) {
            e.printStackTrace();
            stopVpnInternal();
            return;
        }

        vpnThread = new Thread(this::readTunPackets, "VPN-TUN-Reader");
        vpnThread.start();
    }

    private void readTunPackets() {
        try (FileInputStream fis = new FileInputStream(tunFd.getFileDescriptor())) {
            byte[] raw = new byte[32767];
            while (running && !Thread.interrupted()) {
                int len = fis.read(raw);
                if (len > 0 && PacketParser.isIpv4(raw)) {
                    byte[] packet = new byte[len];
                    System.arraycopy(raw, 0, packet, 0, len);
                    processPacket(packet);
                }
            }
        } catch (IOException e) {
            if (running) e.printStackTrace();
        }
    }

    private void processPacket(byte[] packet) {
        int protocol = PacketParser.getProtocol(packet);
        String srcIp = PacketParser.getSourceIp(packet);
        String dstIp = PacketParser.getDestIp(packet);
        int srcPort = PacketParser.getSourcePort(packet);
        int dstPort = PacketParser.getDestPort(packet);

        // Skip VPN internal and DNS traffic
        if (srcIp.startsWith("10.8.0.") && dstPort == 53) return;
        if (dstIp.equals("8.8.8.8") || dstIp.equals("8.8.4.4")) return;

        if (protocol == PacketParser.PROTOCOL_TCP) {
            processTcp(packet, srcIp, dstIp, srcPort, dstPort);
        } else if (protocol == PacketParser.PROTOCOL_UDP) {
            processUdp(packet, srcIp, dstIp, srcPort, dstPort);
        }
    }

    private void processTcp(byte[] packet, String srcIp, String dstIp, int srcPort, int dstPort) {
        byte[] payload = PacketParser.getTcpPayload(packet);
        if (payload.length == 0) return;

        String connKey = srcIp + ":" + srcPort + "->" + dstIp + ":" + dstPort;

        // Resolve the real app package name from UID via /proc/net/tcp
        int uid = resolveUidFromProc(srcPort);
        String packageName = resolvePackageName(uid);
        String appName = resolveAppName(uid);

        TrafficRecord record = new TrafficRecord();
        record.setSrcIp(srcIp);
        record.setSrcPort(srcPort);
        record.setDstIp(dstIp);
        record.setDstPort(dstPort);
        record.setProtocol(TrafficRecord.Protocol.TCP);
        record.setDirection(TrafficRecord.Direction.SENT);
        record.setPayloadSize(payload.length);
        record.setPackageName(packageName);
        record.setAppName(appName);
        record.setUid(uid);

        String[] httpParsed = PacketParser.parseHttpContent(payload);
        if (httpParsed != null) {
            record.setHttp(true);
            record.setContentPreview(httpParsed[0]);
            record.setFullContent(httpParsed[1]);

            if (httpParsed[0].startsWith("GET") || httpParsed[0].startsWith("POST") ||
                    httpParsed[0].startsWith("PUT") || httpParsed[0].startsWith("DELETE") ||
                    httpParsed[0].startsWith("CONNECT") || httpParsed[0].startsWith("HEAD") ||
                    httpParsed[0].startsWith("PATCH") || httpParsed[0].startsWith("OPTIONS")) {
                String[] parts = httpParsed[0].split(" ");
                if (parts.length >= 2) {
                    record.setHttpMethod(parts[0]);
                    record.setHttpUrl(parts[1]);
                }
            }
        } else {
            String preview = new String(payload, 0, Math.min(payload.length, 100));
            record.setContentPreview("[Binary " + payload.length + " bytes] " + dstIp + ":" + dstPort);
        }

        TrafficRecord.addRecord(record);
        if (trafficListener != null) {
            trafficListener.onNewTraffic(record);
        }

        // Forward to real destination via relay
        TcpRelay relay = tcpConnections.get(connKey);
        if (relay == null || !relay.isConnected()) {
            relay = new TcpRelay(this, dstIp, dstPort, srcPort, uid, packageName, appName);
            tcpConnections.put(connKey, relay);
            relay.start();
        }
        relay.sendData(payload);
    }

    private void processUdp(byte[] packet, String srcIp, String dstIp, int srcPort, int dstPort) {
        byte[] payload = PacketParser.getUdpPayload(packet);
        if (payload.length == 0) return;

        int uid = resolveUidFromProc(srcPort);
        String packageName = resolvePackageName(uid);
        String appName = resolveAppName(uid);

        TrafficRecord record = new TrafficRecord();
        record.setSrcIp(srcIp);
        record.setSrcPort(srcPort);
        record.setDstIp(dstIp);
        record.setDstPort(dstPort);
        record.setProtocol(TrafficRecord.Protocol.UDP);
        record.setDirection(TrafficRecord.Direction.SENT);
        record.setPayloadSize(payload.length);
        record.setPackageName(packageName);
        record.setAppName(appName);
        record.setUid(uid);
        record.setContentPreview("UDP " + payload.length + " bytes -> " + dstIp + ":" + dstPort);
        TrafficRecord.addRecord(record);
        if (trafficListener != null) {
            trafficListener.onNewTraffic(record);
        }

        new Thread(() -> {
            try {
                DatagramSocket socket = new DatagramSocket();
                protect(socket);
                socket.setSoTimeout(3000);
                InetAddress address = InetAddress.getByName(dstIp);
                DatagramPacket sendPacket = new DatagramPacket(payload, payload.length, address, dstPort);
                socket.send(sendPacket);

                byte[] recvBuf = new byte[4096];
                DatagramPacket recvPacket = new DatagramPacket(recvBuf, recvBuf.length);
                try {
                    socket.receive(recvPacket);
                    TrafficRecord respRecord = new TrafficRecord();
                    respRecord.setDstIp(srcIp);
                    respRecord.setDstPort(srcPort);
                    respRecord.setSrcIp(dstIp);
                    respRecord.setSrcPort(dstPort);
                    respRecord.setProtocol(TrafficRecord.Protocol.UDP);
                    respRecord.setDirection(TrafficRecord.Direction.RECEIVED);
                    respRecord.setPayloadSize(recvPacket.getLength());
                    respRecord.setPackageName(packageName);
                    respRecord.setAppName(appName);
                    respRecord.setContentPreview("UDP " + recvPacket.getLength() + " bytes <- " + dstIp);
                    TrafficRecord.addRecord(respRecord);
                } catch (Exception ignored) {}
                socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    /**
     * Resolve UID from /proc/net/tcp and /proc/net/tcp6 by matching local port.
     */
    private int resolveUidFromProc(int srcPort) {
        try {
            int uid = searchUidInProcFile("/proc/net/tcp", srcPort);
            if (uid > 0) return uid;
            uid = searchUidInProcFile("/proc/net/tcp6", srcPort);
            if (uid > 0) return uid;
        } catch (Exception e) {
            // Silently ignore - fallback will be used
        }
        return -1;
    }

    private int searchUidInProcFile(String path, int targetPort) {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(path));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("  sl") || line.trim().isEmpty()) continue;
                String[] parts = line.trim().split("\\s+");
                if (parts.length < 10) continue;

                String localAddr = parts[1];
                int colonIdx = localAddr.lastIndexOf(':');
                if (colonIdx < 0) continue;

                try {
                    int port = Integer.parseInt(localAddr.substring(colonIdx + 1), 16);
                    if (port == targetPort) {
                        return Integer.parseInt(parts[7]);
                    }
                } catch (NumberFormatException ignored) {}
            }
        } catch (Exception e) {
            // File may not be readable
        } finally {
            if (reader != null) {
                try { reader.close(); } catch (Exception ignored) {}
            }
        }
        return -1;
    }

    /**
     * Resolve UID to package name with caching.
     */
    private String resolvePackageName(int uid) {
        if (uid <= 0) return "Unknown";
        String cached = uidPackageCache.get(uid);
        if (cached != null) return cached;

        try {
            PackageManager pm = getPackageManager();
            String[] packages = pm.getPackagesForUid(uid);
            if (packages != null && packages.length > 0) {
                // Prefer non-system packages
                for (String pkg : packages) {
                    try {
                        android.content.pm.ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
                        if ((ai.flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0) {
                            uidPackageCache.put(uid, pkg);
                            return pkg;
                        }
                    } catch (Exception ignored) {}
                }
                uidPackageCache.put(uid, packages[0]);
                return packages[0];
            }
        } catch (Exception e) {}
        String fallback = "UID:" + uid;
        uidPackageCache.put(uid, fallback);
        return fallback;
    }

    /**
     * Resolve UID to app display name with caching.
     */
    private String resolveAppName(int uid) {
        if (uid <= 0) return "Unknown";
        String cached = uidAppCache.get(uid);
        if (cached != null) return cached;

        try {
            PackageManager pm = getPackageManager();
            String[] packages = pm.getPackagesForUid(uid);
            if (packages != null && packages.length > 0) {
                for (String pkg : packages) {
                    try {
                        android.content.pm.ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
                        if ((ai.flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0) {
                            String name = pm.getApplicationLabel(ai).toString();
                            uidAppCache.put(uid, name);
                            return name;
                        }
                    } catch (Exception ignored) {}
                }
                String name = pm.getApplicationLabel(
                        pm.getApplicationInfo(packages[0], 0)).toString();
                uidAppCache.put(uid, name);
                return name;
            }
        } catch (Exception e) {}
        uidAppCache.put(uid, "App UID:" + uid);
        return "App UID:" + uid;
    }

    public void writeToTun(byte[] packet) {
        try {
            if (tunFd != null) {
                FileOutputStream fos = new FileOutputStream(tunFd.getFileDescriptor());
                fos.write(packet);
                fos.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "VPN Traffic Monitor",
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Dang theo doi traffic theo thoi gian thuc");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification() {
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        return new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Security Scanner - Live")
                .setContentText("Dang theo doi traffic...")
                .setSmallIcon(android.R.drawable.ic_menu_compass)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
    }

    @Override
    public void onDestroy() {
        running = false;
        TrafficRecord.clearRecords();
        for (TcpRelay relay : tcpConnections.values()) {
            relay.close();
        }
        tcpConnections.clear();
        for (DatagramSocket socket : udpRelays.values()) {
            try { socket.close(); } catch (Exception ignored) {}
        }
        udpRelays.clear();
        if (vpnThread != null) vpnThread.interrupt();
        try {
            if (tunFd != null) tunFd.close();
        } catch (Exception ignored) {}
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        running = false;
        stopForeground(true);
        stopSelf();
        super.onRevoke();
    }
}
