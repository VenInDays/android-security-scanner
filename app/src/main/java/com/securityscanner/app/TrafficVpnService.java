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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TrafficVpnService extends VpnService {

    private static final String TAG = "TrafficVPN";
    private static final String CHANNEL_ID = "vpn_channel";
    private static final int NOTIFICATION_ID = 1001;
    private static final int MTU = 1500;

    private ParcelFileDescriptor tunFd;
    private volatile boolean running = false;
    private Thread vpnThread;
    private final ConcurrentHashMap<String, TcpRelay> tcpConnections = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, DatagramSocket> udpRelays = new ConcurrentHashMap<>();

    // Callback for live UI updates
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
        running = true;
        startVpn();
        return START_STICKY;
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

        // Allow all apps (or specific apps)
        builder.addAllowedApplication("com.android.chrome");
        builder.addAllowedApplication("com.android.vending");
        builder.addAllowedApplication("com.google.android.gms");

        // Block nothing - monitor everything
        try {
            tunFd = builder.establish();
        } catch (Exception e) {
            e.printStackTrace();
            stopSelf();
            return;
        }

        vpnThread = new Thread(this::readTunPackets, "VPN-TUN-Reader");
        vpnThread.start();
    }

    private void readTunPackets() {
        ByteBuffer buffer = ByteBuffer.allocate(32767);
        byte[] packet;

        try (FileInputStream fis = new FileInputStream(tunFd.getFileDescriptor())) {
            byte[] raw = new byte[32767];
            while (running && !Thread.interrupted()) {
                int len = fis.read(raw);
                if (len > 0 && PacketParser.isIpv4(raw)) {
                    packet = new byte[len];
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

        // Skip VPN internal traffic and DNS
        if (srcIp.startsWith("10.8.0.") && dstPort == 53) return;
        if (dstIp.equals("8.8.8.8") || dstIp.equals("8.8.4.4")) return;

        if (protocol == PacketParser.PROTOCOL_TCP) {
            processTcp(packet, srcIp, dstIp, srcPort, dstPort);
        } else if (protocol == PacketParser.PROTOCOL_UDP) {
            processUdp(packet, srcIp, dstIp, srcPort, dstPort);
        }
    }

    private void processTcp(byte[] packet, String srcIp, String dstIp, int srcPort, int dstPort) {
        // Ignore packets without payload (SYN, ACK, etc.)
        byte[] payload = PacketParser.getTcpPayload(packet);
        if (payload.length == 0) return;

        String connKey = srcIp + ":" + srcPort + "->" + dstIp + ":" + dstPort;

        // Create traffic record
        String[] httpParsed = PacketParser.parseHttpContent(payload);
        TrafficRecord record = new TrafficRecord();
        record.setSrcIp(srcIp);
        record.setSrcPort(srcPort);
        record.setDstIp(dstIp);
        record.setDstPort(dstPort);
        record.setProtocol(TrafficRecord.Protocol.TCP);
        record.setDirection(TrafficRecord.Direction.SENT);
        record.setPayloadSize(payload.length);

        if (httpParsed != null) {
            record.setHttp(true);
            record.setContentPreview(httpParsed[0]);
            record.setFullContent(httpParsed[1]);

            if (httpParsed[0].startsWith("GET") || httpParsed[0].startsWith("POST") ||
                    httpParsed[0].startsWith("PUT") || httpParsed[0].startsWith("DELETE") ||
                    httpParsed[0].startsWith("CONNECT")) {
                record.setHttpMethod(httpParsed[0].split(" ")[0]);
                record.setHttpUrl(httpParsed[0].split(" ")[1]);
            }
        } else {
            // Binary or non-HTTP data
            String preview = new String(payload, 0, Math.min(payload.length, 100));
            record.setContentPreview("[Binary " + payload.length + " bytes] " + dstIp + ":" + dstPort);
        }

        // Resolve package name from UID (approximate via port mapping)
        resolvePackageName(record, srcPort);

        // Notify listener
        TrafficRecord.addRecord(record);
        if (trafficListener != null) {
            trafficListener.onNewTraffic(record);
        }

        // Forward to real destination via relay
        TcpRelay relay = tcpConnections.get(connKey);
        if (relay == null || !relay.isConnected()) {
            relay = new TcpRelay(this, dstIp, dstPort, srcPort);
            tcpConnections.put(connKey, relay);
            relay.start();
        }
        relay.sendData(payload);
    }

    private void processUdp(byte[] packet, String srcIp, String dstIp, int srcPort, int dstPort) {
        byte[] payload = PacketParser.getUdpPayload(packet);
        if (payload.length == 0) return;

        TrafficRecord record = new TrafficRecord();
        record.setSrcIp(srcIp);
        record.setSrcPort(srcPort);
        record.setDstIp(dstIp);
        record.setDstPort(dstPort);
        record.setProtocol(TrafficRecord.Protocol.UDP);
        record.setDirection(TrafficRecord.Direction.SENT);
        record.setPayloadSize(payload.length);
        record.setContentPreview("UDP " + payload.length + " bytes -> " + dstIp + ":" + dstPort);
        resolvePackageName(record, srcPort);
        TrafficRecord.addRecord(record);
        if (trafficListener != null) {
            trafficListener.onNewTraffic(record);
        }

        // Simple UDP relay
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
     * Write a packet back to TUN interface (for responses).
     */
    public void writeToTun(byte[] packet) {
        try (FileOutputStream fos = new FileOutputStream(tunFd.getFileDescriptor())) {
            fos.write(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void resolvePackageName(TrafficRecord record, int srcPort) {
        // Map port to app - approximate method
        try {
            PackageManager pm = getPackageManager();
            // Try to find by known ports or use a mapping
            String pkg = "unknown";
            record.setPackageName(pkg);
        } catch (Exception e) {
            record.setPackageName("unknown");
        }
    }

    public void setRecordPackageName(TrafficRecord record, int uid) {
        try {
            PackageManager pm = getPackageManager();
            String[] packages = pm.getPackagesForUid(uid);
            if (packages != null && packages.length > 0) {
                record.setPackageName(packages[0]);
            }
        } catch (Exception ignored) {}
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
        stopSelf();
        super.onRevoke();
    }
}
