package com.securityscanner.app;

import android.net.VpnService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;

/**
 * TCP relay: forwards data between TUN (virtual app side) and a real socket (destination server).
 * Also captures HTTP content from both directions.
 */
public class TcpRelay {

    private final String dstIp;
    private final int dstPort;
    private final int localPort;
    private final TrafficVpnService vpnService;
    private Socket socket;
    private OutputStream socketOut;
    private InputStream socketIn;
    private volatile boolean connected = false;
    private volatile boolean closed = false;
    private int bytesSent = 0;
    private int bytesReceived = 0;

    public TcpRelay(TrafficVpnService vpnService, String dstIp, int dstPort, int localPort) {
        this.vpnService = vpnService;
        this.dstIp = dstIp;
        this.dstPort = dstPort;
        this.localPort = localPort;
    }

    public void start() {
        new Thread(this::connectToServer, "TCP-Relay-" + dstIp + ":" + dstPort).start();
    }

    private void connectToServer() {
        try {
            socket = new Socket();
            socket.setSoTimeout(10000);
            socket.setReceiveBufferSize(65535);
            socket.setSendBufferSize(65535);
            vpnService.protect(socket);
            socket.connect(new InetSocketAddress(dstIp, dstPort), 8000);
            socketOut = socket.getOutputStream();
            socketIn = socket.getInputStream();
            connected = true;

            // Start reading responses from server
            new Thread(this::readFromServer, "TCP-Read-" + dstIp + ":" + dstPort).start();

        } catch (IOException e) {
            close();
        }
    }

    /**
     * Send data from TUN (app) to real server.
     */
    public void sendData(byte[] data) {
        if (!connected || closed) return;
        try {
            socketOut.write(data);
            socketOut.flush();
            bytesSent += data.length;

            // Capture HTTP request content
            String[] httpInfo = PacketParser.parseHttpContent(data);
            if (httpInfo != null) {
                TrafficRecord record = new TrafficRecord();
                record.setDirection(TrafficRecord.Direction.SENT);
                record.setDstIp(dstIp);
                record.setDstPort(dstPort);
                record.setProtocol(TrafficRecord.Protocol.TCP);
                record.setPayloadSize(data.length);
                record.setHttp(true);
                record.setContentPreview(httpInfo[0]);
                record.setFullContent(httpInfo[1]);
                if (httpInfo[0].contains(" ")) {
                    String[] parts = httpInfo[0].split(" ");
                    if (parts.length >= 2) {
                        record.setHttpMethod(parts[0]);
                        record.setHttpUrl(parts[1]);
                    }
                }
                TrafficRecord.addRecord(record);
            }
        } catch (IOException e) {
            close();
        }
    }

    /**
     * Read data from real server and capture it.
     */
    private void readFromServer() {
        byte[] buffer = new byte[65535];
        while (connected && !closed) {
            try {
                int len = socketIn.read(buffer);
                if (len <= 0) break;

                bytesReceived += len;
                byte[] data = Arrays.copyOf(buffer, len);

                // Capture HTTP response content
                String[] httpInfo = PacketParser.parseHttpContent(data);
                if (httpInfo != null) {
                    TrafficRecord record = new TrafficRecord();
                    record.setDirection(TrafficRecord.Direction.RECEIVED);
                    record.setSrcIp(dstIp);
                    record.setSrcPort(dstPort);
                    record.setProtocol(TrafficRecord.Protocol.TCP);
                    record.setPayloadSize(len);
                    record.setHttp(true);
                    record.setContentPreview(httpInfo[0]);
                    record.setFullContent(httpInfo[1]);

                    // Try to parse status code
                    if (httpInfo[0].startsWith("HTTP/")) {
                        String[] parts = httpInfo[0].split(" ");
                        if (parts.length >= 2) {
                            try { record.setStatusCode(Integer.parseInt(parts[1])); } catch (Exception ignored) {}
                        }
                        // Try to extract Content-Type
                        if (httpInfo[1].toLowerCase().contains("content-type:")) {
                            String[] lines = httpInfo[1].split("\n");
                            for (String line : lines) {
                                if (line.toLowerCase().startsWith("content-type:")) {
                                    record.setContentType(line.substring(13).trim());
                                    break;
                                }
                            }
                        }
                    }
                    TrafficRecord.addRecord(record);
                } else {
                    // Binary data
                    TrafficRecord record = new TrafficRecord();
                    record.setDirection(TrafficRecord.Direction.RECEIVED);
                    record.setSrcIp(dstIp);
                    record.setSrcPort(dstPort);
                    record.setProtocol(TrafficRecord.Protocol.TCP);
                    record.setPayloadSize(len);
                    String preview = new String(data, 0, Math.min(len, 80));
                    record.setContentPreview("[Binary " + len + " bytes] <- " + dstIp + ":" + dstPort);
                    TrafficRecord.addRecord(record);
                }

                // Build and write response packet to TUN
                writeResponseToTun(data);

            } catch (SocketTimeoutException e) {
                // Normal timeout, keep reading
            } catch (IOException e) {
                break;
            }
        }
        close();
    }

    /**
     * Construct a TCP response packet and write to TUN.
     */
    private void writeResponseToTun(byte[] payload) {
        try {
            int ipHeaderLen = 20;
            int tcpHeaderLen = 20;
            int totalLen = ipHeaderLen + tcpHeaderLen + payload.length;

            byte[] packet = new byte[totalLen];

            // IP Header (20 bytes)
            packet[0] = (byte) 0x45; // Version 4, IHL 5
            packet[1] = 0x00;       // TOS
            packet[2] = (byte) ((totalLen >> 8) & 0xFF); // Total length
            packet[3] = (byte) (totalLen & 0xFF);
            packet[4] = 0x00; packet[5] = 0x01; // ID
            packet[6] = 0x40; packet[7] = 0x00; // Don't fragment
            packet[8] = 64;  // TTL
            packet[9] = 6;   // Protocol = TCP

            // Source IP (server)
            String[] dstParts = dstIp.split("\\.");
            packet[12] = (byte) Integer.parseInt(dstParts[0]);
            packet[13] = (byte) Integer.parseInt(dstParts[1]);
            packet[14] = (byte) Integer.parseInt(dstParts[2]);
            packet[15] = (byte) Integer.parseInt(dstParts[3]);

            // Dest IP (VPN gateway - 10.8.0.1)
            packet[16] = 10; packet[17] = 8; packet[18] = 0; packet[19] = 2;

            // IP checksum
            System.arraycopy(PacketParser.ipChecksum(Arrays.copyOf(packet, ipHeaderLen)), 0,
                    packet, 10, 2);

            // TCP Header (20 bytes)
            // Source port (server)
            packet[ipHeaderLen] = (byte) ((dstPort >> 8) & 0xFF);
            packet[ipHeaderLen + 1] = (byte) (dstPort & 0xFF);
            // Dest port (local)
            packet[ipHeaderLen + 2] = (byte) ((localPort >> 8) & 0xFF);
            packet[ipHeaderLen + 3] = (byte) (localPort & 0xFF);

            // Sequence number (simplified - use received bytes as approximation)
            int seq = bytesReceived - payload.length;
            packet[ipHeaderLen + 4] = (byte) ((seq >> 24) & 0xFF);
            packet[ipHeaderLen + 5] = (byte) ((seq >> 16) & 0xFF);
            packet[ipHeaderLen + 6] = (byte) ((seq >> 8) & 0xFF);
            packet[ipHeaderLen + 7] = (byte) (seq & 0xFF);

            // ACK number
            int ack = bytesSent + 1;
            packet[ipHeaderLen + 8] = (byte) ((ack >> 24) & 0xFF);
            packet[ipHeaderLen + 9] = (byte) ((ack >> 16) & 0xFF);
            packet[ipHeaderLen + 10] = (byte) ((ack >> 8) & 0xFF);
            packet[ipHeaderLen + 11] = (byte) (ack & 0xFF);

            // TCP flags: PSH + ACK
            packet[ipHeaderLen + 12] = (byte) 0x50; // Data offset = 5 (20 bytes)
            packet[ipHeaderLen + 13] = (byte) 0x18; // PSH + ACK

            // Window
            packet[ipHeaderLen + 14] = (byte) 0xFF;
            packet[ipHeaderLen + 15] = (byte) 0xFF;

            // Checksum (0 for simplicity - Android doesn't verify TUN packets strictly)
            packet[ipHeaderLen + 16] = 0;
            packet[ipHeaderLen + 17] = 0;

            // Copy payload
            System.arraycopy(payload, 0, packet, ipHeaderLen + tcpHeaderLen, payload.length);

            vpnService.writeToTun(packet);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean isConnected() {
        return connected && !closed;
    }

    public void close() {
        closed = true;
        connected = false;
        try { if (socket != null) socket.close(); } catch (Exception ignored) {}
        try { if (socketIn != null) socketIn.close(); } catch (Exception ignored) {}
        try { if (socketOut != null) socketOut.close(); } catch (Exception ignored) {}
    }
}
