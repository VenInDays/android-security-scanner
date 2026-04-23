package com.securityscanner.app;

public class PacketParser {

    public static final int PROTOCOL_TCP = 6;
    public static final int PROTOCOL_UDP = 17;

    private PacketParser() {}

    public static int getIpVersion(byte[] packet) {
        return (packet[0] >> 4) & 0x0F;
    }

    public static boolean isIpv4(byte[] packet) {
        return packet.length >= 20 && getIpVersion(packet) == 4;
    }

    public static int getIpHeaderLength(byte[] packet) {
        return (packet[0] & 0x0F) * 4;
    }

    public static int getTotalLength(byte[] packet) {
        return ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
    }

    public static int getProtocol(byte[] packet) {
        return packet[9] & 0xFF;
    }

    public static String getSourceIp(byte[] packet) {
        return formatIp(packet, 12);
    }

    public static String getDestIp(byte[] packet) {
        return formatIp(packet, 16);
    }

    private static String formatIp(byte[] packet, int offset) {
        return (packet[offset] & 0xFF) + "." +
               (packet[offset + 1] & 0xFF) + "." +
               (packet[offset + 2] & 0xFF) + "." +
               (packet[offset + 3] & 0xFF);
    }

    public static int getSourcePort(byte[] packet) {
        int offset = getIpHeaderLength(packet);
        if (offset + 3 >= packet.length) return 0;
        return ((packet[offset] & 0xFF) << 8) | (packet[offset + 1] & 0xFF);
    }

    public static int getDestPort(byte[] packet) {
        int offset = getIpHeaderLength(packet);
        if (offset + 3 >= packet.length) return 0;
        return ((packet[offset + 2] & 0xFF) << 8) | (packet[offset + 3] & 0xFF);
    }

    public static int getTcpHeaderLength(byte[] packet) {
        int offset = getIpHeaderLength(packet);
        if (offset + 12 >= packet.length) return 20;
        return ((packet[offset + 12] & 0xF0) >> 4) * 4;
    }

    public static int getTcpFlags(byte[] packet) {
        int offset = getIpHeaderLength(packet);
        if (offset + 13 >= packet.length) return 0;
        return packet[offset + 13] & 0xFF;
    }

    public static boolean isSyn(byte[] packet) {
        return (getTcpFlags(packet) & 0x02) != 0;
    }

    public static boolean isAck(byte[] packet) {
        return (getTcpFlags(packet) & 0x10) != 0;
    }

    public static boolean isFin(byte[] packet) {
        return (getTcpFlags(packet) & 0x01) != 0;
    }

    public static boolean isPsh(byte[] packet) {
        return (getTcpFlags(packet) & 0x08) != 0;
    }

    public static boolean isRst(byte[] packet) {
        return (getTcpFlags(packet) & 0x04) != 0;
    }

    public static int getSequenceNumber(byte[] packet) {
        int offset = getIpHeaderLength(packet);
        if (offset + 7 >= packet.length) return 0;
        return ((packet[offset + 4] & 0xFF) << 24) |
               ((packet[offset + 5] & 0xFF) << 16) |
               ((packet[offset + 6] & 0xFF) << 8) |
               (packet[offset + 7] & 0xFF);
    }

    public static int getAckNumber(byte[] packet) {
        int offset = getIpHeaderLength(packet);
        if (offset + 11 >= packet.length) return 0;
        return ((packet[offset + 8] & 0xFF) << 24) |
               ((packet[offset + 9] & 0xFF) << 16) |
               ((packet[offset + 10] & 0xFF) << 8) |
               (packet[offset + 11] & 0xFF);
    }

    public static byte[] getTcpPayload(byte[] packet) {
        int ipLen = getIpHeaderLength(packet);
        int tcpLen = getTcpHeaderLength(packet);
        int headerTotal = ipLen + tcpLen;
        if (headerTotal >= packet.length) return new byte[0];
        byte[] payload = new byte[packet.length - headerTotal];
        System.arraycopy(packet, headerTotal, payload, 0, payload.length);
        return payload;
    }

    public static byte[] getUdpPayload(byte[] packet) {
        int ipLen = getIpHeaderLength(packet);
        int headerTotal = ipLen + 8;
        if (headerTotal >= packet.length) return new byte[0];
        byte[] payload = new byte[packet.length - headerTotal];
        System.arraycopy(packet, headerTotal, payload, 0, payload.length);
        return payload;
    }

    /**
     * Try to parse HTTP content from TCP payload.
     * Returns a string array: [method/url or status line, headers+body preview]
     * or null if not HTTP.
     */
    public static String[] parseHttpContent(byte[] payload) {
        if (payload == null || payload.length < 4) return null;
        try {
            String text = new String(payload, 0, Math.min(payload.length, 4096), "UTF-8");
            if (text.startsWith("GET ") || text.startsWith("POST ") ||
                text.startsWith("PUT ") || text.startsWith("DELETE ") ||
                text.startsWith("HEAD ") || text.startsWith("PATCH ") ||
                text.startsWith("OPTIONS ") || text.startsWith("CONNECT ")) {
                // HTTP request
                int firstLineEnd = text.indexOf('\n');
                if (firstLineEnd > 0) {
                    String firstLine = text.substring(0, firstLineEnd).trim();
                    String rest = text.substring(firstLineEnd).trim();
                    return new String[]{firstLine, rest.length() > 300 ? rest.substring(0, 300) + "..." : rest};
                }
            } else if (text.startsWith("HTTP/1.") || text.startsWith("HTTP/2")) {
                // HTTP response
                int firstLineEnd = text.indexOf('\n');
                if (firstLineEnd > 0) {
                    String firstLine = text.substring(0, firstLineEnd).trim();
                    String rest = text.substring(firstLineEnd).trim();
                    return new String[]{firstLine, rest.length() > 300 ? rest.substring(0, 300) + "..." : rest};
                }
            }
        } catch (Exception e) {
            // Not text, binary data
        }
        return null;
    }

    /**
     * Calculate IP header checksum
     */
    public static short ipChecksum(byte[] header) {
        int sum = 0;
        for (int i = 0; i < header.length; i += 2) {
            if (i + 1 < header.length) {
                sum += ((header[i] & 0xFF) << 8) | (header[i + 1] & 0xFF);
            } else {
                sum += (header[i] & 0xFF) << 8;
            }
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (short) (~sum & 0xFFFF);
    }
}
