package com.securityscanner.app;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TrafficRecord {

    public enum Direction {
        SENT("Gui", 0xFF4CAF50),
        RECEIVED("Nhan", 0xFF2196F3);

        private final String label;
        private final int color;

        Direction(String label, int color) {
            this.label = label;
            this.color = color;
        }

        public String getLabel() { return label; }
        public int getColor() { return color; }
    }

    public enum Protocol {
        TCP, UDP, UNKNOWN
    }

    private long timestamp;
    private String packageName;
    private int uid;
    private String srcIp;
    private int srcPort;
    private String dstIp;
    private int dstPort;
    private Protocol protocol;
    private Direction direction;
    private String contentPreview;
    private String fullContent;
    private int payloadSize;
    private boolean isHttp;
    private String httpMethod;
    private String httpUrl;
    private int statusCode;
    private String contentType;

    private static final List<TrafficRecord> liveRecords =
            Collections.synchronizedList(new ArrayList<TrafficRecord>());
    private static final int MAX_RECORDS = 500;

    public TrafficRecord() {
        this.timestamp = System.currentTimeMillis();
    }

    public static void addRecord(TrafficRecord record) {
        liveRecords.add(record);
        if (liveRecords.size() > MAX_RECORDS) {
            liveRecords.remove(0);
        }
    }

    public static List<TrafficRecord> getRecords() {
        return new ArrayList<>(liveRecords);
    }

    public static void clearRecords() {
        liveRecords.clear();
    }

    // Getters and setters
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public int getUid() { return uid; }
    public void setUid(int uid) { this.uid = uid; }

    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }

    public int getSrcPort() { return srcPort; }
    public void setSrcPort(int srcPort) { this.srcPort = srcPort; }

    public String getDstIp() { return dstIp; }
    public void setDstIp(String dstIp) { this.dstIp = dstIp; }

    public int getDstPort() { return dstPort; }
    public void setDstPort(int dstPort) { this.dstPort = dstPort; }

    public Protocol getProtocol() { return protocol; }
    public void setProtocol(Protocol protocol) { this.protocol = protocol; }

    public Direction getDirection() { return direction; }
    public void setDirection(Direction direction) { this.direction = direction; }

    public String getContentPreview() { return contentPreview; }
    public void setContentPreview(String contentPreview) { this.contentPreview = contentPreview; }

    public String getFullContent() { return fullContent; }
    public void setFullContent(String fullContent) { this.fullContent = fullContent; }

    public int getPayloadSize() { return payloadSize; }
    public void setPayloadSize(int payloadSize) { this.payloadSize = payloadSize; }

    public boolean isHttp() { return isHttp; }
    public void setHttp(boolean http) { isHttp = http; }

    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public String getHttpUrl() { return httpUrl; }
    public void setHttpUrl(String httpUrl) { this.httpUrl = httpUrl; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }
}
