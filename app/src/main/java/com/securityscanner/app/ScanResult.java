package com.securityscanner.app;

public class ScanResult {
    public enum ThreatLevel {
        SAFE("An toan", 0x4CAF50),
        LOW("Thap", 0xFF9800),
        MEDIUM("Trung binh", 0xFFC107),
        HIGH("Cao", 0xFF5722),
        CRITICAL("Nguy hiem", 0xF44336);

        private final String label;
        private final int color;

        ThreatLevel(String label, int color) {
            this.label = label;
            this.color = color;
        }

        public String getLabel() { return label; }
        public int getColor() { return color; }
    }

    private String packageName;
    private String appName;
    private ThreatLevel threatLevel;
    private String description;
    private String[] detectedIssues;
    private boolean isSuspiciousNetwork;
    private boolean hasDangerousPermissions;
    private boolean hasKnownMalwareSignatures;

    public ScanResult(String packageName, String appName) {
        this.packageName = packageName;
        this.appName = appName;
        this.threatLevel = ThreatLevel.SAFE;
    }

    public String getPackageName() { return packageName; }
    public String getAppName() { return appName; }
    public ThreatLevel getThreatLevel() { return threatLevel; }
    public String getDescription() { return description; }
    public String[] getDetectedIssues() { return detectedIssues; }

    public void setThreatLevel(ThreatLevel level) { this.threatLevel = level; }
    public void setDescription(String description) { this.description = description; }
    public void setDetectedIssues(String[] issues) { this.detectedIssues = issues; }

    public boolean isSuspiciousNetwork() { return isSuspiciousNetwork; }
    public void setSuspiciousNetwork(boolean suspicious) { this.isSuspiciousNetwork = suspicious; }

    public boolean hasDangerousPermissions() { return hasDangerousPermissions; }
    public void setDangerousPermissions(boolean dangerous) { this.hasDangerousPermissions = dangerous; }

    public boolean hasKnownMalwareSignatures() { return hasKnownMalwareSignatures; }
    public void setKnownMalwareSignatures(boolean known) { this.hasKnownMalwareSignatures = known; }
}
