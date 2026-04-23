package com.securityscanner.app;

import android.graphics.drawable.Drawable;

public class AppInfo {
    private String packageName;
    private String appName;
    private Drawable icon;
    private long lastUsedTimeMs;
    private long bytesSent;
    private long bytesReceived;
    private boolean isSystemApp;
    private String versionName;
    private long installTimeMs;
    private long updateTimeMs;
    private int uid;

    public AppInfo(String packageName, String appName, Drawable icon) {
        this.packageName = packageName;
        this.appName = appName;
        this.icon = icon;
    }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getAppName() { return appName; }
    public void setAppName(String appName) { this.appName = appName; }

    public Drawable getIcon() { return icon; }
    public void setIcon(Drawable icon) { this.icon = icon; }

    public long getLastUsedTimeMs() { return lastUsedTimeMs; }
    public void setLastUsedTimeMs(long lastUsedTimeMs) { this.lastUsedTimeMs = lastUsedTimeMs; }

    public long getBytesSent() { return bytesSent; }
    public void setBytesSent(long bytesSent) { this.bytesSent = bytesSent; }

    public long getBytesReceived() { return bytesReceived; }
    public void setBytesReceived(long bytesReceived) { this.bytesReceived = bytesReceived; }

    public boolean isSystemApp() { return isSystemApp; }
    public void setSystemApp(boolean systemApp) { isSystemApp = systemApp; }

    public String getVersionName() { return versionName; }
    public void setVersionName(String versionName) { this.versionName = versionName; }

    public long getInstallTimeMs() { return installTimeMs; }
    public void setInstallTimeMs(long installTimeMs) { this.installTimeMs = installTimeMs; }

    public long getUpdateTimeMs() { return updateTimeMs; }
    public void setUpdateTimeMs(long updateTimeMs) { this.updateTimeMs = updateTimeMs; }

    public int getUid() { return uid; }
    public void setUid(int uid) { this.uid = uid; }
}
