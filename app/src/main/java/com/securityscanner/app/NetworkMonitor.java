package com.securityscanner.app;

import android.app.usage.NetworkStats;
import android.app.usage.NetworkStatsManager;
import android.content.Context;
import android.net.ConnectivityManager;
import android.os.Build;
import android.os.RemoteException;
import android.telephony.TelephonyManager;

import java.util.Calendar;
import java.util.Date;

public class NetworkMonitor {

    private final Context context;
    private final NetworkStatsManager networkStatsManager;

    public NetworkMonitor(Context context) {
        this.context = context;
        this.networkStatsManager = (NetworkStatsManager)
                context.getSystemService(Context.NETWORK_STATS_SERVICE);
    }

    /**
     * Get per-app network usage stats using NetworkStatsManager (mTim tracking).
     * Tracks bytes sent/received and last active timestamp per UID.
     */
    public void updateAppNetworkStats(AppInfo appInfo) {
        try {
            int uid = appInfo.getUid();
            long[] usage = getNetworkUsageForUid(uid);
            appInfo.setBytesSent(usage[0]);
            appInfo.setBytesReceived(usage[1]);
            appInfo.setLastUsedTimeMs(usage[2]);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Returns [bytesSent, bytesReceived, lastActiveTimestampMs] for a given UID.
     */
    private long[] getNetworkUsageForUid(int uid) throws RemoteException {
        long bytesSent = 0;
        long bytesReceived = 0;
        long lastActiveTimestamp = 0;

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, -7);
        long startTime = calendar.getTimeInMillis();
        long endTime = System.currentTimeMillis();

        // Query mobile data
        try {
            NetworkStats mobileStats = networkStatsManager.querySummary(
                    TelephonyManager.DATA_USAGE_SOURCE_MOBILE,
                    null, startTime, endTime);

            NetworkStats.Bucket bucket = new NetworkStats.Bucket();
            while (mobileStats.hasNextBucket()) {
                mobileStats.getNextBucket(bucket);
                if (bucket.getUid() == uid) {
                    bytesSent += bucket.getTxBytes();
                    bytesReceived += bucket.getRxBytes();
                    if (bucket.getStartTimeStamp() > lastActiveTimestamp) {
                        lastActiveTimestamp = bucket.getStartTimeStamp();
                    }
                }
            }
            mobileStats.close();
        } catch (Exception e) {
            // Mobile stats not available
        }

        // Query WiFi data
        try {
            NetworkStats wifiStats = networkStatsManager.querySummary(
                    ConnectivityManager.TYPE_WIFI,
                    null, startTime, endTime);

            NetworkStats.Bucket bucket = new NetworkStats.Bucket();
            while (wifiStats.hasNextBucket()) {
                wifiStats.getNextBucket(bucket);
                if (bucket.getUid() == uid) {
                    bytesSent += bucket.getTxBytes();
                    bytesReceived += bucket.getRxBytes();
                    if (bucket.getStartTimeStamp() > lastActiveTimestamp) {
                        lastActiveTimestamp = bucket.getStartTimeStamp();
                    }
                }
            }
            wifiStats.close();
        } catch (Exception e) {
            // WiFi stats not available
        }

        return new long[]{bytesSent, bytesReceived, lastActiveTimestamp};
    }

    /**
     * Check if an app has suspicious network activity
     * (high data usage in background, unusual upload patterns, etc.)
     */
    public boolean isSuspiciousNetworkActivity(AppInfo appInfo) {
        long totalBytes = appInfo.getBytesSent() + appInfo.getBytesReceived();
        // Flag if app sent more than 50MB in the last 7 days with mostly upload
        if (appInfo.getBytesSent() > 50 * 1024 * 1024
                && appInfo.getBytesSent() > appInfo.getBytesReceived()) {
            return true;
        }
        // Flag if very high total usage (>500MB) for a non-browser/non-streaming app
        String pkg = appInfo.getPackageName().toLowerCase();
        boolean isKnownHighUsage = pkg.contains("browser") || pkg.contains("chrome")
                || pkg.contains("youtube") || pkg.contains("netflix")
                || pkg.contains("facebook") || pkg.contains("instagram")
                || pkg.contains("tiktok") || pkg.contains("whatsapp")
                || pkg.contains("telegram") || pkg.contains("telegram");
        if (!isKnownHighUsage && totalBytes > 500 * 1024 * 1024) {
            return true;
        }
        return false;
    }

    /**
     * Format bytes into human-readable string
     */
    public static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        char unit = "KMGTPE".charAt(exp - 1);
        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), unit);
    }

    /**
     * Format timestamp into human-readable relative time
     */
    public static String formatLastUsed(long timestampMs) {
        if (timestampMs <= 0) return "Chua su dung";
        long now = System.currentTimeMillis();
        long diffMs = now - timestampMs;
        long diffMin = diffMs / (60 * 1000);
        long diffHour = diffMs / (60 * 60 * 1000);
        long diffDay = diffMs / (24 * 60 * 60 * 1000);

        if (diffMin < 1) return "Vua xong";
        if (diffMin < 60) return diffMin + " phut truoc";
        if (diffHour < 24) return diffHour + " gio truoc";
        if (diffDay < 7) return diffDay + " ngay truoc";
        return new Date(timestampMs).toString();
    }
}
