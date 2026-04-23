package com.securityscanner.app;

import android.app.AppOpsManager;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private RecyclerView recyclerView;
    private AppListAdapter adapter;
    private SwipeRefreshLayout swipeRefreshLayout;
    private TextView statsText;
    private EditText searchInput;
    private LinearLayout filterBar;
    private Button filterAllBtn, filterSafeBtn, filterThreatsBtn;
    private Button scanBtn;

    private ExecutorService executor;
    private NetworkMonitor networkMonitor;
    private MalwareScanner malwareScanner;
    private List<AppInfo> allApps = new ArrayList<>();
    private List<ScanResult> allResults = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        executor = Executors.newSingleThreadExecutor();
        networkMonitor = new NetworkMonitor(this);
        malwareScanner = new MalwareScanner(this);

        initViews();
        setupRecyclerView();
        setupListeners();

        // Check permission and load apps
        if (hasUsageStatsPermission()) {
            loadAndScanApps();
        } else {
            requestUsageStatsPermission();
        }
    }

    private void initViews() {
        recyclerView = findViewById(R.id.recycler_view);
        swipeRefreshLayout = findViewById(R.id.swipe_refresh);
        statsText = findViewById(R.id.stats_text);
        searchInput = findViewById(R.id.search_input);
        filterBar = findViewById(R.id.filter_bar);
        filterAllBtn = findViewById(R.id.filter_all);
        filterSafeBtn = findViewById(R.id.filter_safe);
        filterThreatsBtn = findViewById(R.id.filter_threats);
        scanBtn = findViewById(R.id.scan_btn);
    }

    private void setupRecyclerView() {
        adapter = new AppListAdapter(this);
        adapter.setOnAppClickListener(this::showAppDetail);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        recyclerView.setAdapter(adapter);
    }

    private void setupListeners() {
        swipeRefreshLayout.setOnRefreshListener(() -> {
            if (hasUsageStatsPermission()) {
                loadAndScanApps();
            } else {
                swipeRefreshLayout.setRefreshing(false);
                requestUsageStatsPermission();
            }
        });

        scanBtn.setOnClickListener(v -> {
            if (hasUsageStatsPermission()) {
                loadAndScanApps();
            } else {
                requestUsageStatsPermission();
            }
        });

        searchInput.setOnEditorActionListener((v, actionId, event) -> {
            adapter.setFilter(searchInput.getText().toString(),
                    adapter.getFilterMode() != null ? adapter.getFilterMode() : AppListAdapter.FilterMode.ALL);
            return false;
        });

        filterAllBtn.setOnClickListener(v -> {
            adapter.setFilter(searchInput.getText().toString(), AppListAdapter.FilterMode.ALL);
            updateFilterButtons(AppListAdapter.FilterMode.ALL);
        });
        filterSafeBtn.setOnClickListener(v -> {
            adapter.setFilter(searchInput.getText().toString(), AppListAdapter.FilterMode.SAFE);
            updateFilterButtons(AppListAdapter.FilterMode.SAFE);
        });
        filterThreatsBtn.setOnClickListener(v -> {
            adapter.setFilter(searchInput.getText().toString(), AppListAdapter.FilterMode.THREATS);
            updateFilterButtons(AppListAdapter.FilterMode.THREATS);
        });
    }

    private void updateFilterButtons(AppListAdapter.FilterMode activeMode) {
        filterAllBtn.setSelected(activeMode == AppListAdapter.FilterMode.ALL);
        filterSafeBtn.setSelected(activeMode == AppListAdapter.FilterMode.SAFE);
        filterThreatsBtn.setSelected(activeMode == AppListAdapter.FilterMode.THREATS);
    }

    private boolean hasUsageStatsPermission() {
        AppOpsManager appOps = (AppOpsManager) getSystemService(Context.APP_OPS_SERVICE);
        int mode;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            mode = appOps.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    android.os.Process.myUid(), getPackageName());
        } else {
            mode = appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    android.os.Process.myUid(), getPackageName());
        }
        return mode == AppOpsManager.MODE_ALLOWED;
    }

    private void requestUsageStatsPermission() {
        new AlertDialog.Builder(this)
                .setTitle("Can quyen truy cap")
                .setMessage("App can quyen \"Usage Access\" de theo doi hoat dong mang va quet bao mat. Vui long cap quyen de tiep tuc.")
                .setPositiveButton("Mo cai dat", (dialog, which) -> {
                    Intent intent = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
                    startActivity(intent);
                })
                .setNegativeButton("Huy", (dialog, which) -> {
                    Toast.makeText(this, "Can quyen Usage Access de su dung app", Toast.LENGTH_LONG).show();
                })
                .setCancelable(false)
                .show();
    }

    private void loadAndScanApps() {
        scanBtn.setEnabled(false);
        scanBtn.setText("Dang quet...");
        swipeRefreshLayout.setRefreshing(true);

        executor.execute(() -> {
            List<AppInfo> apps = getInstalledApps();
            allApps = apps;

            // Update network stats for all apps
            for (AppInfo app : apps) {
                networkMonitor.updateAppNetworkStats(app);
            }

            // Update last used time from UsageStatsManager
            updateLastUsedTimes(apps);

            // Sort by last used time (most recent first)
            Collections.sort(apps, (a, b) ->
                    Long.compare(b.getLastUsedTimeMs(), a.getLastUsedTimeMs()));

            // Run malware scan
            List<ScanResult> scanResults = new ArrayList<>();
            for (AppInfo app : apps) {
                ScanResult result = malwareScanner.scanApp(app);
                // Also check network activity
                result.setSuspiciousNetwork(networkMonitor.isSuspiciousNetworkActivity(app));
                scanResults.add(result);
            }
            allResults = scanResults;

            // Count threats
            int safeCount = 0, threatCount = 0;
            for (ScanResult r : scanResults) {
                if (r.getThreatLevel() == ScanResult.ThreatLevel.SAFE) safeCount++;
                else threatCount++;
            }
            int finalSafe = safeCount;
            int finalThreats = threatCount;
            int total = apps.size();

            runOnUiThread(() -> {
                adapter.setData(apps, scanResults);
                statsText.setText(String.format("Tong: %d | An toan: %d | Co van de: %d",
                        total, finalSafe, finalThreats));
                scanBtn.setEnabled(true);
                scanBtn.setText("Quet lai");
                swipeRefreshLayout.setRefreshing(false);
                Toast.makeText(this,
                        "Quet xong! " + finalThreats + " app co van de bao mat.",
                        Toast.LENGTH_SHORT).show();
            });
        });
    }

    private List<AppInfo> getInstalledApps() {
        List<AppInfo> apps = new ArrayList<>();
        PackageManager pm = getPackageManager();

        List<PackageInfo> packages;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packages = pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(
                    PackageManager.GET_META_DATA));
        } else {
            packages = pm.getInstalledPackages(PackageManager.GET_META_DATA);
        }

        for (PackageInfo packageInfo : packages) {
            try {
                ApplicationInfo appInfo = packageInfo.applicationInfo;
                if ((appInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0
                        || (appInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) {
                    // Skip our own package
                    if (packageInfo.packageName.equals(getPackageName())) continue;

                    AppInfo info = new AppInfo(
                            packageInfo.packageName,
                            appInfo.loadLabel(pm).toString(),
                            appInfo.loadIcon(pm)
                    );
                    info.setUid(appInfo.uid);
                    info.setSystemApp((appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
                    info.setVersionName(packageInfo.versionName != null ? packageInfo.versionName : "N/A");
                    info.setInstallTimeMs(packageInfo.firstInstallTime);
                    info.setUpdateTimeMs(packageInfo.lastUpdateTime);
                    apps.add(info);
                }
            } catch (Exception e) {
                // Skip packages that can't be loaded
            }
        }

        return apps;
    }

    private void updateLastUsedTimes(List<AppInfo> apps) {
        UsageStatsManager usageStatsManager = (UsageStatsManager)
                getSystemService(Context.USAGE_STATS_SERVICE);

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, -7);
        long startTime = calendar.getTimeInMillis();
        long endTime = System.currentTimeMillis();

        List<UsageStats> stats;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            stats = usageStatsManager.queryUsageStats(
                    UsageStatsManager.INTERVAL_BEST, startTime, endTime);
        } else {
            stats = usageStatsManager.queryUsageStats(
                    UsageStatsManager.INTERVAL_DAILY, startTime, endTime);
        }

        if (stats == null) return;

        // Map UID -> last used time for quick lookup
        // Also map package name -> last used time
        java.util.HashMap<String, Long> packageLastUsed = new java.util.HashMap<>();
        for (UsageStats stat : stats) {
            Long existing = packageLastUsed.get(stat.getPackageName());
            if (existing == null || stat.getLastTimeStamp() > existing) {
                packageLastUsed.put(stat.getPackageName(), stat.getLastTimeStamp());
            }
        }

        // Apply to apps
        for (AppInfo app : apps) {
            Long lastUsed = packageLastUsed.get(app.getPackageName());
            if (lastUsed != null && lastUsed > app.getLastUsedTimeMs()) {
                app.setLastUsedTimeMs(lastUsed);
            }
        }
    }

    private void showAppDetail(AppInfo appInfo, ScanResult result) {
        View detailView = getLayoutInflater().inflate(R.layout.dialog_scan_result, null);

        TextView nameView = detailView.findViewById(R.id.detail_name);
        TextView packageView = detailView.findViewById(R.id.detail_package);
        TextView versionView = detailView.findViewById(R.id.detail_version);
        TextView networkView = detailView.findViewById(R.id.detail_network);
        TextView lastUsedView = detailView.findViewById(R.id.detail_last_used);
        TextView threatView = detailView.findViewById(R.id.detail_threat);
        TextView issuesView = detailView.findViewById(R.id.detail_issues);

        nameView.setText(appInfo.getAppName());
        packageView.setText(appInfo.getPackageName());
        versionView.setText("Phien ban: " + appInfo.getVersionName());
        networkView.setText(
                "Gui: " + NetworkMonitor.formatBytes(appInfo.getBytesSent())
                        + "\nNhan: " + NetworkMonitor.formatBytes(appInfo.getBytesReceived())
                        + "\nTong: " + NetworkMonitor.formatBytes(
                        appInfo.getBytesSent() + appInfo.getBytesReceived()));
        lastUsedView.setText("Lan cuoi su dung: " + NetworkMonitor.formatLastUsed(appInfo.getLastUsedTimeMs()));

        if (result != null) {
            threatView.setText("Muc do: " + result.getThreatLevel().getLabel());
            threatView.setTextColor(getResources().getColor(
                    result.getThreatLevel().getColor(), getTheme()));

            StringBuilder issues = new StringBuilder();
            if (result.getDetectedIssues() != null && result.getDetectedIssues().length > 0) {
                for (String issue : result.getDetectedIssues()) {
                    issues.append("  - ").append(issue).append("\n");
                }
            } else {
                issues.append("  Khong phat hien van de nao.");
            }
            if (result.isSuspiciousNetwork()) {
                issues.append("  - Hoat dong mang bat thuong (upload cao)\n");
            }
            issuesView.setText(issues.toString());
        }

        new AlertDialog.Builder(this)
                .setTitle("Chi tiet bao mat")
                .setView(detailView)
                .setPositiveButton("OK", null)
                .show();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (hasUsageStatsPermission() && allApps.isEmpty()) {
            loadAndScanApps();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
    }
}
