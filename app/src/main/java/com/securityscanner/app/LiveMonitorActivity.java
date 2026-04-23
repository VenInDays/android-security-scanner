package com.securityscanner.app;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import java.util.ArrayList;
import java.util.List;

public class LiveMonitorActivity extends AppCompatActivity {

    private RecyclerView recyclerView;
    private TrafficListAdapter adapter;
    private SwipeRefreshLayout swipeRefreshLayout;
    private TextView statsText;
    private TextView statusText;
    private Button toggleVpnBtn;
    private Button installCertBtn;
    private Button clearBtn;

    private Handler handler = new Handler(Looper.getMainLooper());
    private Runnable updateRunnable;
    private boolean isVpnActive = false;
    private static final int VPN_REQUEST_CODE = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_live_monitor);

        initViews();
        setupRecyclerView();
        setupListeners();
        checkVpnStatus();
    }

    private void initViews() {
        recyclerView = findViewById(R.id.traffic_recycler);
        swipeRefreshLayout = findViewById(R.id.traffic_swipe);
        statsText = findViewById(R.id.traffic_stats);
        statusText = findViewById(R.id.vpn_status);
        toggleVpnBtn = findViewById(R.id.toggle_vpn_btn);
        installCertBtn = findViewById(R.id.install_cert_btn);
        clearBtn = findViewById(R.id.clear_btn);
    }

    private void setupRecyclerView() {
        adapter = new TrafficListAdapter();
        adapter.setOnItemClickListener((record, position) -> showTrafficDetail(record));
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        recyclerView.setAdapter(adapter);
    }

    private void setupListeners() {
        toggleVpnBtn.setOnClickListener(v -> {
            if (isVpnActive) {
                stopVpn();
            } else {
                startVpn();
            }
        });

        installCertBtn.setOnClickListener(v -> {
            CertUtils.installCertificate(this);
        });

        clearBtn.setOnClickListener(v -> {
            TrafficRecord.clearRecords();
            adapter.updateData(new ArrayList<>());
            statsText.setText("Tong: 0 | Gui: 0 | Nhan: 0 | App: 0");
            Toast.makeText(this, "Da xoa toan bo traffic log", Toast.LENGTH_SHORT).show();
        });

        swipeRefreshLayout.setOnRefreshListener(() -> {
            updateTrafficList();
            swipeRefreshLayout.setRefreshing(false);
        });
    }

    private void checkVpnStatus() {
        isVpnActive = isVpnServiceRunning();
        updateVpnUi();
    }

    private boolean isVpnServiceRunning() {
        ActivityManager am = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
        if (am != null) {
            for (ActivityManager.RunningServiceInfo si : am.getRunningServices(100)) {
                if (TrafficVpnService.class.getName().equals(si.service.getClassName())) {
                    return true;
                }
            }
        }
        return false;
    }

    private void startVpn() {
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
        } else {
            launchVpnService();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            launchVpnService();
        } else if (requestCode == VPN_REQUEST_CODE) {
            Toast.makeText(this, "Can cap quyen VPN de bat live monitor",
                    Toast.LENGTH_LONG).show();
        }
    }

    private void launchVpnService() {
        Intent intent = new Intent(this, TrafficVpnService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }

        isVpnActive = true;
        updateVpnUi();
        startAutoRefresh();

        TrafficVpnService.setTrafficListener(record -> {
            handler.post(() -> updateTrafficList());
        });

        Toast.makeText(this, "VPN da bat - Dang theo doi traffic", Toast.LENGTH_SHORT).show();
    }

    /**
     * Stop VPN by sending STOP action to the service.
     * The service handles clean shutdown (stopForeground + close TUN + stopSelf).
     */
    private void stopVpn() {
        try {
            // Send STOP action to the service
            Intent intent = new Intent(this, TrafficVpnService.class);
            intent.setAction(TrafficVpnService.ACTION_STOP);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent);
            } else {
                startService(intent);
            }

            // Also call stopService as backup
            stopService(new Intent(this, TrafficVpnService.class));
        } catch (Exception e) {
            e.printStackTrace();
        }

        isVpnActive = false;
        updateVpnUi();
        stopAutoRefresh();
        Toast.makeText(this, "VPN da tat", Toast.LENGTH_SHORT).show();
    }

    private void updateVpnUi() {
        if (isVpnActive) {
            statusText.setText("VPN: DANG BAT");
            statusText.setTextColor(0xFF4CAF50);
            toggleVpnBtn.setText("Tat VPN");
            toggleVpnBtn.setBackground(ContextCompat.getDrawable(this, R.drawable.btn_danger));
        } else {
            statusText.setText("VPN: TAT");
            statusText.setTextColor(0xFF666666);
            toggleVpnBtn.setText("Bat Live Monitor");
            toggleVpnBtn.setBackground(ContextCompat.getDrawable(this, R.drawable.scan_btn_bg));
        }
    }

    private void startAutoRefresh() {
        updateRunnable = new Runnable() {
            @Override
            public void run() {
                updateTrafficList();
                handler.postDelayed(this, 1500);
            }
        };
        handler.postDelayed(updateRunnable, 1500);
    }

    private void stopAutoRefresh() {
        if (updateRunnable != null) {
            handler.removeCallbacks(updateRunnable);
        }
    }

    private void updateTrafficList() {
        List<TrafficRecord> records = TrafficRecord.getRecords();
        // Show newest first
        ArrayList<TrafficRecord> reversed = new ArrayList<>(records);
        java.util.Collections.reverse(reversed);
        adapter.updateData(reversed);

        int sent = 0, received = 0;
        java.util.HashSet<String> uniqueApps = new java.util.HashSet<>();
        for (TrafficRecord r : records) {
            if (r.getDirection() == TrafficRecord.Direction.SENT) sent++;
            else received++;
            if (r.getAppName() != null && !r.getAppName().isEmpty()) {
                uniqueApps.add(r.getAppName());
            }
        }
        statsText.setText(String.format("Tong: %d | Gui: %d | Nhan: %d | App: %d",
                records.size(), sent, received, uniqueApps.size()));
    }

    private void showTrafficDetail(TrafficRecord record) {
        View detailView = getLayoutInflater().inflate(R.layout.dialog_traffic_detail, null);

        TextView dirView = detailView.findViewById(R.id.traffic_direction);
        TextView protoView = detailView.findViewById(R.id.traffic_protocol);
        TextView connView = detailView.findViewById(R.id.traffic_connection);
        TextView sizeView = detailView.findViewById(R.id.traffic_size);
        TextView httpView = detailView.findViewById(R.id.traffic_http_info);
        TextView contentView = detailView.findViewById(R.id.traffic_content);
        TextView timeView = detailView.findViewById(R.id.traffic_time);

        dirView.setText(record.getDirection().getLabel());
        dirView.setTextColor(record.getDirection().getColor());

        StringBuilder protoInfo = new StringBuilder("Giao thuc: " + record.getProtocol().name());
        if (record.getAppName() != null && !record.getAppName().isEmpty()) {
            protoInfo.append("\nApp: ").append(record.getAppName());
        }
        if (record.getPackageName() != null && !record.getPackageName().isEmpty()) {
            protoInfo.append(" (").append(record.getPackageName()).append(")");
        }
        protoView.setText(protoInfo.toString());

        connView.setText(
                (record.getDirection() == TrafficRecord.Direction.SENT ?
                        record.getSrcIp() + ":" + record.getSrcPort() + " -> " +
                                record.getDstIp() + ":" + record.getDstPort() :
                        record.getSrcIp() + ":" + record.getSrcPort() + " <- " +
                                record.getDstIp() + ":" + record.getDstPort()));
        sizeView.setText("Kich thuoc payload: " + record.getPayloadSize() + " bytes (" +
                NetworkMonitor.formatBytes(record.getPayloadSize()) + ")");
        timeView.setText("Thoi gian: " + new java.text.SimpleDateFormat(
                "HH:mm:ss.SSS", java.util.Locale.getDefault()).format(new java.util.Date(record.getTimestamp())));

        if (record.isHttp()) {
            httpView.setVisibility(View.VISIBLE);
            StringBuilder httpInfo = new StringBuilder();
            if (record.getHttpMethod() != null) {
                httpInfo.append("Method: ").append(record.getHttpMethod()).append("\n");
            }
            if (record.getHttpUrl() != null) {
                httpInfo.append("URL: ").append(record.getHttpUrl()).append("\n");
            }
            if (record.getStatusCode() > 0) {
                httpInfo.append("Status: ").append(record.getStatusCode()).append("\n");
            }
            if (record.getContentType() != null) {
                httpInfo.append("Content-Type: ").append(record.getContentType()).append("\n");
            }
            httpView.setText(httpInfo.toString());
        } else {
            httpView.setVisibility(View.GONE);
        }

        if (record.getFullContent() != null && !record.getFullContent().isEmpty()) {
            contentView.setVisibility(View.VISIBLE);
            contentView.setText(record.getFullContent());
        } else if (record.getContentPreview() != null) {
            contentView.setVisibility(View.VISIBLE);
            contentView.setText(record.getContentPreview());
        } else {
            contentView.setVisibility(View.GONE);
        }

        new AlertDialog.Builder(this)
                .setTitle("Chi tiet traffic")
                .setView(detailView)
                .setPositiveButton("OK", null)
                .setNeutralButton("Copy", (d, which) -> {
                    String text = protoView.getText() + "\n" + connView.getText() + "\n" + contentView.getText();
                    android.content.ClipboardManager clipboard =
                            (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    if (clipboard != null) {
                        clipboard.setPrimaryClip(
                                android.content.ClipData.newPlainText("traffic", text));
                        Toast.makeText(this, "Da copy!", Toast.LENGTH_SHORT).show();
                    }
                })
                .show();
    }

    @Override
    protected void onResume() {
        super.onResume();
        checkVpnStatus();
        if (isVpnActive) startAutoRefresh();
    }

    @Override
    protected void onPause() {
        super.onPause();
        stopAutoRefresh();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopAutoRefresh();
    }
}
