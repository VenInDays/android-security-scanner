package com.securityscanner.app;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class AppListAdapter extends RecyclerView.Adapter<AppListAdapter.ViewHolder> {

    private final List<AppInfo> apps = new ArrayList<>();
    private final List<ScanResult> results = new ArrayList<>();
    private final Context context;
    private OnAppClickListener clickListener;
    private String filterText = "";
    private FilterMode filterMode = FilterMode.ALL;

    public enum FilterMode {
        ALL, SAFE, THREATS
    }

    public interface OnAppClickListener {
        void onAppClick(AppInfo appInfo, ScanResult result);
    }

    public AppListAdapter(Context context) {
        this.context = context;
    }

    public void setOnAppClickListener(OnAppClickListener listener) {
        this.clickListener = listener;
    }

    public void setData(List<AppInfo> appList, List<ScanResult> scanResults) {
        apps.clear();
        results.clear();
        if (appList != null) apps.addAll(appList);
        if (scanResults != null) results.addAll(scanResults);
        notifyDataSetChanged();
    }

    public void setFilter(String text, FilterMode mode) {
        this.filterText = text.toLowerCase(Locale.getDefault());
        this.filterMode = mode;
        notifyDataSetChanged();
    }

    @Override
    public int getItemCount() {
        int count = 0;
        for (int i = 0; i < apps.size(); i++) {
            if (matchesFilter(apps.get(i), i < results.size() ? results.get(i) : null)) {
                count++;
            }
        }
        return count;
    }

    private boolean matchesFilter(AppInfo app, ScanResult result) {
        // Text filter
        if (!filterText.isEmpty()
                && !app.getAppName().toLowerCase(Locale.getDefault()).contains(filterText)
                && !app.getPackageName().toLowerCase(Locale.getDefault()).contains(filterText)) {
            return false;
        }

        // Mode filter
        switch (filterMode) {
            case SAFE:
                return result == null || result.getThreatLevel() == ScanResult.ThreatLevel.SAFE;
            case THREATS:
                return result != null && result.getThreatLevel() != ScanResult.ThreatLevel.SAFE;
            default:
                return true;
        }
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(context).inflate(R.layout.list_item_app, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        // Find the actual item at the filtered position
        int actualPosition = -1;
        int filteredIndex = 0;
        for (int i = 0; i < apps.size(); i++) {
            ScanResult result = i < results.size() ? results.get(i) : null;
            if (matchesFilter(apps.get(i), result)) {
                if (filteredIndex == position) {
                    actualPosition = i;
                    break;
                }
                filteredIndex++;
            }
        }

        if (actualPosition < 0) return;

        AppInfo appInfo = apps.get(actualPosition);
        ScanResult scanResult = actualPosition < results.size() ? results.get(actualPosition) : null;

        holder.icon.setImageDrawable(appInfo.getIcon());
        holder.nameText.setText(appInfo.getAppName());
        holder.packageText.setText(appInfo.getPackageName());
        holder.networkText.setText(
                "Gui: " + NetworkMonitor.formatBytes(appInfo.getBytesSent())
                        + " | Nhan: " + NetworkMonitor.formatBytes(appInfo.getBytesReceived())
        );
        holder.lastUsedText.setText("Lan cuoi: " + NetworkMonitor.formatLastUsed(appInfo.getLastUsedTimeMs()));

        if (scanResult != null) {
            holder.threatBadge.setVisibility(View.VISIBLE);
            holder.threatBadge.setText(scanResult.getThreatLevel().getLabel());
            holder.threatBadge.setBackgroundResource(getThreatBg(scanResult.getThreatLevel()));
        } else {
            holder.threatBadge.setVisibility(View.GONE);
        }

        holder.itemView.setOnClickListener(v -> {
            if (clickListener != null) {
                clickListener.onAppClick(appInfo, scanResult);
            }
        });
    }

    private int getThreatBg(ScanResult.ThreatLevel level) {
        switch (level) {
            case SAFE: return R.drawable.badge_safe;
            case LOW: return R.drawable.badge_low;
            case MEDIUM: return R.drawable.badge_medium;
            case HIGH: return R.drawable.badge_high;
            case CRITICAL: return R.drawable.badge_critical;
            default: return R.drawable.badge_safe;
        }
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        ImageView icon;
        TextView nameText;
        TextView packageText;
        TextView networkText;
        TextView lastUsedText;
        TextView threatBadge;

        ViewHolder(View itemView) {
            super(itemView);
            icon = itemView.findViewById(R.id.app_icon);
            nameText = itemView.findViewById(R.id.app_name);
            packageText = itemView.findViewById(R.id.app_package);
            networkText = itemView.findViewById(R.id.app_network);
            lastUsedText = itemView.findViewById(R.id.app_last_used);
            threatBadge = itemView.findViewById(R.id.threat_badge);
        }
    }
}
