package com.securityscanner.app;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Adapter that displays traffic records grouped by app name.
 * Two view types: TYPE_GROUP_HEADER and TYPE_TRAFFIC_ITEM.
 */
public class TrafficListAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    private static final int TYPE_GROUP_HEADER = 0;
    private static final int TYPE_TRAFFIC_ITEM = 1;

    /** Represents a group header or a traffic record in the flat list */
    private static class ListItem {
        static final int KIND_HEADER = 0;
        static final int KIND_RECORD = 1;
        int kind;
        String groupName;       // for header
        String groupPackage;    // for header
        int groupCount;         // for header
        String groupSize;       // for header
        TrafficRecord record;   // for record
    }

    private final List<ListItem> items = new ArrayList<>();
    private OnItemClickListener clickListener;

    public interface OnItemClickListener {
        void onItemClick(TrafficRecord record, int position);
    }

    public void setOnItemClickListener(OnItemClickListener listener) {
        this.clickListener = listener;
    }

    /**
     * Update with grouped data: groups records by appName, then shows newest group first,
     * newest record within each group first.
     */
    public void updateData(List<TrafficRecord> data) {
        items.clear();
        if (data == null || data.isEmpty()) {
            notifyDataSetChanged();
            return;
        }

        // Group by app name (use "Unknown" if null)
        LinkedHashMap<String, List<TrafficRecord>> groups = new LinkedHashMap<>();
        for (TrafficRecord r : data) {
            String key = (r.getAppName() != null && !r.getAppName().isEmpty()) ? r.getAppName() : "Unknown";
            List<TrafficRecord> list = groups.get(key);
            if (list == null) {
                list = new ArrayList<>();
                groups.put(key, list);
            }
            list.add(r);
        }

        // Build flat list with group headers
        for (Map.Entry<String, List<TrafficRecord>> entry : groups.entrySet()) {
            List<TrafficRecord> records = entry.getValue();
            String groupName = entry.getKey();
            String groupPackage = null;
            int groupTotalSize = 0;

            // Find package name and total size
            for (TrafficRecord r : records) {
                if (groupPackage == null && r.getPackageName() != null) {
                    groupPackage = r.getPackageName();
                }
                groupTotalSize += r.getPayloadSize();
            }

            ListItem header = new ListItem();
            header.kind = ListItem.KIND_HEADER;
            header.groupName = groupName;
            header.groupPackage = groupPackage != null ? groupPackage : "";
            header.groupCount = records.size();
            header.groupSize = NetworkMonitor.formatBytes(groupTotalSize);
            items.add(header);

            for (TrafficRecord record : records) {
                ListItem item = new ListItem();
                item.kind = ListItem.KIND_RECORD;
                item.record = record;
                items.add(item);
            }
        }

        notifyDataSetChanged();
    }

    @Override
    public int getItemCount() { return items.size(); }

    @Override
    public int getItemViewType(int position) {
        if (position < items.size()) {
            return items.get(position).kind == ListItem.KIND_HEADER ? TYPE_GROUP_HEADER : TYPE_TRAFFIC_ITEM;
        }
        return TYPE_TRAFFIC_ITEM;
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        if (viewType == TYPE_GROUP_HEADER) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.list_item_traffic_group, parent, false);
            return new GroupHeaderViewHolder(view);
        } else {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.list_item_traffic, parent, false);
            return new TrafficViewHolder(view);
        }
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        if (position >= items.size()) return;
        ListItem item = items.get(position);

        if (item.kind == ListItem.KIND_HEADER) {
            GroupHeaderViewHolder gh = (GroupHeaderViewHolder) holder;
            gh.nameText.setText(item.groupName);
            gh.packageText.setText(item.groupPackage);
            gh.countText.setText(item.groupCount + " req | " + item.groupSize);
        } else {
            TrafficViewHolder tv = (TrafficViewHolder) holder;
            TrafficRecord record = item.record;

            // Direction badge
            tv.directionText.setText(record.getDirection().getLabel());
            tv.directionText.setTextColor(record.getDirection().getColor());

            // Protocol
            tv.protocolText.setText(record.getProtocol().name());

            // Connection info
            if (record.getDirection() == TrafficRecord.Direction.SENT) {
                tv.connText.setText(record.getDstIp() + ":" + record.getDstPort());
            } else {
                tv.connText.setText(record.getSrcIp() + ":" + record.getSrcPort());
            }

            // Size
            tv.sizeText.setText(NetworkMonitor.formatBytes(record.getPayloadSize()));

            // Time
            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
            tv.timeText.setText(sdf.format(new Date(record.getTimestamp())));

            // Content preview - compact, focused on URL and method
            if (record.isHttp() && record.getHttpMethod() != null) {
                String url = record.getHttpUrl() != null ? record.getHttpUrl() : "";
                // Truncate long URLs
                if (url.length() > 50) url = url.substring(0, 47) + "...";
                tv.contentText.setText(record.getHttpMethod() + " " + url);
                tv.contentText.setTextColor(0xFF4CAF50);

                // Show status code or content type inline
                String extra = "";
                if (record.getStatusCode() > 0) extra = " [" + record.getStatusCode() + "]";
                else if (record.getContentType() != null) extra = " (" + record.getContentType() + ")";
                if (!extra.isEmpty() && tv.connText != null) {
                    tv.connText.setText(tv.connText.getText() + extra);
                }
            } else if (record.getStatusCode() > 0) {
                tv.contentText.setText("HTTP " + record.getStatusCode());
                tv.contentText.setTextColor(0xFF2196F3);
            } else if (record.getContentType() != null) {
                tv.contentText.setText("[" + record.getContentType() + "] " +
                        NetworkMonitor.formatBytes(record.getPayloadSize()));
                tv.contentText.setTextColor(0xFFFF9800);
            } else if (record.getContentPreview() != null) {
                String preview = record.getContentPreview();
                if (preview.length() > 50) preview = preview.substring(0, 47) + "...";
                tv.contentText.setText(preview);
                tv.contentText.setTextColor(0xCCCCCC);
            } else {
                tv.contentText.setText(record.getPayloadSize() + " bytes");
                tv.contentText.setTextColor(0x888888);
            }

            // HTTP badge
            if (record.isHttp()) {
                tv.httpBadge.setVisibility(View.VISIBLE);
            } else {
                tv.httpBadge.setVisibility(View.GONE);
            }

            holder.itemView.setOnClickListener(v -> {
                if (clickListener != null) {
                    clickListener.onItemClick(record, holder.getAdapterPosition());
                }
            });
        }
    }

    // ViewHolders
    static class GroupHeaderViewHolder extends RecyclerView.ViewHolder {
        TextView nameText;
        TextView packageText;
        TextView countText;

        GroupHeaderViewHolder(View itemView) {
            super(itemView);
            nameText = itemView.findViewById(R.id.group_name);
            packageText = itemView.findViewById(R.id.group_package);
            countText = itemView.findViewById(R.id.group_count);
        }
    }

    static class TrafficViewHolder extends RecyclerView.ViewHolder {
        TextView directionText;
        TextView protocolText;
        TextView connText;
        TextView sizeText;
        TextView timeText;
        TextView contentText;
        TextView httpBadge;

        TrafficViewHolder(View itemView) {
            super(itemView);
            directionText = itemView.findViewById(R.id.traffic_direction);
            protocolText = itemView.findViewById(R.id.traffic_protocol);
            connText = itemView.findViewById(R.id.traffic_conn);
            sizeText = itemView.findViewById(R.id.traffic_size);
            timeText = itemView.findViewById(R.id.traffic_time);
            contentText = itemView.findViewById(R.id.traffic_content);
            httpBadge = itemView.findViewById(R.id.traffic_http_badge);
        }
    }
}
