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
import java.util.List;
import java.util.Locale;

public class TrafficListAdapter extends RecyclerView.Adapter<TrafficListAdapter.ViewHolder> {

    private final List<TrafficRecord> records = new ArrayList<>();
    private OnItemClickListener clickListener;

    public interface OnItemClickListener {
        void onItemClick(TrafficRecord record, int position);
    }

    public void setOnItemClickListener(OnItemClickListener listener) {
        this.clickListener = listener;
    }

    public void updateData(List<TrafficRecord> data) {
        records.clear();
        if (data != null) records.addAll(data);
        notifyDataSetChanged();
    }

    @Override
    public int getItemCount() { return records.size(); }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.list_item_traffic, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        TrafficRecord record = records.get(position);

        // Direction
        holder.directionText.setText(record.getDirection().getLabel());
        holder.directionText.setTextColor(record.getDirection().getColor());

        // Protocol
        holder.protocolText.setText(record.getProtocol().name());

        // Connection info
        if (record.getDirection() == TrafficRecord.Direction.SENT) {
            holder.connText.setText(record.getDstIp() + ":" + record.getDstPort());
        } else {
            holder.connText.setText(record.getSrcIp() + ":" + record.getSrcPort());
        }

        // Size
        holder.sizeText.setText(NetworkMonitor.formatBytes(record.getPayloadSize()));

        // Time
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
        holder.timeText.setText(sdf.format(new Date(record.getTimestamp())));

        // Content preview
        if (record.isHttp() && record.getHttpMethod() != null) {
            holder.contentText.setText(record.getHttpMethod() + " " +
                    (record.getHttpUrl() != null ? record.getHttpUrl() : ""));
            holder.contentText.setTextColor(0xFF4CAF50);
        } else if (record.getStatusCode() > 0) {
            holder.contentText.setText("HTTP " + record.getStatusCode());
            holder.contentText.setTextColor(0xFF2196F3);
        } else if (record.getContentPreview() != null) {
            String preview = record.getContentPreview();
            if (preview.length() > 60) preview = preview.substring(0, 57) + "...";
            holder.contentText.setText(preview);
            holder.contentText.setTextColor(0xCCCCCC);
        } else {
            holder.contentText.setText(record.getPayloadSize() + " bytes");
            holder.contentText.setTextColor(0x888888);
        }

        // HTTP badge
        if (record.isHttp()) {
            holder.httpBadge.setVisibility(View.VISIBLE);
        } else {
            holder.httpBadge.setVisibility(View.GONE);
        }

        holder.itemView.setOnClickListener(v -> {
            if (clickListener != null) {
                clickListener.onItemClick(record, holder.getAdapterPosition());
            }
        });
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView directionText;
        TextView protocolText;
        TextView connText;
        TextView sizeText;
        TextView timeText;
        TextView contentText;
        TextView httpBadge;

        ViewHolder(View itemView) {
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
