'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { useSocket } from './socket-provider';
import { LoadingSpinner } from './loading-spinner';
import { EmptyState } from './empty-state';

export interface TelemetryEvent {
  event_id: string;
  timestamp: string;
  pod_name: string;
  namespace: string;
  syscall_name: string;
  binary: string;
  target: string;
  port: number;
  anomaly_score: number | null;
  is_alert: boolean;
  source?: string;
  data_mode?: string;
  dataset_source?: string;
  record_id?: string;
  benchmark_ref?: string;
}

export function TelemetryTable({ limit = 20 }: { limit?: number }) {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const { socket } = useSocket();

  useEffect(() => {
    const fetchTelemetry = () => {
      api.get<{ events: TelemetryEvent[] }>(`/api/telemetry/recent?limit=${limit}`)
        .then((data) => {
          if (data.events && data.events.length > 0) {
            setEvents(data.events);
          }
        })
        .catch(() => {})
        .finally(() => setLoading(false));
    };

    fetchTelemetry();
    const interval = setInterval(fetchTelemetry, 2000);
    return () => clearInterval(interval);
  }, [limit]);

  useEffect(() => {
    if (!socket) return;
    const handler = (event: TelemetryEvent) => {
      setEvents((prev) => [event, ...prev].slice(0, limit));
    };
    socket.on('telemetry_event', handler);
    return () => {
      socket.off('telemetry_event', handler);
    };
  }, [socket, limit]);

  if (loading) return <LoadingSpinner />;
  if (!events.length) return <EmptyState message="No telemetry events yet" subtitle="Awaiting eBPF kernel telemetry stream" />;

  return (
    <div className="overflow-x-auto border border-border rounded-lg bg-card shadow-sm">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/40 text-left text-muted-foreground text-xs uppercase tracking-wider">
            <th className="p-2.5">Time</th>
            <th className="p-2.5">Source & Provenance</th>
            <th className="p-2.5">Pod</th>
            <th className="p-2.5">Syscall</th>
            <th className="p-2.5">Binary</th>
            <th className="p-2.5">Target</th>
            <th className="p-2.5">Port</th>
            <th className="p-2.5">Score</th>
            <th className="p-2.5 text-center">Alert</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border font-mono text-xs">
          {events.map((e) => (
            <tr key={e.event_id} className={`hover:bg-muted/50 transition-colors ${e.is_alert ? 'bg-destructive/5' : ''}`}>
              <td className="p-2.5 whitespace-nowrap text-muted-foreground">
                {new Date(e.timestamp).toLocaleTimeString()}
              </td>
              <td className="p-2.5 whitespace-nowrap">
                {e.source === 'lab_test' ? (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-500/15 text-amber-500 border border-amber-500/30">
                    API Test (PC2)
                  </span>
                ) : e.source === 'replay' ? (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-500/15 text-purple-400 border border-purple-500/30">
                    Dataset Replay
                  </span>
                ) : e.source === 'tetragon' || e.source === 'ebpf_probe' ? (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                    Kernel eBPF
                  </span>
                ) : (
                  <span
                    className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
                    title={`Real Dataset: ${e.dataset_source || 'ADFA-LD & MIMIC-III'}${e.benchmark_ref ? ` | Ref: ${e.benchmark_ref}` : ''}`}
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                    ADFA / MIMIC
                    {e.record_id && (
                      <span className="text-[9px] font-mono opacity-80 border-l border-cyan-500/30 pl-1">
                        {e.record_id}
                      </span>
                    )}
                  </span>
                )}
              </td>
              <td className="p-2.5 font-medium text-foreground">{e.pod_name}</td>
              <td className="p-2.5 text-primary">{e.syscall_name}</td>
              <td className="p-2.5 truncate max-w-[140px]" title={e.binary}>{e.binary}</td>
              <td className="p-2.5 truncate max-w-[160px]" title={e.target}>{e.target}</td>
              <td className="p-2.5">{e.port || '-'}</td>
              <td className="p-2.5 font-semibold">
                {e.anomaly_score !== null && e.anomaly_score !== undefined
                  ? <span className={e.anomaly_score > 0.72 ? 'text-destructive font-bold' : 'text-foreground'}>
                      {e.anomaly_score.toFixed(3)}
                    </span>
                  : <span className="text-muted-foreground">N/A</span>}
              </td>
              <td className="p-2.5 text-center">
                {e.is_alert ? <span className="text-destructive font-bold" title="High Anomaly Alert">⚠️</span> : <span className="text-muted-foreground/30">-</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
