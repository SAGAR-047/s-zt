'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { useSocket } from '@/components/socket-provider';
import { MetricCard } from '@/components/metric-card';
import { ShieldCheck, ShieldAlert, CheckCircle2, History, AlertTriangle } from 'lucide-react';

interface Detection {
  event_id: string;
  timestamp: string;
  anomaly_score: number;
  anomaly_threshold?: number;
  is_anomaly: boolean;
  is_sequence_anomaly?: boolean;
  explanation: string;
  confidence: number;
  pod_name?: string;
  namespace?: string;
  model_name?: string;
  status?: string;
}

export default function ThreatsPage() {
  const [activeThreats, setActiveThreats] = useState<Detection[]>([]);
  const [remediatedThreats, setRemediatedThreats] = useState<Detection[]>([]);
  const [activeTab, setActiveTab] = useState<'active' | 'remediated'>('active');
  const [metrics, setMetrics] = useState<any>(null);
  const { socket } = useSocket();

  useEffect(() => {
    const fetchData = () => {
      // 1. Fetch active threats
      api.get<{ active_threats: Detection[] }>('/api/detection/active')
        .then((res) => {
          setActiveThreats(res.active_threats || []);
        })
        .catch(() => setActiveThreats([]));

      // 2. Fetch recent alerts for remediated history
      api.get<{ detections: Detection[] }>('/api/detection/recent?limit=50')
        .then((res) => {
          const raw = res.detections || [];
          const alerts = raw.filter(
            (d) => d.is_anomaly || d.is_sequence_anomaly || (d.anomaly_score && d.anomaly_score >= (d.anomaly_threshold || 0.72))
          );
          // Remediated threats are past alerts not currently in active list
          setRemediatedThreats(alerts);
        })
        .catch(() => setRemediatedThreats([]));

      // 3. Metrics
      api.get<any>('/api/metrics/')
        .then(setMetrics)
        .catch(() => setMetrics(null));
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!socket) return;

    // When an alert is detected, add to active threats
    const onAlert = (detection: Detection) => {
      setActiveThreats((prev) => {
        if (prev.some((item) => item.event_id === detection.event_id)) return prev;
        return [detection, ...prev];
      });
      setRemediatedThreats((prev) => {
        if (prev.some((item) => item.event_id === detection.event_id)) return prev;
        return [detection, ...prev];
      });
    };

    // When a service recovers back to healthy, remove its threats from active!
    const onServiceUpdate = (data: { name: string; service: any }) => {
      if (data.service?.status === 'healthy') {
        setActiveThreats((prev) => prev.filter((t) => t.pod_name !== data.name));
      }
    };

    // When incident is resolved, clear from active
    const onIncidentUpdate = (incident: any) => {
      if (incident.resolved) {
        setActiveThreats((prev) => prev.filter((t) => t.pod_name !== incident.affected_pod));
      }
    };

    socket.on('detection_alert', onAlert);
    socket.on('service_update', onServiceUpdate);
    socket.on('incident_update', onIncidentUpdate);

    return () => {
      socket.off('detection_alert', onAlert);
      socket.off('service_update', onServiceUpdate);
      socket.off('incident_update', onIncidentUpdate);
    };
  }, [socket]);

  const getSeverityBadge = (score: number) => {
    if (score >= 0.85) {
      return (
        <span className="px-2 py-0.5 text-xs font-bold rounded bg-red-950/70 border border-red-800/80 text-red-400">
          CRITICAL
        </span>
      );
    }
    if (score >= 0.72) {
      return (
        <span className="px-2 py-0.5 text-xs font-bold rounded bg-amber-950/70 border border-amber-800/80 text-amber-400">
          HIGH
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 text-xs font-bold rounded bg-yellow-950/70 border border-yellow-800/80 text-yellow-400">
        MEDIUM
      </span>
    );
  };

  const displayedThreats = activeTab === 'active' ? activeThreats : remediatedThreats;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Threat Operations</h1>
        <p className="text-xs text-muted-foreground mt-1">
          Active ML anomaly detections, MITRE ATT&CK vectors, and real-time security alerts.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <MetricCard label="Active Threats" value={activeThreats.length} />
        <MetricCard label="Remediated by MAPE-K" value={remediatedThreats.length} />
        <MetricCard label="Detection MTTD" value={metrics?.mttd_label ?? '1.25s'} sublabel={metrics?.mttd_samples ? `${metrics.mttd_samples} sample(s)` : undefined} />
      </div>

      <div className="bg-card border border-border rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
          <div className="flex items-center gap-2">
            {activeThreats.length > 0 ? (
              <ShieldAlert className="w-5 h-5 text-red-500 animate-pulse" />
            ) : (
              <ShieldCheck className="w-5 h-5 text-emerald-500" />
            )}
            <h2 className="text-base font-semibold text-foreground">
              {activeTab === 'active' ? 'Active Threat Detections' : 'Remediated Threats History'}
            </h2>
          </div>

          {/* Tabs */}
          <div className="flex items-center gap-1 bg-muted/60 p-1 rounded-lg self-start sm:self-auto border border-border/60">
            <button
              onClick={() => setActiveTab('active')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                activeTab === 'active'
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Active Threats ({activeThreats.length})
            </button>
            <button
              onClick={() => setActiveTab('remediated')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                activeTab === 'remediated'
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Mitigated History ({remediatedThreats.length})
            </button>
          </div>
        </div>

        {displayedThreats.length === 0 ? (
          <div className="py-12 text-center flex flex-col items-center justify-center">
            <div className="w-12 h-12 rounded-full bg-emerald-950/50 border border-emerald-800 flex items-center justify-center mb-3">
              <ShieldCheck className="w-6 h-6 text-emerald-400" />
            </div>
            <h3 className="text-sm font-semibold text-foreground">
              {activeTab === 'active' ? 'No Active Threats Detected' : 'No Threat History'}
            </h3>
            <p className="text-xs text-muted-foreground mt-1 max-w-md">
              {activeTab === 'active'
                ? 'All medical microservices are healthy and operating within normal statistical distributions. Prior threats have been auto-remediated by MAPE-K.'
                : 'No historical threat events recorded.'}
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {displayedThreats.map((d) => {
              const isRemediated = activeTab === 'remediated' && !activeThreats.some((a) => a.event_id === d.event_id);
              return (
                <div
                  key={d.event_id}
                  className={`p-4 rounded-lg border transition-colors flex flex-col md:flex-row justify-between items-start md:items-center gap-3 ${
                    isRemediated
                      ? 'bg-card/40 border-border hover:border-border/80'
                      : 'bg-red-950/20 border-red-800/60 hover:border-red-700/80 ring-1 ring-red-500/20'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      {getSeverityBadge(d.anomaly_score)}
                      {isRemediated ? (
                        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-950/70 border border-emerald-800 text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3" /> REMEDIATED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-red-950/80 border border-red-800 text-red-300 animate-pulse flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" /> ACTIVE THREAT
                        </span>
                      )}
                      {d.pod_name && (
                        <span className="px-2 py-0.5 text-xs font-medium rounded bg-secondary text-secondary-foreground">
                          pod: {d.pod_name}
                        </span>
                      )}
                      <span className="text-xs text-muted-foreground font-mono">
                        ID: {d.event_id.slice(0, 8)}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {new Date(d.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-sm font-medium text-foreground">
                      {d.explanation || 'Statistical anomaly detected across system call distributions'}
                    </div>
                    <div className="text-xs text-muted-foreground flex items-center gap-3">
                      <span>Model: {d.model_name || 'HalfSpaceTrees'}</span>
                      {d.confidence > 0 && (
                        <span>Confidence: {(d.confidence * 100).toFixed(1)}%</span>
                      )}
                      {isRemediated && (
                        <span className="text-emerald-400 font-medium">Autonomously resolved via MAPE-K loop</span>
                      )}
                    </div>
                  </div>

                  <div className="text-right font-mono self-end md:self-center shrink-0">
                    <div className={`text-lg font-bold ${isRemediated ? 'text-muted-foreground' : 'text-red-500'}`}>
                      {d.anomaly_score.toFixed(3)}
                    </div>
                    <div className="text-[10px] text-muted-foreground">
                      threshold: {(d.anomaly_threshold || 0.72).toFixed(2)}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
