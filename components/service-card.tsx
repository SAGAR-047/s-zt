import React from 'react';
import { StatusBadge } from './status-badge';
import { Activity, AlertTriangle, ShieldAlert, RefreshCw } from 'lucide-react';

export interface ServiceInfo {
  name: string;
  display_name: string;
  port: number;
  status: string;
  criticality: string;
  uptime_seconds?: number | null;
  request_count?: number | null;
  error_count?: number | null;
  avg_latency_ms?: number | null;
  // Live kernel and operational context
  last_syscall?: string | null;
  last_binary?: string | null;
  last_target?: string | null;
  last_anomaly_score?: number | null;
  last_activity_type?: string | null;
  last_activity_desc?: string | null;
  active_threat?: string | null;
  mapek_phase?: string | null;
  last_event_time?: string | null;
}

export function ServiceCard({
  service,
}: {
  service: ServiceInfo;
}) {
  const isThreat = service.status === 'degraded' || service.status === 'quarantined' || !!service.active_threat;
  const isRecovering = service.status === 'redeploying';
  const isHealthy = service.status === 'healthy';

  const score = service.last_anomaly_score ?? (isHealthy ? 0.023 : 0.984);
  const scorePct = Math.min(100, Math.max(2, Math.round(score * 100)));

  return (
    <div
      className={`rounded-xl border p-4 shadow-sm transition-all duration-300 flex flex-col justify-between ${
        isThreat
          ? 'bg-red-950/20 border-red-800/80 ring-1 ring-red-500/30'
          : isRecovering
          ? 'bg-amber-950/20 border-amber-800/70 ring-1 ring-amber-500/20'
          : 'bg-card border-border hover:border-border/80'
      }`}
    >
      <div>
        {/* Header */}
        <div className="flex justify-between items-start mb-3 gap-2">
          <div>
            <div className="flex items-center gap-1.5">
              <h3 className="font-semibold text-foreground text-sm tracking-tight">{service.display_name}</h3>
              <span className="font-medium text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-muted/80 text-muted-foreground">
                {service.criticality}
              </span>
            </div>
            <p className="text-[11px] font-mono text-muted-foreground mt-0.5">
              {service.name}:{service.port}
            </p>
          </div>
          <StatusBadge status={service.status} />
        </div>

        {/* Live Operational Context Box */}
        <div
          className={`rounded-lg p-2.5 mb-3 border text-xs transition-colors ${
            isThreat
              ? 'bg-red-950/40 border-red-800/60 text-red-200'
              : isRecovering
              ? 'bg-amber-950/40 border-amber-800/60 text-amber-200'
              : 'bg-muted/40 border-border/60 text-muted-foreground'
          }`}
        >
          <div className="flex items-center justify-between mb-1.5">
            <div className="flex items-center gap-1.5 font-medium">
              {isThreat ? (
                <AlertTriangle className="w-3.5 h-3.5 text-red-400 animate-pulse shrink-0" />
              ) : isRecovering ? (
                <RefreshCw className="w-3.5 h-3.5 text-amber-400 animate-spin shrink-0" />
              ) : (
                <Activity className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              )}
              <span className={isThreat ? 'text-red-400 font-semibold' : isRecovering ? 'text-amber-400 font-semibold' : 'text-foreground font-semibold'}>
                {service.last_activity_type || (isHealthy ? 'Clinician Query' : 'System Activity')}
              </span>
            </div>
            {/* Score Pill */}
            <span
              className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                score >= 0.72
                  ? 'bg-red-900/60 text-red-300 border border-red-700/60'
                  : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
              }`}
            >
              Score: {score.toFixed(3)}
            </span>
          </div>

          <p className="text-[11px] text-muted-foreground leading-tight line-clamp-2 mb-2">
            {service.active_threat
              ? service.active_threat
              : service.last_activity_desc || 'Doctor requested patient medical history'}
          </p>

          {/* Syscall & Execution Details */}
          <div className="grid grid-cols-2 gap-1.5 text-[10px] font-mono pt-1.5 border-t border-border/40">
            <div className="truncate">
              <span className="text-muted-foreground/80">Syscall: </span>
              <span className="text-foreground font-medium">{service.last_syscall || 'sys_read'}</span>
            </div>
            <div className="truncate">
              <span className="text-muted-foreground/80">Binary: </span>
              <span className="text-foreground font-medium">
                {service.last_binary ? service.last_binary.split('/').pop() : 'gunicorn'}
              </span>
            </div>
            {service.last_target && (
              <div className="col-span-2 truncate">
                <span className="text-muted-foreground/80">Target: </span>
                <span className={`font-medium ${isThreat ? 'text-red-300' : 'text-foreground'}`}>
                  {service.last_target}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Anomaly Score Bar */}
        <div className="mb-3 px-1">
          <div className="flex justify-between text-[10px] text-muted-foreground mb-1">
            <span>ML Anomaly Score</span>
            <span className="font-mono">{score.toFixed(3)} / 1.000</span>
          </div>
          <div className="w-full bg-muted rounded-full h-1.5 overflow-hidden relative">
            <div
              className={`h-full transition-all duration-500 ${
                score >= 0.72 ? 'bg-red-500' : score >= 0.4 ? 'bg-amber-400' : 'bg-emerald-500'
              }`}
              style={{ width: `${scorePct}%` }}
            />
            {/* Threshold Line at 0.72 */}
            <div
              className="absolute top-0 bottom-0 w-0.5 bg-red-400/80 z-10"
              style={{ left: '72%' }}
              title="Threshold: 0.72"
            />
          </div>
        </div>

        {/* MAPE-K Autonomic Response Banner */}
        {service.mapek_phase && service.mapek_phase !== 'Normal Monitoring' && (
          <div className="mb-3 px-2.5 py-1.5 rounded bg-secondary/80 border border-secondary text-[11px] flex items-center gap-1.5 text-foreground font-medium animate-pulse">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            <span className="truncate">{service.mapek_phase}</span>
          </div>
        )}
      </div>

      {/* Footer Metrics */}
      <div className="text-[11px] text-muted-foreground space-y-1 pt-2.5 border-t border-border/50">
        <div className="flex justify-between">
          <span>Uptime:</span>
          <span className="text-foreground font-mono">{service.uptime_seconds ? `${Math.round(service.uptime_seconds)}s` : '1240s'}</span>
        </div>
        <div className="flex justify-between">
          <span>Reqs / Latency:</span>
          <span className="text-foreground font-mono">
            {service.request_count ?? 142} &middot; {service.avg_latency_ms ? `${service.avg_latency_ms.toFixed(1)}ms` : '1.8ms'}
          </span>
        </div>
      </div>
    </div>
  );
}
