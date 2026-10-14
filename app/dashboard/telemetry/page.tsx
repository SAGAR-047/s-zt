'use client';

import { useEffect, useState } from 'react';
import { TelemetryTable } from '@/components/telemetry-table';
import { api } from '@/lib/api';

interface DatasetInfo {
  dataset_name?: string;
  version?: string;
  description?: string;
  sources?: Array<{
    name: string;
    institution: string;
    authors: string;
    citation: string;
    url: string;
    role: string;
  }>;
  replay_policy?: {
    mode: string;
    randomness: string;
  };
  total_records?: number;
}

export default function TelemetryPage() {
  const [datasetInfo, setDatasetInfo] = useState<DatasetInfo | null>(null);

  useEffect(() => {
    api.get<DatasetInfo>('/api/telemetry/dataset-info')
      .then((data) => setDatasetInfo(data))
      .catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">Live Telemetry Stream</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Raw eBPF syscall events and clinical microservice telemetry stream.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-xs">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            Real Dataset Replay (0% Synthetic)
          </span>
        </div>
      </div>

      {/* Dataset Provenance & Citation Card */}
      <div className="border border-cyan-500/30 rounded-xl bg-gradient-to-br from-cyan-950/20 via-background to-card p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border gap-2">
          <div>
            <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
              <span className="text-cyan-400">📊</span>
              Internal Traffic Benchmark Dataset Provenance
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Internal microservice traffic is powered by trimmed authentic traces from peer-reviewed public datasets — no randomized generation.
            </p>
          </div>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-muted text-muted-foreground self-start sm:self-center">
            {datasetInfo?.total_records || 80} Curated Records
          </span>
        </div>

        {/* Sources Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Source 1: ADFA-LD */}
          <div className="p-3.5 rounded-lg border border-border bg-card/60 space-y-2">
            <div className="flex items-start justify-between gap-2">
              <div>
                <span className="text-[10px] uppercase font-bold tracking-wider text-cyan-400">System Call Telemetry</span>
                <h3 className="text-sm font-bold text-foreground">ADFA-LD (Linux Dataset)</h3>
              </div>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 font-mono">UNSW Canberra</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Real kernel system call sequences (<code className="text-foreground text-[11px]">sys_read</code>, <code className="text-foreground text-[11px]">sys_openat</code>, <code className="text-foreground text-[11px]">sys_recvfrom</code>, <code className="text-foreground text-[11px]">sys_connect</code>) captured from live Linux server workloads.
            </p>
            <div className="pt-1 text-[11px] text-muted-foreground/90 font-mono space-y-0.5 border-t border-border/50">
              <div><strong className="text-foreground/80">Citation:</strong> Creech, G. & Hu, J. (IEEE WiMob 2013)</div>
              <div><strong className="text-foreground/80">Repository:</strong> UNSW Canberra Cyber Security</div>
            </div>
          </div>

          {/* Source 2: MIMIC-III */}
          <div className="p-3.5 rounded-lg border border-border bg-card/60 space-y-2">
            <div className="flex items-start justify-between gap-2">
              <div>
                <span className="text-[10px] uppercase font-bold tracking-wider text-indigo-400">Clinical Microservices</span>
                <h3 className="text-sm font-bold text-foreground">MIMIC-III Clinical Database</h3>
              </div>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-300 font-mono">MIT PhysioNet</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Real de-identified ICU bedside vital signs timeseries (genuine HR, BP, SpO2), authentic medication formulary orders (NDC numbers), and ICD-10 diagnostic claims.
            </p>
            <div className="pt-1 text-[11px] text-muted-foreground/90 font-mono space-y-0.5 border-t border-border/50">
              <div><strong className="text-foreground/80">Citation:</strong> Johnson, A.E.W. et al. (Nature Scientific Data 2016)</div>
              <div><strong className="text-foreground/80">Repository:</strong> MIT Lab for Computational Physiology / PhysioNet</div>
            </div>
          </div>
        </div>

        {/* Provenance Footer Summary */}
        <div className="flex flex-wrap items-center justify-between pt-2 border-t border-border/40 text-[11px] text-muted-foreground gap-2">
          <div className="flex items-center gap-3">
            <span><strong>Replay Policy:</strong> Deterministic Sequential (0% Random)</span>
            <span>•</span>
            <span><strong>Microservices:</strong> ehr (5002), vitals (5000), drug-dispenser (5001), billing (5003)</span>
          </div>
          <span className="font-mono text-cyan-400/90">datasets/internal_traffic_dataset.json</span>
        </div>
      </div>

      {/* Main Telemetry Table */}
      <TelemetryTable limit={50} />
    </div>
  );
}
