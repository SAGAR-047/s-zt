'use client';

import { useSocket } from './socket-provider';

export function ModeBanner() {
  const { mode, connected } = useSocket();

  const modeConfig: Record<string, { label: string; desc: string; badge: string; border: string }> = {
    live: {
      label: 'LIVE MODE',
      desc: 'Executing against real Kubernetes cluster, Cilium CNI, and kernel eBPF probes.',
      badge: 'bg-emerald-500 text-white',
      border: 'border-emerald-500/30 bg-emerald-500/5',
    },
    lab: {
      label: 'LAB MODE',
      desc: 'Running in Docker Compose lab environment with local containers.',
      badge: 'bg-blue-600 text-white',
      border: 'border-blue-500/30 bg-blue-500/5',
    },
    dev: {
      label: 'DEV MODE',
      desc: 'Single machine development. Replaying real benchmark datasets (ADFA-LD & MIMIC-III) into streaming ML pipeline. Autonomous response active.',
      badge: 'bg-amber-600 text-white',
      border: 'border-amber-500/30 bg-amber-500/5',
    },
  };

  const current = modeConfig[mode?.toLowerCase()] || modeConfig.dev;

  return (
    <div className={`px-4 py-2 border-b flex items-center justify-between text-xs transition-colors ${current.border}`}>
      <div className="flex items-center gap-2.5">
        <span className={`px-2 py-0.5 rounded font-bold tracking-wider text-[10px] ${current.badge}`}>
          {current.label}
        </span>
        <span className="text-muted-foreground hidden sm:inline">
          {current.desc}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <span className="flex items-center gap-1 text-[11px] font-medium text-muted-foreground">
          <span className={`inline-block w-2 h-2 rounded-full ${connected ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`} />
          {connected ? 'Socket Connected' : 'Socket Reconnecting...'}
        </span>
      </div>
    </div>
  );
}
