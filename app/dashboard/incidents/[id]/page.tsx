'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api';
import { LoadingSpinner } from '@/components/loading-spinner';
import { StatusBadge } from '@/components/status-badge';
import { ArrowLeft } from 'lucide-react';

export default function IncidentDetailPage() {
  const { id } = useParams();
  const router = useRouter();
  const [incident, setIncident] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (id) {
      api.get<any>(`/api/incidents/${id}`)
        .then(setIncident)
        .catch(() => setIncident(null))
        .finally(() => setLoading(false));
    }
  }, [id]);

  if (loading) return <LoadingSpinner />;

  if (!incident) {
    return (
      <div className="space-y-4">
        <Link href="/dashboard/incidents" className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Incidents
        </Link>
        <div className="p-8 text-center text-muted-foreground border border-dashed border-border rounded-lg">
          Incident not found or could not be loaded.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Link href="/dashboard/incidents" className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
        <ArrowLeft className="w-3.5 h-3.5" /> Back to Incidents
      </Link>

      <div className="flex justify-between items-start">
        <div>
          <span className="font-mono text-xs text-primary font-bold">{incident.incident_id}</span>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">{incident.title}</h1>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 text-xs font-bold rounded uppercase bg-destructive/10 text-destructive">
            {incident.severity}
          </span>
          <StatusBadge status={incident.phase} />
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-5 space-y-3">
        <h2 className="text-sm font-semibold text-foreground">Incident Summary</h2>
        <p className="text-xs text-muted-foreground">{incident.description || 'No detailed description.'}</p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs pt-3 border-t border-border">
          <div>
            <span className="text-muted-foreground block text-[11px]">Affected Pod</span>
            <span className="font-mono font-medium text-foreground">{incident.affected_pod || 'N/A'}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px]">Namespace</span>
            <span className="font-mono font-medium text-foreground">{incident.affected_namespace || 'medical'}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px]">MTTD</span>
            <span className="font-mono font-medium text-foreground">{incident.mttd_ms ? `${incident.mttd_ms.toFixed(0)}ms` : 'N/A'}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px]">MTTR</span>
            <span className="font-mono font-medium text-foreground">{incident.mttr_ms ? `${incident.mttr_ms.toFixed(0)}ms` : 'N/A'}</span>
          </div>
        </div>
      </div>

      {/* Timeline */}
      <div className="bg-card border border-border rounded-lg p-5">
        <h2 className="text-base font-semibold mb-4 text-foreground">Event & Remediation Timeline</h2>
        {incident.timeline && incident.timeline.length > 0 ? (
          <ul className="space-y-4 relative border-l-2 border-primary/40 ml-3 pl-4">
            {incident.timeline.map((entry: any, idx: number) => (
              <li key={idx} className="relative">
                <div className="absolute -left-[23px] top-1 w-3 h-3 rounded-full bg-primary border-2 border-card" />
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-xs text-foreground">{entry.title}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted uppercase tracking-wider text-muted-foreground font-mono">
                    {entry.phase}
                  </span>
                </div>
                {entry.detail && <p className="text-xs text-muted-foreground mt-0.5">{entry.detail}</p>}
                <div className="text-[10px] text-muted-foreground font-mono mt-1 flex gap-3">
                  <span>{new Date(entry.timestamp).toLocaleTimeString()}</span>
                  {entry.duration_ms && <span>Duration: {entry.duration_ms.toFixed(1)}ms</span>}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-muted-foreground">No timeline events recorded.</p>
        )}
      </div>
    </div>
  );
}
