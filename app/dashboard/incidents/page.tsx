'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '@/lib/api';
import { useSocket } from '@/components/socket-provider';
import { EmptyState } from '@/components/empty-state';
import { LoadingSpinner } from '@/components/loading-spinner';
import { StatusBadge } from '@/components/status-badge';

interface Incident {
  incident_id: string;
  title: string;
  severity: string;
  phase: string;
  created_at: string;
  affected_pod: string;
}

export default function IncidentsListPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const { socket } = useSocket();

  useEffect(() => {
    const fetchIncidents = () => {
      api.get<any>('/api/incidents/')
        .then((data: any) => {
          if (data.incidents) {
            setIncidents(data.incidents);
          }
        })
        .catch(() => {})
        .finally(() => setLoading(false));
    };

    fetchIncidents();
    const interval = setInterval(fetchIncidents, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!socket) return;
    const handler = (incident: any) => {
      setIncidents((prev) => {
        const exists = prev.find((i) => i.incident_id === incident.incident_id);
        if (exists) {
          return prev.map((i) => (i.incident_id === incident.incident_id ? incident : i));
        }
        return [incident, ...prev];
      });
    };
    socket.on('incident_update', handler);
    return () => {
      socket.off('incident_update', handler);
    };
  }, [socket]);

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Security Incidents</h1>
        <p className="text-xs text-muted-foreground mt-1">Full lifecycle management: Detection → Diagnosis → Mitigation → Recovery</p>
      </div>

      {incidents.length === 0 ? (
        <EmptyState message="No incidents recorded" subtitle="Incidents automatically open upon high-confidence ML anomaly alerts" />
      ) : (
        <div className="space-y-2.5">
          {incidents.map((inc) => (
            <Link key={inc.incident_id} href={`/dashboard/incidents/${inc.incident_id}`} className="block">
              <div className="bg-card border border-border rounded-lg p-4 hover:border-border/90 hover:bg-muted/30 transition shadow-xs flex justify-between items-center">
                <div className="space-y-1">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono font-bold text-xs text-primary">{inc.incident_id}</span>
                    <span className="font-medium text-sm text-foreground">{inc.title}</span>
                  </div>
                  <div className="text-xs text-muted-foreground flex gap-3">
                    <span>Pod: {inc.affected_pod || 'unknown'}</span>
                    <span>•</span>
                    <span>Created: {new Date(inc.created_at).toLocaleString()}</span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-0.5 text-xs font-bold rounded uppercase ${
                    inc.severity === 'HIGH' || inc.severity === 'CRITICAL' ? 'bg-destructive/10 text-destructive' : 'bg-amber-500/10 text-amber-600'
                  }`}>
                    {inc.severity}
                  </span>
                  <StatusBadge status={inc.phase} />
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
