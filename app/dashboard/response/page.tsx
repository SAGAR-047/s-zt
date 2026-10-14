'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { useSocket } from '@/components/socket-provider';
import { EmptyState } from '@/components/empty-state';
import { LoadingSpinner } from '@/components/loading-spinner';

export default function ResponsePage() {
  const [actions, setActions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const { socket } = useSocket();

  useEffect(() => {
    const fetchActions = () => {
      api.get<any>('/api/state')
        .then((data: any) => {
          const incs = data.incidents || {};
          const allActions = Object.values(incs).flatMap((inc: any) => inc.actions || []);
          setActions(allActions.slice(-20).reverse());
        })
        .catch(() => setActions([]))
        .finally(() => setLoading(false));
    };

    fetchActions();
    const interval = setInterval(fetchActions, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!socket) return;
    const handler = (action: any) => {
      setActions((prev) => [action, ...prev].slice(0, 20));
    };
    socket.on('action_update', handler);
    return () => {
      socket.off('action_update', handler);
    };
  }, [socket]);

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Autonomous Response (MAPE-K)</h1>
        <p className="text-xs text-muted-foreground mt-1">
          Monitor → Analyze → Plan → Execute → Knowledge remediation controller
        </p>
      </div>

      {actions.length === 0 ? (
        <EmptyState message="No remediation actions yet" subtitle="Remediation actions taken against threats will appear here" />
      ) : (
        <div className="space-y-3">
          {actions.map((action) => (
            <div key={action.action_id} className="bg-card border border-border rounded-lg p-4 shadow-sm space-y-2">
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-sm font-mono text-primary uppercase">{action.action_type}</span>
                  <span className="text-xs text-muted-foreground">• Pod: {action.pod_name}</span>
                </div>
                <span className={`px-2 py-0.5 text-xs font-semibold rounded uppercase ${
                  action.status === 'completed' ? 'bg-emerald-500/10 text-emerald-600' : 'bg-amber-500/10 text-amber-600'
                }`}>
                  {action.status}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">{action.details}</p>
              <div className="text-[11px] text-muted-foreground font-mono flex gap-4 pt-1 border-t border-border/40">
                <span>Timestamp: {new Date(action.timestamp).toLocaleTimeString()}</span>
                <span>Duration: {action.duration_ms ? `${action.duration_ms.toFixed(0)}ms` : 'N/A'}</span>
                <span>Critical Service: {action.is_critical_service ? 'Yes' : 'No'}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
