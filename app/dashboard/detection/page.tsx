'use client';

import { useEffect, useState, useRef } from 'react';
import { api } from '@/lib/api';
import { useSocket } from '@/components/socket-provider';
import { MetricCard } from '@/components/metric-card';
import { LoadingSpinner } from '@/components/loading-spinner';
import { Sparkline, BarChart, DonutChart } from '@/components/charts';

interface DetectionStatus {
  model_name: string;
  events_processed: number;
  alerts_generated: number;
  threshold: number;
  avg_inference_latency_ms: number | null;
  events_per_second: number | null;
  hmm: any;
  feature_names: string[];
}

export default function DetectionPage() {
  const [status, setStatus] = useState<DetectionStatus | null>(null);
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const { socket } = useSocket();

  // Real-time data buffers for charts
  const [scoreHistory, setScoreHistory] = useState<number[]>([]);
  const [latencyHistory, setLatencyHistory] = useState<number[]>([]);
  const [eventCounts, setEventCounts] = useState({ normal: 0, anomaly: 0 });
  const [perPodAlerts, setPerPodAlerts] = useState<Record<string, number>>({});

  // Fetch initial data
  useEffect(() => {
    const fetchStatusAndMetrics = () => {
      Promise.all([
        api.get<DetectionStatus>('/api/detection/status').catch(() => null),
        api.get<any>('/api/metrics/').catch(() => null),
        api.get<any>('/api/detection/recent?limit=30').catch(() => null),
      ]).then(([s, m, d]) => {
        if (s) setStatus(s);
        if (m) {
          setMetrics(m);
          setEventCounts({
            normal: Math.max(0, (m.events_processed || 0) - (m.alerts_total || 0)),
            anomaly: m.alerts_total || 0,
          });
        }
        if (d?.detections && d.detections.length >= 5) {
          const scores = d.detections.map((x: any) => x.anomaly_score ?? 0);
          const lats = d.detections.map((x: any) => x.inference_latency_ms ?? 1.2);
          setScoreHistory((prev) => (prev.length === 0 ? scores : prev));
          setLatencyHistory((prev) => (prev.length === 0 ? lats : prev));
        } else {
          setScoreHistory((prev) => (prev.length === 0 ? Array(25).fill(0.02) : prev));
          setLatencyHistory((prev) => (prev.length === 0 ? Array(25).fill(1.2) : prev));
        }
      }).finally(() => setLoading(false));
    };

    fetchStatusAndMetrics();
    const interval = setInterval(fetchStatusAndMetrics, 2000);
    return () => clearInterval(interval);
  }, []);

  // Real-time WebSocket updates
  useEffect(() => {
    if (!socket) return;

    const onDetection = (data: any) => {
      // Update score history (keep last 30 points)
      setScoreHistory((prev) => [...prev.slice(-29), data.anomaly_score ?? 0]);

      // Update latency history
      if (data.inference_latency_ms) {
        setLatencyHistory((prev) => [...prev.slice(-29), data.inference_latency_ms]);
      }

      // Update event counts
      setEventCounts((prev) => ({
        normal: prev.normal + (data.is_anomaly ? 0 : 1),
        anomaly: prev.anomaly + (data.is_anomaly ? 1 : 0),
      }));

      // Update per-pod alerts
      if (data.is_anomaly && data.pod_name) {
        setPerPodAlerts((prev) => ({
          ...prev,
          [data.pod_name]: (prev[data.pod_name] || 0) + 1,
        }));
      }
    };

    const onResult = (data: any) => {
      setScoreHistory((prev) => [...prev.slice(-29), data.anomaly_score ?? 0]);
      if (data.inference_latency_ms) {
        setLatencyHistory((prev) => [...prev.slice(-29), data.inference_latency_ms]);
      }
      setEventCounts((prev) => ({
        normal: prev.normal + 1,
        anomaly: prev.anomaly,
      }));
    };

    const onMetrics = (data: any) => {
      setMetrics(data);
    };

    socket.on('detection_alert', onDetection);
    socket.on('detection_result', onResult);
    socket.on('metrics_update', onMetrics);

    return () => {
      socket.off('detection_alert', onDetection);
      socket.off('detection_result', onResult);
      socket.off('metrics_update', onMetrics);
    };
  }, [socket]);

  // Periodic status refresh
  useEffect(() => {
    const interval = setInterval(() => {
      api.get<DetectionStatus>('/api/detection/status')
        .then(setStatus)
        .catch(() => {});
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <LoadingSpinner />;

  const totalEvents = eventCounts.normal + eventCounts.anomaly;
  const alertRate = totalEvents > 0 ? ((eventCounts.anomaly / totalEvents) * 100).toFixed(1) : '0.0';

  // Pod alert data for bar chart
  const podBarData = Object.entries(perPodAlerts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, count]) => ({
      label: name,
      value: count,
      color: count > 5 ? '#ef4444' : count > 2 ? '#f59e0b' : '#6366f1',
    }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">AI/ML Detection Pipeline</h1>
        <p className="text-xs text-muted-foreground mt-1">
          River HalfSpaceTrees streaming anomaly detection &amp; HMM sequence analysis
        </p>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
        <MetricCard label="Model" value={status?.model_name ?? 'HalfSpaceTrees'} sublabel="River Online iForest" />
        <MetricCard label="Events Processed" value={status?.events_processed ?? 0} />
        <MetricCard label="Alerts Generated" value={status?.alerts_generated ?? 0} />
        <MetricCard label="Alert Rate" value={`${alertRate}%`} />
        <MetricCard label="Anomaly Threshold" value={status?.threshold ?? 0.72} />
        <MetricCard label="Avg Latency" value={status?.avg_inference_latency_ms ? `${status.avg_inference_latency_ms}ms` : 'N/A'} />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Anomaly Score Timeline */}
        <div className="bg-card border border-border rounded-lg p-5">
          <div className="flex justify-between items-center mb-3">
            <h2 className="text-sm font-semibold text-foreground">Anomaly Score Timeline</h2>
            <span className="text-[10px] text-muted-foreground font-mono">
              Last {scoreHistory.length} events · threshold: {status?.threshold ?? 0.72}
            </span>
          </div>
          <Sparkline
            data={scoreHistory}
            width={520}
            height={100}
            color="#6366f1"
            showDots={false}
            threshold={status?.threshold ?? 0.72}
            thresholdColor="#ef4444"
            label="score"
          />
          <div className="flex justify-between mt-2 text-[10px] text-muted-foreground">
            <span>0.0</span>
            <span className="text-destructive font-medium">— anomaly threshold</span>
            <span>1.0</span>
          </div>
        </div>

        {/* Inference Latency */}
        <div className="bg-card border border-border rounded-lg p-5">
          <div className="flex justify-between items-center mb-3">
            <h2 className="text-sm font-semibold text-foreground">Inference Latency (ms)</h2>
            <span className="text-[10px] text-muted-foreground font-mono">
              Last {latencyHistory.length} events
            </span>
          </div>
          <Sparkline
            data={latencyHistory}
            width={520}
            height={100}
            color="#10b981"
            label="latency"
          />
          <div className="flex justify-between mt-2 text-[10px] text-muted-foreground">
            <span>Faster ↑</span>
            <span>
              {latencyHistory.length > 0
                ? `avg: ${(latencyHistory.reduce((a, b) => a + b, 0) / latencyHistory.length).toFixed(1)}ms`
                : 'Waiting for data...'}
            </span>
          </div>
        </div>
      </div>

      {/* Bottom Charts Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Detection Distribution Donut */}
        <div className="bg-card border border-border rounded-lg p-5 flex flex-col items-center">
          <h2 className="text-sm font-semibold text-foreground mb-4 self-start">Detection Distribution</h2>
          <DonutChart
            data={[
              { label: 'Normal', value: eventCounts.normal, color: '#10b981' },
              { label: 'Anomaly', value: eventCounts.anomaly, color: '#ef4444' },
            ]}
            size={130}
            centerValue={totalEvents}
            centerLabel="total"
          />
        </div>

        {/* Per-Pod Alert Distribution */}
        <div className="bg-card border border-border rounded-lg p-5 md:col-span-2">
          <h2 className="text-sm font-semibold text-foreground mb-3">Alerts by Service</h2>
          {podBarData.length > 0 ? (
            <BarChart data={podBarData} width={480} height={130} />
          ) : (
            <div className="h-[130px] flex items-center justify-center text-xs text-muted-foreground">
              No alerts yet — run an attack scenario to see data
            </div>
          )}
        </div>
      </div>

      {/* MTTD / MTTR Metrics */}
      {metrics && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <MetricCard label="Mean Time to Detect" value={metrics.mttd_label ?? 'N/A'} sublabel={metrics.mttd_samples ? `${metrics.mttd_samples} samples` : undefined} />
          <MetricCard label="Mean Time to Remediate" value={metrics.mttr_label ?? 'N/A'} sublabel={metrics.mttr_samples ? `${metrics.mttr_samples} samples` : undefined} />
          <MetricCard label="Actions Executed" value={metrics.actions_executed ?? 0} />
          <MetricCard label="Incidents Created" value={metrics.incidents_total ?? 0} />
        </div>
      )}
    </div>
  );
}
