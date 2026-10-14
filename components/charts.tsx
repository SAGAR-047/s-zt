'use client';

import React from 'react';

// ── Sparkline Chart ──
// A lightweight SVG line chart for time-series data

interface SparklineProps {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
  fillColor?: string;
  showDots?: boolean;
  threshold?: number;
  thresholdColor?: string;
  label?: string;
}

export function Sparkline({
  data,
  width = 300,
  height = 80,
  color = '#6366f1',
  fillColor,
  showDots = false,
  threshold,
  thresholdColor = '#ef4444',
  label,
}: SparklineProps) {
  if (!data || data.length === 0) {
    return (
      <div style={{ width, height }} className="flex items-center justify-center text-xs text-muted-foreground">
        No data yet
      </div>
    );
  }

  const padding = { top: 8, right: 8, bottom: 8, left: 8 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const maxVal = Math.max(...data, threshold ?? 0) * 1.1 || 1;
  const minVal = Math.min(...data, 0);
  const range = maxVal - minVal || 1;

  const points = data.map((val, i) => ({
    x: padding.left + (i / Math.max(data.length - 1, 1)) * chartW,
    y: padding.top + chartH - ((val - minVal) / range) * chartH,
  }));

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');

  const fillPath = linePath +
    ` L ${points[points.length - 1].x} ${padding.top + chartH}` +
    ` L ${points[0].x} ${padding.top + chartH} Z`;

  const thresholdY = threshold !== undefined
    ? padding.top + chartH - ((threshold - minVal) / range) * chartH
    : null;

  return (
    <svg width={width} height={height} className="overflow-visible">
      {/* Gradient fill */}
      <defs>
        <linearGradient id={`grad-${label}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={fillColor || color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={fillColor || color} stopOpacity="0.02" />
        </linearGradient>
      </defs>

      {/* Fill area */}
      <path d={fillPath} fill={`url(#grad-${label})`} />

      {/* Main line */}
      <path d={linePath} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />

      {/* Threshold line */}
      {thresholdY !== null && (
        <line
          x1={padding.left}
          y1={thresholdY}
          x2={padding.left + chartW}
          y2={thresholdY}
          stroke={thresholdColor}
          strokeWidth="1"
          strokeDasharray="4 3"
          opacity="0.7"
        />
      )}

      {/* Dots */}
      {showDots && points.map((p, i) => (
        <circle
          key={i}
          cx={p.x}
          cy={p.y}
          r="2.5"
          fill={data[i] >= (threshold ?? Infinity) ? thresholdColor : color}
          stroke="var(--card)"
          strokeWidth="1"
        />
      ))}
    </svg>
  );
}


// ── Bar Chart ──

interface BarChartProps {
  data: { label: string; value: number; color?: string }[];
  width?: number;
  height?: number;
  defaultColor?: string;
}

export function BarChart({
  data,
  width = 300,
  height = 120,
  defaultColor = '#6366f1',
}: BarChartProps) {
  if (!data || data.length === 0) {
    return (
      <div style={{ width, height }} className="flex items-center justify-center text-xs text-muted-foreground">
        No data yet
      </div>
    );
  }

  const padding = { top: 8, right: 8, bottom: 24, left: 8 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const maxVal = Math.max(...data.map((d) => d.value)) || 1;
  const barWidth = Math.min(chartW / data.length - 4, 40);
  const gap = (chartW - barWidth * data.length) / (data.length + 1);

  return (
    <svg width={width} height={height}>
      {data.map((d, i) => {
        const barH = (d.value / maxVal) * chartH;
        const x = padding.left + gap + i * (barWidth + gap);
        const y = padding.top + chartH - barH;
        return (
          <g key={i}>
            <rect
              x={x}
              y={y}
              width={barWidth}
              height={barH}
              rx="3"
              fill={d.color || defaultColor}
              opacity="0.85"
            />
            <text
              x={x + barWidth / 2}
              y={padding.top + chartH + 14}
              textAnchor="middle"
              className="fill-muted-foreground"
              fontSize="9"
              fontFamily="var(--font-sans)"
            >
              {d.label}
            </text>
            <text
              x={x + barWidth / 2}
              y={y - 4}
              textAnchor="middle"
              className="fill-foreground"
              fontSize="9"
              fontWeight="600"
              fontFamily="var(--font-sans)"
            >
              {d.value}
            </text>
          </g>
        );
      })}
    </svg>
  );
}


// ── Donut Chart ──

interface DonutChartProps {
  data: { label: string; value: number; color: string }[];
  size?: number;
  strokeWidth?: number;
  centerLabel?: string;
  centerValue?: string | number;
}

export function DonutChart({
  data,
  size = 120,
  strokeWidth = 16,
  centerLabel,
  centerValue,
}: DonutChartProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0) || 1;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const center = size / 2;

  let offset = 0;

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size}>
        {/* Background circle */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="var(--border)"
          strokeWidth={strokeWidth}
          opacity="0.3"
        />

        {data.map((d, i) => {
          const pct = d.value / total;
          const dash = pct * circumference;
          const gap = circumference - dash;
          const rotation = (offset / total) * 360 - 90;
          offset += d.value;

          return (
            <circle
              key={i}
              cx={center}
              cy={center}
              r={radius}
              fill="none"
              stroke={d.color}
              strokeWidth={strokeWidth}
              strokeDasharray={`${dash} ${gap}`}
              strokeLinecap="round"
              transform={`rotate(${rotation} ${center} ${center})`}
              className="transition-all duration-500"
            />
          );
        })}

        {/* Center text */}
        {centerValue !== undefined && (
          <>
            <text x={center} y={center - 4} textAnchor="middle" className="fill-foreground" fontSize="18" fontWeight="700">
              {centerValue}
            </text>
            {centerLabel && (
              <text x={center} y={center + 12} textAnchor="middle" className="fill-muted-foreground" fontSize="9">
                {centerLabel}
              </text>
            )}
          </>
        )}
      </svg>

      {/* Legend */}
      <div className="flex flex-wrap gap-x-3 gap-y-1 justify-center">
        {data.map((d, i) => (
          <div key={i} className="flex items-center gap-1.5 text-[10px]">
            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
            <span className="text-muted-foreground">{d.label}</span>
            <span className="font-semibold text-foreground">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

