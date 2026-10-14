import React from 'react';

interface MetricCardProps {
  label: string;
  value: string | number | null | undefined;
  icon?: React.ReactNode;
  sublabel?: string;
}

export function MetricCard({ label, value, icon, sublabel }: MetricCardProps) {
  const strVal = value !== null && value !== undefined ? String(value) : 'N/A';
  const isLong = strVal.length > 10;
  const isVeryLong = strVal.length > 15;

  return (
    <div className="bg-card border border-border rounded-lg p-3.5 shadow-sm min-w-0 overflow-hidden flex flex-col justify-between">
      <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground mb-1 truncate">
        {icon && <span className="shrink-0">{icon}</span>}
        <span className="truncate">{label}</span>
      </div>
      <div
        className={`font-bold text-foreground tracking-tight truncate ${
          isVeryLong ? 'text-xs' : isLong ? 'text-sm lg:text-[15px]' : 'text-2xl'
        }`}
        title={strVal}
      >
        {strVal}
      </div>
      {sublabel ? (
        <div className="text-[11px] text-muted-foreground mt-1 truncate" title={sublabel}>
          {sublabel}
        </div>
      ) : (
        <div className="h-2" />
      )}
    </div>
  );
}
