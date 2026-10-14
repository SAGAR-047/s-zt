import React from 'react';

export function EmptyState({ message = 'No data available', subtitle }: { message?: string; subtitle?: string }) {
  return (
    <div className="text-center text-muted-foreground py-12 px-4 border border-dashed border-border rounded-lg bg-card/40">
      <p className="font-medium text-foreground">{message}</p>
      {subtitle && <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>}
    </div>
  );
}
