import React from 'react';

type StatusType = 'healthy' | 'degraded' | 'offline' | 'unknown' | 'quarantined' | 'redeploying' | 'online';

const statusColors: Record<StatusType, string> = {
  healthy: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300 border border-green-300 dark:border-green-800',
  online: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300 border border-green-300 dark:border-green-800',
  degraded: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300 border border-yellow-300 dark:border-yellow-800',
  offline: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300 border border-red-300 dark:border-red-800',
  unknown: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300 border border-gray-300 dark:border-gray-700',
  quarantined: 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300 border border-orange-300 dark:border-orange-800',
  redeploying: 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300 border border-blue-300 dark:border-blue-800',
};

export function StatusBadge({ status }: { status: string }) {
  const normalized = (status || 'unknown').toLowerCase() as StatusType;
  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded-full inline-flex items-center capitalize ${statusColors[normalized] || statusColors.unknown}`}>
      {status || 'unknown'}
    </span>
  );
}
