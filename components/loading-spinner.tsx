import React from 'react';

export function LoadingSpinner({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const sizeClasses = {
    sm: 'h-4 w-4 border-2',
    md: 'h-8 w-8 border-2',
    lg: 'h-12 w-12 border-3',
  };

  return (
    <div className="flex justify-center items-center p-8">
      <div
        className={`animate-spin rounded-full border-t-transparent border-primary ${sizeClasses[size]}`}
      />
    </div>
  );
}
