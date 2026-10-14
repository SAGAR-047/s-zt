'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { SocketProvider } from '@/components/socket-provider';
import { Sidebar } from '@/components/sidebar';
import { ModeBanner } from '@/components/mode-banner';
import { LoadingSpinner } from '@/components/loading-spinner';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [authorized, setAuthorized] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('sentinel_token');
    if (!token) {
      router.push('/login');
    } else {
      setAuthorized(true);
    }
  }, [router]);

  if (!authorized) {
    return (
      <div className="h-screen flex items-center justify-center bg-background">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <SocketProvider>
      <div className="flex h-screen overflow-hidden bg-background text-foreground">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <ModeBanner />
          <main className="flex-1 overflow-y-auto p-6 lg:p-8">
            <div className="max-w-7xl mx-auto">
              {children}
            </div>
          </main>
        </div>
      </div>
    </SocketProvider>
  );
}
