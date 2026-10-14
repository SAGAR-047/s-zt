'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await api.post<{
        authenticated: boolean;
        token?: string;
        role?: string;
        username?: string;
        display_name?: string;
        message?: string;
      }>('/api/auth/login', { username, password });

      if (res.authenticated && res.token) {
        localStorage.setItem('sentinel_token', res.token);
        localStorage.setItem('sentinel_user', JSON.stringify({
          username: res.username,
          role: res.role,
          displayName: res.display_name,
        }));
        router.push('/dashboard');
      } else {
        setError(res.message || 'Authentication failed');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to connect to backend service (:5050)');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md bg-card border border-border rounded-xl p-8 shadow-lg space-y-6">
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-xl bg-primary text-primary-foreground font-bold text-lg flex items-center justify-center mx-auto shadow-md">
            SC
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">SentinelCloud-Advanced</h1>
          <p className="text-xs text-muted-foreground">
            eBPF-Driven Autonomous Cyber-Resilience for Medical Microservices
          </p>
        </div>

        {error && (
          <div className="p-3 bg-destructive/10 border border-destructive/30 rounded-lg text-xs text-destructive font-medium">
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-foreground">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="w-full px-3 py-2 border border-input rounded-lg bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
              placeholder="e.g. admin"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-foreground">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full px-3 py-2 border border-input rounded-lg bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 bg-primary text-primary-foreground font-semibold rounded-lg text-sm shadow hover:bg-primary/90 transition-colors disabled:opacity-50"
          >
            {loading ? 'Authenticating...' : 'Sign In to Command Center'}
          </button>
        </form>

        <div className="p-3 bg-muted/40 rounded-lg border border-border text-[11px] text-muted-foreground space-y-1">
          <span className="font-semibold text-foreground block">Default SOC Credentials:</span>
          <div>Username: <code className="text-foreground">admin</code></div>
          <div>Password: <code className="text-foreground">sentinel-admin-2026</code></div>
        </div>
      </div>
    </div>
  );
}
