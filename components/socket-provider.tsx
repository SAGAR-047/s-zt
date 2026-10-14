'use client';

import React, { createContext, useContext, useEffect, useState } from 'react';
import { io, Socket } from 'socket.io-client';

interface SocketContextType {
  socket: Socket | null;
  connected: boolean;
  mode: string;
}

const SocketContext = createContext<SocketContextType>({
  socket: null,
  connected: false,
  mode: 'dev',
});

export const useSocket = () => useContext(SocketContext);

const SOCKET_URL = process.env.NEXT_PUBLIC_SOCKET_URL || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5050';

export function SocketProvider({ children }: { children: React.ReactNode }) {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const [mode, setMode] = useState('dev');

  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('sentinel_token') : null;

    const s = io(SOCKET_URL, {
      transports: ['websocket', 'polling'],
      autoConnect: true,
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 1000,
    });

    s.on('connect', () => {
      setConnected(true);
      if (token) {
        s.emit('authenticate', { token });
      }
    });

    s.on('disconnect', () => {
      setConnected(false);
    });

    s.on('mode', (data: { mode: string }) => {
      if (data?.mode) {
        setMode(data.mode);
      }
    });

    setSocket(s);

    return () => {
      s.disconnect();
    };
  }, []);

  return (
    <SocketContext.Provider value={{ socket, connected, mode }}>
      {children}
    </SocketContext.Provider>
  );
}
