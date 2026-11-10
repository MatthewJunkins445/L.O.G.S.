import { useState, useEffect } from 'react';

const API = 'http://localhost:8080';
const CONNECT_TIMEOUT_MS = 30_000;

// Polls /api/health until the backend responds or 30 s elapses.
// Returns { ready: bool, connectionError: string|null }
export function useBackendReady() {
  const [ready, setReady] = useState(false);
  const [connectionError, setConnectionError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const deadline = Date.now() + CONNECT_TIMEOUT_MS;

    async function poll() {
      while (!cancelled) {
        if (Date.now() >= deadline) {
          setConnectionError(
            'Backend failed to start after 30 s. ' +
            'Make sure the app is running as Administrator and that nmap is installed.'
          );
          return;
        }
        try {
          const res = await fetch(`${API}/api/health`);
          if (res.ok) { setReady(true); return; }
        } catch { /* backend not up yet */ }
        await new Promise(r => setTimeout(r, 1500));
      }
    }
    poll();
    return () => { cancelled = true; };
  }, []);

  return { ready, connectionError };
}

// Thin wrapper around fetch.
// Pass `timeout` (ms) in options to override the default (30 s).
// Use 120 000 for scan calls. Throws on non-ok HTTP or abort.
export async function apiFetch(path, options = {}) {
  const { timeout = 30_000, ...fetchOptions } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  let res;
  try {
    res = await fetch(`${API}${path}`, { ...fetchOptions, signal: controller.signal });
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error(`Request timed out after ${timeout / 1000} s`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }

  const text = await res.text();
  let body = null;
  if (text) {
    try { body = JSON.parse(text); } catch { body = null; }
  }

  if (!res.ok) {
    throw new Error(body?.detail || text || `HTTP ${res.status}`);
  }

  return body;
}
