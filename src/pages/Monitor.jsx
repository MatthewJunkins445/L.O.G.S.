import { useState, useEffect, useRef } from 'react';
import { apiFetch } from '../useBackend';
import { Spinner } from '../components/LoadingBar';
import './Monitor.css';

const CREATED_KEY = 'logs_created_rules';

const SEVERITY_CLASS = {
  Strong: 'severity-strong',
  Moderate: 'severity-moderate',
  Mild: 'severity-mild',
};

// IsolationForest decision_function: anomalies are always < 0.
// Thresholds: Mild > -0.05, Moderate <= -0.05, Strong <= -0.09
const SCORE_LABELS = {
  Strong:   'Highly Abnormal',
  Moderate: 'Moderately Abnormal',
  Mild:     'Mildly Abnormal',
};

const SCORE_DESCS = {
  Strong:   'Traffic is strongly deviating from your learned baseline. This warrants immediate investigation.',
  Moderate: 'Traffic patterns differ noticeably from your baseline. Review the indicators and check for unusual processes.',
  Mild:     'A minor deviation from your normal traffic pattern. Watch for recurrence before taking action.',
};

// Map anomaly score to a 0-100 bar fill (capped at score = -0.15 for 100%)
function scoreIntensity(score) {
  return Math.min(100, (Math.abs(score) / 0.15) * 100);
}

function getRecommendations(alert) {
  const { severity, attack_type, targeted_ports = [] } = alert;

  if (attack_type === 'POSSIBLE SYN FLOOD') {
    return [
      'Open an Admin PowerShell and run: netsh int tcp set global synattackprotect=1',
      'In the Firewall tab, create an Inbound Block rule targeting the affected port(s) to limit connection attempts',
      'Open Task Manager → Performance → Resource Monitor → Network to find processes with abnormally high connection counts',
    ];
  }
  if (attack_type === 'POSSIBLE BRUTE FORCE') {
    return [
      'Open Event Viewer → Windows Logs → Security and filter for Event ID 4625 (failed login attempts) to find the source',
      'In the Firewall tab, add an Inbound Block rule with the attacker\'s IP set as the Remote Address',
      'Run secpol.msc → Account Policies → Account Lockout Policy to enforce login-attempt limits',
      'Disable unused remote services (RDP port 3389, Telnet port 23, FTP port 21) via services.msc if not needed',
    ];
  }
  if (attack_type === 'POSSIBLE PORT SCAN') {
    return [
      'In the Firewall tab, create an Inbound Block rule targeting the scanning source IP as the Remote Address',
      'Run a Network Scan to confirm which ports are currently exposed and close any that are unnecessary',
      'Block inbound ICMP echo requests (ping) in the Firewall tab to reduce the visibility of this machine',
    ];
  }

  if (severity === 'Strong') {
    return [
      'Open Task Manager (Ctrl+Shift+Esc) → Performance → Open Resource Monitor → Network tab to identify high-traffic processes',
      'Run a Network Scan to check whether any new ports have opened since your last scan',
      'Review the Top Indicators below — features marked High impact deviated the most from your baseline',
      'If you identify a suspicious process, use the Firewall tab to block its port',
    ];
  }
  if (severity === 'Moderate') {
    return [
      'Review the Top Indicators below to identify which traffic features spiked above your baseline',
      'Check Task Manager → App History / Details tab for any process with unexpectedly high network usage',
      'If this alert repeats, use the Firewall tab to restrict traffic on the affected port(s)',
    ];
  }
  // Mild
  const portAdvice = targeted_ports.length > 0
    ? `Ports ${targeted_ports.slice(0, 3).map(p => `:${p.port}`).join(', ')} had elevated activity — verify their firewall rules in the Firewall tab`
    : 'Review the Top Indicators to understand which metric briefly spiked';
  return [
    'A single mild alert may be normal variation — monitor for repeated occurrences before taking action',
    portAdvice,
    'If alerts become frequent, run a Network Scan and check the Firewall tab for any missing block rules',
  ];
}

// Poll interval in ms for each status
const POLL_INTERVAL = {
  connecting: 1500,
  collecting_baseline: 3000,
  starting: 2000,
  stopping: 2000,
  running: 10000,
  default: null,
};

function saveCreatedRule(rule) {
  try {
    const existing = JSON.parse(localStorage.getItem(CREATED_KEY) || '[]');
    const withoutDuplicate = existing.filter(item => item.name !== rule.name);
    const next = [{ time: new Date().toLocaleString(), ...rule }, ...withoutDuplicate].slice(0, 50);
    localStorage.setItem(CREATED_KEY, JSON.stringify(next));
    window.dispatchEvent(new CustomEvent('logs-created-rules-updated'));
  } catch {
    // localStorage may be unavailable in restricted browser contexts.
  }
}

export default function Monitor({ backendReady = true, setFirewallResults }) {
  const [state, setState] = useState(null); // null = loading
  const [actionLoading, setActionLoading] = useState(false);
  const [blockingIp, setBlockingIp] = useState(null);
  const [blockedIps, setBlockedIps] = useState(new Set());
  const [blockError, setBlockError] = useState('');
  const pollRef = useRef(null);

  async function fetchStatus() {
    try {
      const data = await apiFetch('/api/monitor/status');
      setState(data);
    } catch {
      // backend not ready yet — keep polling
    }
  }

  // Initial fetch
  useEffect(() => {
    fetchStatus();
  }, []);

  // Set up polling based on current status
  useEffect(() => {
    clearInterval(pollRef.current);
    const interval = state
      ? (POLL_INTERVAL[state.status] ?? POLL_INTERVAL.default)
      : POLL_INTERVAL.connecting;
    if (interval) {
      pollRef.current = setInterval(fetchStatus, interval);
    }
    return () => clearInterval(pollRef.current);
  }, [state?.status]);

  async function post(url) {
    return apiFetch(url, { method: 'POST' });
  }

  async function handleStartBaseline() {
    setActionLoading(true);
    try {
      const data = await post('/api/monitor/baseline/start');
      if (data.success) await fetchStatus();
      else setState(s => ({ ...s, error: data.message }));
    } finally {
      setActionLoading(false);
    }
  }

  async function handleResetBaseline() {
    if (!confirm('This will delete your current baseline and model. You will need to re-run the setup scan. Continue?')) return;
    setActionLoading(true);
    try {
      await post('/api/monitor/baseline/reset');
      await fetchStatus();
    } finally {
      setActionLoading(false);
    }
  }

  async function handleStartMonitor() {
    setActionLoading(true);
    try {
      const data = await post('/api/monitor/start');
      if (data.success) await fetchStatus();
      else setState(s => ({ ...s, error: data.message }));
    } finally {
      setActionLoading(false);
    }
  }

  async function handleStop() {
    setActionLoading(true);
    try {
      await post('/api/monitor/stop');
      await fetchStatus();
    } finally {
      setActionLoading(false);
    }
  }

  async function handleClearAlerts() {
    await post('/api/monitor/alerts/clear');
    setState(s => ({ ...s, alerts: [] }));
  }

  async function handleBlockIp(ip) {
    setBlockingIp(ip);
    setBlockError('');
    const ruleName = `L.O.G.S. Block ${ip}`;
    try {
      const result = await apiFetch('/api/firewall/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: ruleName,
          direction: 'Inbound',
          action: 'Block',
          protocol: 'any',
          port: 'Any',
          source_ip: ip,
          description: 'Auto-blocked by L.O.G.S. anomaly detection',
        }),
      });
      if (!result?.success) {
        throw new Error('The firewall rule was not created. Run L.O.G.S. as Administrator and try again.');
      }
      setBlockedIps(prev => new Set([...prev, ip]));
      saveCreatedRule({
        name: ruleName,
        sourceIp: ip,
        origin: 'Monitor',
        description: 'Auto-blocked by L.O.G.S. anomaly detection',
      });
      if (backendReady && setFirewallResults) {
        const firewallData = await apiFetch('/api/firewall/analyze');
        setFirewallResults(firewallData);
      }
    } catch (err) {
      setBlockError(`Could not block ${ip}: ${err.message}`);
    } finally {
      setBlockingIp(null);
    }
  }

  // ── Loading ──────────────────────────────────────────────────────────────
  if (!state) {
    return (
      <div className="monitor-page">
        <div className="loading-state">Connecting to backend…</div>
      </div>
    );
  }

  const { status, alerts = [], windows_analyzed, baseline_progress, error } = state;
  const progress = baseline_progress ?? { current: 0, total: 10 };
  const pct = progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0;
  const secRemaining = (progress.total - progress.current) * 15;

  // ── Setup required ────────────────────────────────────────────────────────
  if (status === 'needs_baseline') {
    return (
      <div className="monitor-page">
        <div className="setup-card">
          <div className="setup-icon">🛡</div>
          <h2>Setup Required</h2>
          <p className="setup-desc">
            Before monitoring can begin, L.O.G.S. needs to learn what
            <em> normal </em> traffic looks like on <em>your</em> network.
          </p>
          <div className="setup-details">
            <div className="setup-detail-row">
              <span className="detail-icon">⏱</span>
              <span>Takes about <strong>{Math.ceil((progress.total * 15) / 60)} minutes</strong> — leave your computer running normally</span>
            </div>
            <div className="setup-detail-row">
              <span className="detail-icon">📡</span>
              <span>Captures <strong>{progress.total} traffic windows</strong> to build your personal baseline</span>
            </div>
            <div className="setup-detail-row">
              <span className="detail-icon">🔒</span>
              <span>All data stays <strong>local</strong> — nothing is sent to the cloud</span>
            </div>
          </div>
          {error && <div className="error-banner">{error}</div>}
          <button
            className="btn-setup"
            onClick={handleStartBaseline}
            disabled={actionLoading}
          >
            {actionLoading && <Spinner size={15} color="#fff" />}
            {actionLoading ? 'Starting…' : 'Start Setup Scan'}
          </button>
        </div>
      </div>
    );
  }

  // ── Collecting baseline ───────────────────────────────────────────────────
  if (status === 'collecting_baseline') {
    return (
      <div className="monitor-page">
        <div className="setup-card">
          <div className="setup-icon collecting-spin">📡</div>
          <h2>Learning Your Network…</h2>
          <p className="setup-desc">
            Please use your computer normally. L.O.G.S. is recording baseline traffic patterns.
          </p>

          <div className="progress-area">
            <div className="progress-numbers">
              <span>{progress.current} / {progress.total} windows</span>
              <span>{pct}%</span>
            </div>
            <div className="progress-bar-track">
              <div className="progress-bar-fill" style={{ width: `${pct}%` }} />
            </div>
            <div className="progress-eta">
              {progress.current < progress.total
                ? `~${Math.ceil(secRemaining / 60)} min ${secRemaining % 60} sec remaining`
                : 'Training model…'}
            </div>
          </div>

          <div className="collecting-tips">
            <p className="tips-title">While you wait:</p>
            <ul>
              <li>Browse the web, check email, use apps as usual</li>
              <li>Avoid running large downloads or backups during setup</li>
              <li>The more typical the traffic, the better the baseline</li>
            </ul>
          </div>
        </div>
      </div>
    );
  }

  // ── Normal monitor view (stopped / starting / running / stopping / error) ──
  const isRunning  = status === 'running' || status === 'starting';
  const isStopping = status === 'stopping';

  return (
    <div className="monitor-page">
      <div className="page-header">
        <div>
          <h1>Live Traffic Monitor</h1>
          <p className="subtitle">ML-based anomaly detection on live network traffic</p>
        </div>
        <div className="monitor-controls">
          {!isRunning && !isStopping ? (
            <button className="btn-start" onClick={handleStartMonitor} disabled={actionLoading || status === 'error'}>
              {actionLoading && <Spinner size={13} color="#fff" />}
              {actionLoading ? 'Starting…' : '▶ Start Monitor'}
            </button>
          ) : (
            <button className="btn-stop" onClick={handleStop} disabled={actionLoading || isStopping}>
              {isStopping
                ? '■ Stopping…'
                : actionLoading ? 'Stopping…' : '■ Stop Monitor'}
            </button>
          )}
          <button className="btn-reset" onClick={handleResetBaseline} disabled={actionLoading || isRunning || isStopping} title="Re-run setup scan">
            ↺ Reset Baseline
          </button>
        </div>
      </div>

      <div className="monitor-stats">
        <div className="stat-card">
          <div className="stat-label">Status</div>
          <div className={`status-badge status-${status}`}>
            {(isRunning || isStopping) && <span className="pulse-dot" />}
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Windows Analyzed</div>
          <div className="stat-number">{windows_analyzed}</div>
          <div className="stat-meta">× 15 sec each</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Alerts Detected</div>
          <div className={`stat-number ${alerts.length > 0 ? 'alert-count' : ''}`}>{alerts.length}</div>
          <div className="stat-meta">most recent 50</div>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          <strong>Error:</strong> {error}
        </div>
      )}

      {isRunning && (
        <div className="info-banner">
          Capturing 15-second traffic windows and scoring against <em>your</em> baseline. Auto-refreshes every 10 s.
        </div>
      )}
      {isStopping && (
        <div className="info-banner">
          Finishing current capture window before stopping…
        </div>
      )}

      <div className="alerts-section">
        <div className="section-header">
          <h2>Anomaly Alerts</h2>
          {alerts.length > 0 && (
            <button className="btn-clear" onClick={handleClearAlerts}>Clear All</button>
          )}
        </div>

        {alerts.length === 0 ? (
          <div className="empty-state">
            {isRunning ? 'No anomalies detected yet. Monitoring…'
              : isStopping ? 'Stopping…'
              : 'Start the monitor to begin detecting anomalies.'}
          </div>
        ) : (
          <div className="alert-list">
            {alerts.map((alert, idx) => (
              <div key={idx} className={`alert-card ${SEVERITY_CLASS[alert.severity] || ''}`}>
                <div className="alert-header">
                  <span className={`severity-tag ${SEVERITY_CLASS[alert.severity] || ''}`}>
                    {alert.severity}
                  </span>
                  {alert.attack_type && (
                    <span className="attack-type-tag">{alert.attack_type}</span>
                  )}
                  <span className="alert-score">Score: {alert.score}</span>
                  <span className="alert-time">{alert.timestamp}</span>
                </div>

                {/* ── Score interpretation ── */}
                <div className="score-interpretation">
                  <div className="score-bar-row">
                    <span className="score-bar-label">Anomaly intensity</span>
                    <div className="score-bar-track">
                      <div
                        className={`score-bar-fill score-fill-${alert.severity.toLowerCase()}`}
                        style={{ width: `${scoreIntensity(alert.score)}%` }}
                      />
                    </div>
                    <span className="score-bar-value">{SCORE_LABELS[alert.severity] || alert.severity}</span>
                  </div>
                  <p className="score-desc">{SCORE_DESCS[alert.severity]}</p>
                </div>

                {/* ── Scanner source IPs ── */}
                {alert.scanner_ips?.length > 0 && (
                  <div className="scanner-ips">
                    <div className="scanner-ips-label">Scanner Source IPs</div>
                    {blockError && <div className="block-ip-error">{blockError}</div>}
                    <div className="scanner-ip-list">
                      {alert.scanner_ips.map((s, i) => {
                        const isBlocked  = blockedIps.has(s.ip);
                        const isBlocking = blockingIp === s.ip;
                        return (
                          <div key={i} className="scanner-ip-row">
                            <span className="scanner-ip-addr">{s.ip}</span>
                            <span className="scanner-ip-meta">
                              {s.syn_count} SYNs &bull; {s.port_count} port{s.port_count !== 1 ? 's' : ''}
                            </span>
                            <button
                              className={`btn-block-ip${isBlocked ? ' btn-block-ip--blocked' : ''}`}
                              onClick={() => handleBlockIp(s.ip)}
                              disabled={isBlocking || isBlocked}
                            >
                              {isBlocking ? 'Blocking…' : isBlocked ? '✓ Blocked' : 'Block IP'}
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {alert.top_reasons?.length > 0 && (
                  <div className="alert-reasons">
                    <div className="reasons-label">Top Indicators</div>
                    <div className="reasons-grid">
                      {alert.top_reasons.map((r, i) => (
                        <div key={i} className={`reason-chip impact-${r.impact?.toLowerCase()}`}>
                          <span className="reason-name">{r.name}</span>
                          <span className="reason-impact">{r.impact}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {alert.targeted_ports?.length > 0 && (
                  <div className="alert-ports">
                    <div className="ports-label">Targeted Ports</div>
                    <div className="ports-list">
                      {alert.targeted_ports.map((p, i) => (
                        <span key={i} className="port-chip">:{p.port}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* ── Recommended actions ── */}
                <div className="recommendations">
                  <div className="recs-label">Recommended Actions</div>
                  <ul className="recs-list">
                    {getRecommendations(alert).map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
