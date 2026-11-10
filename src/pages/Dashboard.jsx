import { useState } from 'react';
import { apiFetch } from '../useBackend';
import { Spinner } from '../components/LoadingBar';
import RiskBadge from '../components/RiskBadge';
import './Dashboard.css';

function formatScanTime(date) {
  if (!date) return null;
  const now = new Date();
  const isToday = date.toDateString() === now.toDateString();
  const time = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return isToday ? `Today ${time}` : `${date.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${time}`;
}

function Dashboard({
  backendReady,
  onNavigate,
  scanResults,
  firewallResults,
  riskData,
  anomalies,
  setScanResults,
  setFirewallResults,
  setRiskData,
  setAnomalies,
  lastScanTime,
  setLastScanTime,
}) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function runFullScan() {
    setLoading(true);
    setError('');
    try {
      // Scan and firewall are independent — run them in parallel
      const [scanData, fwData] = await Promise.all([
        apiFetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ profile: 'quick' }),
          timeout: 120_000,
        }),
        apiFetch('/api/firewall/analyze', { timeout: 60_000 }),
      ]);
      setScanResults(scanData);
      setFirewallResults(fwData);

      // Risk needs both; anomaly only needs scan — run them in parallel
      const [riskResult, anomalyData] = await Promise.all([
        apiFetch('/api/risk/calculate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scan_results: scanData, firewall_results: fwData }),
        }),
        apiFetch('/api/anomaly/detect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ current_scan: scanData }),
        }),
      ]);
      setRiskData(riskResult);
      setAnomalies(anomalyData.anomalies || []);
      setLastScanTime(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const openPorts = scanResults?.ports?.filter(p => p.state === 'open').length || 0;
  const criticalPorts = scanResults?.ports?.filter(p => p.is_critical && p.state === 'open').length || 0;
  const firewallIssues = firewallResults?.issues?.length || 0;
  const highSeverity = firewallResults?.issues?.filter(i => i.severity === 'High').length || 0;

  return (
    <div className="dashboard">
      <div className="page-header">
        <div>
          <h1>Security Dashboard</h1>
          <p className="subtitle">System security monitoring and analysis</p>
        </div>
        <button
          className="btn-scan"
          onClick={runFullScan}
          disabled={loading || !backendReady}
        >
          {loading && <Spinner size={14} color="#fff" />}
          {!backendReady ? 'Connecting…' : loading ? 'Scanning…' : 'Run Security Scan'}
        </button>
      </div>

      {error && (
        <div className="error-banner">
          <strong>Error:</strong> {error}
          <button className="btn-retry" onClick={runFullScan} disabled={loading}>Retry</button>
        </div>
      )}

      <div className="section risk-section">
        <div className="section-header">
          <h2>Risk Assessment</h2>
          <span className={`badge badge-${riskData.level?.toLowerCase()}`}>
            {riskData.level || 'Unknown'}
          </span>
        </div>
        <div className="risk-meter">
          <div className="risk-value">{riskData.percent}%</div>
          <div className="risk-bar-container">
            <div
              className={`risk-bar level-${riskData.level?.toLowerCase()}`}
              style={{ width: `${riskData.percent}%` }}
            />
          </div>
          <div className="risk-labels">
            <span>Low (0-30%)</span>
            <span>Medium (31-70%)</span>
            <span>High (71-100%)</span>
          </div>
        </div>
      </div>

      <div className="stats-container">
        <div className="stat-box">
          <div className="stat-label">Open Ports</div>
          <div className="stat-value">{openPorts}</div>
          <div className="stat-meta">{criticalPorts} critical</div>
        </div>
        <div className="stat-box clickable" onClick={() => onNavigate('firewall')}>
          <div className="stat-label">Firewall Issues</div>
          <div className="stat-value">{firewallIssues}</div>
          <div className="stat-meta">{highSeverity} high severity</div>
          <div className="stat-link">View Firewall →</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Anomalies</div>
          <div className="stat-value">{anomalies.length}</div>
          <div className="stat-meta">from baseline</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Last Scan</div>
          <div className="stat-value">{lastScanTime ? 'Complete' : 'None'}</div>
          <div className="stat-meta">{formatScanTime(lastScanTime) || scanResults?.profile_label || 'Not run'}</div>
        </div>
      </div>

      {anomalies.length > 0 && (
        <div className="section alert-section">
          <div className="section-header">
            <h2>Detected Anomalies</h2>
            <span className="count">{anomalies.length}</span>
          </div>
          <ul className="alert-list">
            {anomalies.map((anomaly, idx) => (
              <li key={idx} className="alert-item">{anomaly}</li>
            ))}
          </ul>
        </div>
      )}

      {scanResults && scanResults.ports.length > 0 && (
        <div className="section">
          <div className="section-header">
            <h2>Open Ports</h2>
            <span className="count">{openPorts} found</span>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Version</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {scanResults.ports
                .filter(p => p.state === 'open')
                .map((port, idx) => (
                  <tr key={idx} className={port.is_critical ? 'critical-row' : ''}>
                    <td className="port-number">{port.port}</td>
                    <td>{port.proto}</td>
                    <td>{port.service}</td>
                    <td className="version-text">{port.version || '—'}</td>
                    <td><RiskBadge port={port} /></td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}

      {firewallResults && firewallResults.issues.length > 0 && (
        <div className="section">
          <div className="section-header">
            <h2>Firewall Issues</h2>
            <div className="header-actions">
              <span className="count">{firewallIssues} found</span>
              <button className="btn-link" onClick={() => onNavigate('firewall')}>View All →</button>
            </div>
          </div>
          <div className="issues-list">
            {firewallResults.issues.slice(0, 5).map((issue, idx) => (
              <div key={idx} className={`issue-card severity-${issue.severity.toLowerCase()}`}>
                <div className="issue-header">
                  <span className={`severity-badge ${issue.severity.toLowerCase()}`}>{issue.severity}</span>
                  <span className="issue-type">{issue.issue_type}</span>
                </div>
                <div className="issue-rule">{issue.rule_name}</div>
                <div className="issue-fix">{issue.suggested_fix}</div>
              </div>
            ))}
          </div>
          {firewallIssues > 5 && (
            <div className="view-more">
              <button className="btn-link" onClick={() => onNavigate('firewall')}>
                View all {firewallIssues} issues →
              </button>
            </div>
          )}
        </div>
      )}

      {!scanResults && !loading && (
        <div className="empty-state">
          <h3>No scan data available</h3>
          <p>{backendReady ? 'Click "Run Security Scan" to analyze your system' : 'Connecting to backend…'}</p>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
