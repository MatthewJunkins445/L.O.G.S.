import { useState } from 'react';
import { apiFetch } from '../useBackend';
import { Spinner } from '../components/LoadingBar';
import RiskBadge from '../components/RiskBadge';
import './Scanner.css';

function Scanner({ backendReady, scanResults, setScanResults }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedProfile, setSelectedProfile] = useState('quick');

  const profiles = {
    quick:    { label: 'Quick Scan',    description: 'Top 100 common ports — fast (~5–10 sec)',          duration: '~5-10 seconds'  },
    standard: { label: 'Standard Scan', description: 'Ports 1–10,000 with version detection (~30–60 sec)', duration: '~30-60 seconds' },
    full:     { label: 'Full Scan',     description: 'All 65,535 ports — thorough (~2–5 min)',            duration: '~2-5 minutes'   },
  };

  async function runScan() {
    setLoading(true);
    setError('');
    try {
      const data = await apiFetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile: selectedProfile }),
        timeout: 120_000,
      });
      setScanResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const openPorts    = scanResults?.ports?.filter(p => p.state === 'open') || [];
  const criticalPorts = openPorts.filter(p => p.is_critical);
  const riskyPorts   = openPorts.filter(p => p.is_risky && !p.is_critical);
  const normalPorts  = openPorts.filter(p => !p.is_critical && !p.is_risky);

  return (
    <div className="scanner-page">
      <div className="page-header">
        <div>
          <h1>Vulnerability Scanner</h1>
          <p className="subtitle">Network port scanning and service detection</p>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          <strong>Error:</strong> {error}
          <button className="btn-retry" onClick={runScan} disabled={loading}>Retry</button>
        </div>
      )}

      <div className="section scan-config">
        <div className="section-header"><h2>Scan Configuration</h2></div>
        <div className="profile-selector">
          {Object.entries(profiles).map(([key, profile]) => (
            <div
              key={key}
              className={`profile-card ${selectedProfile === key ? 'selected' : ''}`}
              onClick={() => setSelectedProfile(key)}
            >
              <div className="profile-header">
                <input type="radio" name="profile" checked={selectedProfile === key} onChange={() => setSelectedProfile(key)} />
                <div className="profile-title">{profile.label}</div>
              </div>
              <div className="profile-description">{profile.description}</div>
              <div className="profile-duration">{profile.duration}</div>
            </div>
          ))}
        </div>
        <div className="scan-actions">
          <button
            className="btn-scan-large"
            onClick={runScan}
            disabled={loading || !backendReady}
          >
            {loading && <Spinner size={14} color="#fff" />}
            {!backendReady ? 'Connecting…' : loading ? 'Scanning…' : `Run ${profiles[selectedProfile].label}`}
          </button>
        </div>
      </div>

      {scanResults && (
        <>
          <div className="stats-container">
            <div className="stat-box"><div className="stat-label">Total Open Ports</div><div className="stat-value">{openPorts.length}</div><div className="stat-meta">detected</div></div>
            <div className="stat-box critical-stat"><div className="stat-label">Critical Ports</div><div className="stat-value">{criticalPorts.length}</div><div className="stat-meta">high risk</div></div>
            <div className="stat-box warning-stat"><div className="stat-label">Risky Ports</div><div className="stat-value">{riskyPorts.length}</div><div className="stat-meta">medium risk</div></div>
            <div className="stat-box ok-stat"><div className="stat-label">Normal Ports</div><div className="stat-value">{normalPorts.length}</div><div className="stat-meta">low risk</div></div>
          </div>

          <div className="section scan-info">
            <div className="info-grid">
              <div className="info-item"><div className="info-label">Target</div><div className="info-value">{scanResults.target}</div></div>
              <div className="info-item"><div className="info-label">Scan Profile</div><div className="info-value">{scanResults.profile_label}</div></div>
              <div className="info-item"><div className="info-label">OS Detection</div><div className="info-value">{scanResults.os_guess}</div></div>
              <div className="info-item"><div className="info-label">Scan Arguments</div><div className="info-value code">{scanResults.scan_args}</div></div>
            </div>
          </div>

          {criticalPorts.length > 0 && (
            <div className="section alert-critical">
              <div className="section-header">
                <h2>Critical Ports Detected</h2>
                <span className="count">{criticalPorts.length}</span>
              </div>
              <div className="alert-message">
                Critical ports represent severe security risks and should be closed or heavily restricted.
              </div>
              <ul className="critical-list">
                {criticalPorts.map((port, idx) => (
                  <li key={idx} className="critical-item">
                    <span className="port-num">Port {port.port}</span>
                    <span className="port-service">{port.service}</span>
                    <span className="port-version">{port.version}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="section">
            <div className="section-header">
              <h2>Detected Ports</h2>
              <span className="count">{openPorts.length} open</span>
            </div>
            {openPorts.length > 0 ? (
              <table className="data-table ports-table">
                <thead>
                  <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version / Details</th><th>Risk Level</th></tr>
                </thead>
                <tbody>
                  {openPorts.map((port, idx) => (
                    <tr key={idx} className={port.is_critical ? 'critical-row' : port.is_risky ? 'risky-row' : ''}>
                      <td className="port-number">{port.port}</td>
                      <td>{port.proto}</td>
                      <td className="service-name">{port.service}</td>
                      <td className="version-text">{port.version || '—'}</td>
                      <td><RiskBadge port={port} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="no-ports"><p>No open ports detected. System appears secure.</p></div>
            )}
          </div>
        </>
      )}

      {!scanResults && !loading && (
        <div className="empty-state">
          <h3>No scan results</h3>
          <p>{backendReady ? 'Select a scan profile and click "Run Scan" to begin' : 'Connecting to backend…'}</p>
        </div>
      )}
    </div>
  );
}

export default Scanner;
