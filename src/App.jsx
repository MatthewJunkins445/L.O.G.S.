import { useState } from 'react';
import { useBackendReady } from './useBackend';
import Dashboard from './pages/Dashboard';
import Firewall from './pages/Firewall';
import Scanner from './pages/Scanner';
import Monitor from './pages/Monitor';
import './App.css';

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard');

  // Single health-check poll shared by all pages
  const { ready: backendReady, connectionError } = useBackendReady();

  // SHARED STATE - accessible by all pages
  const [scanResults, setScanResults] = useState(null);
  const [firewallResults, setFirewallResults] = useState(null);
  const [riskData, setRiskData] = useState({ percent: 0, level: 'Low' });
  const [anomalies, setAnomalies] = useState([]);
  const [lastScanTime, setLastScanTime] = useState(null);

  return (
    <div className="app">
      {/* Navigation bar */}
      <div className="nav-bar">
        <div className="nav-brand">L.O.G.S. Security</div>
        <div className="nav-links">
          <button
            className={currentPage === 'dashboard' ? 'nav-link active' : 'nav-link'}
            onClick={() => setCurrentPage('dashboard')}
          >
            Dashboard
          </button>
          <button
            className={currentPage === 'scanner' ? 'nav-link active' : 'nav-link'}
            onClick={() => setCurrentPage('scanner')}
          >
            Scanner
          </button>
          <button
            className={currentPage === 'firewall' ? 'nav-link active' : 'nav-link'}
            onClick={() => setCurrentPage('firewall')}
          >
            Firewall
          </button>
          <button
            className={currentPage === 'monitor' ? 'nav-link active' : 'nav-link'}
            onClick={() => setCurrentPage('monitor')}
          >
            Monitor
          </button>
        </div>
      </div>

      {connectionError && (
        <div className="connection-error-banner">
          <strong>Connection Error:</strong> {connectionError}
        </div>
      )}

      {/* Page content - pass shared state as props */}
      <div className="page-container">
        {currentPage === 'dashboard' && (
          <Dashboard
            backendReady={backendReady}
            onNavigate={setCurrentPage}
            scanResults={scanResults}
            firewallResults={firewallResults}
            riskData={riskData}
            anomalies={anomalies}
            setScanResults={setScanResults}
            setFirewallResults={setFirewallResults}
            setRiskData={setRiskData}
            setAnomalies={setAnomalies}
            lastScanTime={lastScanTime}
            setLastScanTime={setLastScanTime}
          />
        )}
        {currentPage === 'scanner' && (
          <Scanner
            backendReady={backendReady}
            scanResults={scanResults}
            setScanResults={setScanResults}
          />
        )}
        {currentPage === 'firewall' && (
          <Firewall
            backendReady={backendReady}
            firewallResults={firewallResults}
            setFirewallResults={setFirewallResults}
          />
        )}
        {currentPage === 'monitor' && (
          <Monitor
            backendReady={backendReady}
            setFirewallResults={setFirewallResults}
          />
        )}
      </div>
    </div>
  );
}

export default App;
