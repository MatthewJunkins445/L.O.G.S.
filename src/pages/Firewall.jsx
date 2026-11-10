import { useState, useEffect, useRef } from 'react';
import { apiFetch } from '../useBackend';
import { Spinner } from '../components/LoadingBar';
import './Firewall.css';

const ISSUES_PER_PAGE = 20;
const RULES_PER_PAGE = 20;
const CREATED_KEY = 'logs_created_rules';

// PowerShell 5.1 serialises Enabled as integer 1 (true) or 2 (false).
// The backend may also normalise it to a real boolean. Handle all cases.
function ruleEnabled(rule) {
  const v = rule.Enabled;
  if (typeof v === 'boolean') return v;
  if (v === 1) return true;
  if (v === 2) return false;
  return String(v).toLowerCase() === 'true';
}

function getStoredCreatedRules() {
  try {
    const raw = JSON.parse(localStorage.getItem(CREATED_KEY) || '[]');
    const seen = new Set();
    return raw.filter(rule => {
      if (!rule?.name || seen.has(rule.name)) return false;
      seen.add(rule.name);
      return true;
    });
  } catch {
    return [];
  }
}
function saveCreatedRule(name, details = {}) {
  const existing = getStoredCreatedRules();
  const withoutDuplicate = existing.filter(rule => rule.name !== name);
  withoutDuplicate.unshift({ name, time: new Date().toLocaleString(), ...details });
  localStorage.setItem(CREATED_KEY, JSON.stringify(withoutDuplicate.slice(0, 50)));
  window.dispatchEvent(new CustomEvent('logs-created-rules-updated'));
}
function clearStoredCreatedRules() {
  localStorage.removeItem(CREATED_KEY);
  window.dispatchEvent(new CustomEvent('logs-created-rules-updated'));
}

function Firewall({ backendReady, firewallResults, setFirewallResults }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [showAddModal, setShowAddModal] = useState(false);
  const [newRule, setNewRule] = useState({
    name: '', port: '', protocol: 'tcp', action: 'Block', direction: 'Inbound', source_ip: '', description: '',
  });
  const [issuePage, setIssuePage] = useState(0);
  const [rulesPage, setRulesPage] = useState(0);
  const [highlightedRule, setHighlightedRule] = useState(null);
  const [changeLog, setChangeLog] = useState([]);
  const [createdRules, setCreatedRules] = useState(getStoredCreatedRules);
  const tableRef = useRef(null);

  useEffect(() => {
    if (backendReady && !firewallResults) loadFirewallData();
  }, [backendReady]);

  useEffect(() => {
    setIssuePage(0);
    setRulesPage(0);
  }, [firewallResults]);

  useEffect(() => {
    setRulesPage(0);
  }, [filter]);

  useEffect(() => {
    function syncCreatedRules() {
      setCreatedRules(getStoredCreatedRules());
    }
    window.addEventListener('storage', syncCreatedRules);
    window.addEventListener('logs-created-rules-updated', syncCreatedRules);
    return () => {
      window.removeEventListener('storage', syncCreatedRules);
      window.removeEventListener('logs-created-rules-updated', syncCreatedRules);
    };
  }, []);

  function logChange(action, ruleName) {
    setChangeLog(prev => [
      { action, ruleName, time: new Date().toLocaleTimeString() },
      ...prev,
    ].slice(0, 30));
  }

  async function loadFirewallData() {
    setLoading(true);
    setError('');
    try {
      const data = await apiFetch('/api/firewall/analyze');
      setFirewallResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleAddRule(e) {
    e.preventDefault();
    setError('');
    try {
      const result = await apiFetch('/api/firewall/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newRule),
      });
      if (result.success) {
        logChange('Created', newRule.name);
        saveCreatedRule(newRule.name, {
          sourceIp: newRule.source_ip,
          origin: 'Firewall',
          description: newRule.description,
        });
        setCreatedRules(getStoredCreatedRules());
        setShowAddModal(false);
        setNewRule({ name: '', port: '', protocol: 'tcp', action: 'Block', direction: 'Inbound', source_ip: '', description: '' });
        loadFirewallData();
      } else {
        setError('Failed to create rule. Ensure the application is running as Administrator.');
      }
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleToggleRule(ruleName, enable) {
    try {
      const action = enable ? 'enable' : 'disable';
      const result = await apiFetch(`/api/firewall/${action}/${encodeURIComponent(ruleName)}`, { method: 'POST' });
      if (result.success) {
        logChange(enable ? 'Enabled' : 'Disabled', ruleName);
        loadFirewallData();
      } else {
        setError(`Failed to ${enable ? 'enable' : 'disable'} "${ruleName}". Ensure the application is running as Administrator.`);
      }
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleRemoveRule(ruleName) {
    if (!confirm(`Are you sure you want to remove the rule "${ruleName}"?`)) return;
    try {
      const result = await apiFetch(`/api/firewall/remove/${encodeURIComponent(ruleName)}`, { method: 'DELETE' });
      if (result.success) {
        logChange('Removed', ruleName);
        setCreatedRules(getStoredCreatedRules());
        loadFirewallData();
      } else {
        setError(`Failed to remove "${ruleName}". Ensure the application is running as Administrator.`);
      }
    } catch (err) {
      setError(err.message);
    }
  }

  function jumpToRule(ruleName) {
    const allRules = (firewallResults?.rules || []);
    const ruleIdx = allRules.findIndex(r => r.DisplayName === ruleName);
    const targetPage = ruleIdx >= 0 ? Math.floor(ruleIdx / RULES_PER_PAGE) : 0;

    setFilter('all');
    setRulesPage(targetPage);
    setHighlightedRule(ruleName);

    setTimeout(() => {
      if (tableRef.current) {
        const rows = tableRef.current.querySelectorAll('tr[data-rulename]');
        for (const row of rows) {
          if (row.dataset.rulename === ruleName) {
            row.scrollIntoView({ behavior: 'smooth', block: 'center' });
            break;
          }
        }
      }
      setTimeout(() => setHighlightedRule(null), 2500);
    }, 150);
  }

  function handleIssueClick(issue) {
    jumpToRule(issue.rule_name);
  }

  const rules = firewallResults?.rules || [];
  const issues = firewallResults?.issues || [];

  const totalIssuePages = Math.ceil(issues.length / ISSUES_PER_PAGE);
  const pagedIssues = issues.slice(issuePage * ISSUES_PER_PAGE, (issuePage + 1) * ISSUES_PER_PAGE);

  const enrichedCreatedRules = createdRules.map(cr => {
    const currentRule = rules.find(r => r.DisplayName === cr.name);
    const exists = !!currentRule;
    const isEnabled = exists && ruleEnabled(currentRule);
    return { ...cr, currentRule, exists, isEnabled };
  });

  const filteredRules = rules.filter(rule => {
    if (filter === 'all') return true;
    if (filter === 'issues') return issues.some(i => i.rule_name === rule.DisplayName);
    if (filter === 'enabled') return ruleEnabled(rule);
    if (filter === 'disabled') return !ruleEnabled(rule);
    return true;
  });

  const totalRulesPages = Math.ceil(filteredRules.length / RULES_PER_PAGE);
  const pagedRules = filteredRules.slice(rulesPage * RULES_PER_PAGE, (rulesPage + 1) * RULES_PER_PAGE);

  const enabledCount  = rules.filter(r => ruleEnabled(r)).length;
  const disabledCount = rules.filter(r => !ruleEnabled(r)).length;

  return (
    <div className="firewall-page">
      <div className="page-header">
        <div>
          <h1>Firewall Management</h1>
          <p className="subtitle">Firewall rules and security analysis</p>
        </div>
        <div className="header-buttons">
          <button className="btn-add" onClick={() => setShowAddModal(true)} disabled={!backendReady}>+ Add Rule</button>
          <button className="btn-scan" onClick={loadFirewallData} disabled={loading || !backendReady}>
            {loading && <Spinner size={13} color="#fff" />}
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>
      </div>

      {!backendReady && !firewallResults && (
        <div className="loading-state">Connecting to backend…</div>
      )}

      {error && (
        <div className="error-banner">
          <strong>Error:</strong> {error}
          <button className="btn-retry" onClick={loadFirewallData} disabled={loading}>Retry</button>
        </div>
      )}

      {/* ── Stats ── */}
      <div className="stats-container">
        <div className="stat-box"><div className="stat-label">Total Rules</div><div className="stat-value">{rules.length}</div><div className="stat-meta">configured</div></div>
        <div className="stat-box"><div className="stat-label">Enabled</div><div className="stat-value">{enabledCount}</div><div className="stat-meta">active rules</div></div>
        <div className="stat-box"><div className="stat-label">Disabled</div><div className="stat-value">{disabledCount}</div><div className="stat-meta">inactive rules</div></div>
        <div className="stat-box"><div className="stat-label">Issues Found</div><div className="stat-value">{issues.length}</div><div className="stat-meta">need attention</div></div>
      </div>

      {/* ── Issues (paginated) ── */}
      {issues.length > 0 && (
        <div className="section alert-section">
          <div className="section-header">
            <h2>Detected Issues</h2>
            <span className="count">{issues.length} total</span>
          </div>
          <div className="issues-grid">
            {pagedIssues.map((issue, idx) => (
              <div
                key={idx}
                className={`issue-card severity-${issue.severity.toLowerCase()} issue-card-clickable`}
                onClick={() => handleIssueClick(issue)}
                title="Click to jump to this rule in the table below"
              >
                <div className="issue-header">
                  <span className={`severity-badge ${issue.severity.toLowerCase()}`}>{issue.severity}</span>
                  <span className="issue-type">{issue.issue_type}</span>
                  <span className="issue-click-hint">↓ Jump to rule</span>
                </div>
                <div className="issue-rule">{issue.rule_name}</div>
                <div className="issue-fix">{issue.suggested_fix}</div>
              </div>
            ))}
          </div>
          {totalIssuePages > 1 && (
            <div className="pagination-bar">
              <button className="pagination-btn" onClick={() => setIssuePage(p => Math.max(0, p - 1))} disabled={issuePage === 0}>← Prev</button>
              <span className="pagination-info">
                Page {issuePage + 1} of {totalIssuePages}
                <span className="pagination-sub"> &mdash; showing {pagedIssues.length} of {issues.length} issues</span>
              </span>
              <button className="pagination-btn" onClick={() => setIssuePage(p => Math.min(totalIssuePages - 1, p + 1))} disabled={issuePage === totalIssuePages - 1}>Next →</button>
            </div>
          )}
        </div>
      )}

      {/* ── Recent Changes ── */}
      {changeLog.length > 0 && (
        <div className="section changes-section">
          <div className="section-header">
            <h2>Recent Changes</h2>
            <div className="section-header-actions">
              <span className="count">{changeLog.length} this session</span>
              <button className="btn-clear-log" onClick={() => setChangeLog([])}>Clear</button>
            </div>
          </div>
          <div className="changes-list">
            {changeLog.map((entry, idx) => {
              const canJump = entry.action !== 'Removed';
              return (
                <div
                  key={idx}
                  className={`change-item${canJump ? ' change-item-clickable' : ''}`}
                  onClick={canJump ? () => jumpToRule(entry.ruleName) : undefined}
                  title={canJump ? 'Click to jump to this rule in the table below' : 'Rule has been removed'}
                >
                  <span className={`change-badge change-${entry.action.toLowerCase()}`}>{entry.action}</span>
                  <span className="change-rule-name">{entry.ruleName}</span>
                  {canJump && <span className="change-click-hint">↓ Jump</span>}
                  <span className="change-time">{entry.time}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Created via L.O.G.S. ── */}
      <div className="section created-section">
        <div className="section-header">
          <h2>Created via L.O.G.S.</h2>
          <div className="section-header-actions">
            {createdRules.length > 0 && <span className="count">{createdRules.length} rules</span>}
            {createdRules.length > 0 && (
              <button className="btn-clear-log" onClick={() => { clearStoredCreatedRules(); setCreatedRules([]); }}>
                Clear History
              </button>
            )}
          </div>
        </div>
        {createdRules.length === 0 ? (
          <div className="section-inline-empty">
            <span>No rules created yet. Click <strong>+ Add Rule</strong> above to create a custom firewall rule.</span>
          </div>
        ) : (
          <div className="created-rules-grid">
            {enrichedCreatedRules.map((cr, idx) => (
              <div key={idx} className={`created-rule-card${!cr.exists ? ' card-removed' : ''}`}>
                <div className="created-rule-top">
                  <span className="created-rule-name">{cr.name}</span>
                  <span className={`rule-status-pill ${cr.exists ? (cr.isEnabled ? 'pill-active' : 'pill-disabled') : 'pill-removed'}`}>
                    {cr.exists ? (cr.isEnabled ? 'Active' : 'Disabled') : 'Removed'}
                  </span>
                </div>
                <div className="created-rule-meta">Added {cr.time}</div>
                {cr.sourceIp && (
                  <div className="created-rule-meta">Remote IP {cr.sourceIp}</div>
                )}
                {cr.exists && (
                  <div className="created-rule-actions">
                    {cr.isEnabled
                      ? <button className="btn-action btn-disable" onClick={() => handleToggleRule(cr.name, false)}>Disable</button>
                      : <button className="btn-action btn-enable"  onClick={() => handleToggleRule(cr.name, true)}>Enable</button>
                    }
                    <button className="btn-action btn-remove" onClick={() => handleRemoveRule(cr.name)}>Remove</button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── All Rules table ── */}
      <div className="section">
        <div className="filter-bar">
          <div className="filter-group">
            {[['all', `All (${rules.length})`], ['issues', `With Issues (${issues.length})`], ['enabled', `Enabled (${enabledCount})`], ['disabled', `Disabled (${disabledCount})`]].map(([key, label]) => (
              <button key={key} className={filter === key ? 'filter-btn active' : 'filter-btn'} onClick={() => setFilter(key)}>{label}</button>
            ))}
          </div>
        </div>

        <table ref={tableRef} className="data-table firewall-table">
          <thead>
            <tr><th>Rule Name</th><th>Direction</th><th>Action</th><th>Profile</th><th>Status</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {pagedRules.map((rule, idx) => {
              const hasIssue = issues.some(i => i.rule_name === rule.DisplayName);
              const isEnabled = ruleEnabled(rule);
              const isHighlighted = highlightedRule === rule.DisplayName;
              return (
                <tr
                  key={idx}
                  data-rulename={rule.DisplayName}
                  className={`${hasIssue ? 'issue-row' : ''} ${isHighlighted ? 'highlighted-row' : ''}`}
                >
                  <td className="rule-name">{rule.DisplayName}{hasIssue && <span className="issue-indicator">!</span>}</td>
                  <td>{rule.Direction || '—'}</td>
                  <td><span className={`action-badge ${String(rule.Action ?? '').toLowerCase()}`}>{rule.Action || '—'}</span></td>
                  <td>{rule.Profile || '—'}</td>
                  <td><span className={isEnabled ? 'status-enabled' : 'status-disabled'}>{isEnabled ? 'Enabled' : 'Disabled'}</span></td>
                  <td className="action-buttons">
                    {isEnabled
                      ? <button className="btn-action btn-disable" onClick={() => handleToggleRule(rule.DisplayName, false)}>Disable</button>
                      : <button className="btn-action btn-enable"  onClick={() => handleToggleRule(rule.DisplayName, true)}>Enable</button>
                    }
                    <button className="btn-action btn-remove" onClick={() => handleRemoveRule(rule.DisplayName)}>Remove</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {filteredRules.length === 0 && !loading && backendReady && (
          <div className="empty-state"><h3>No rules found</h3><p>No firewall rules match the current filter</p></div>
        )}

        {totalRulesPages > 1 && (
          <div className="pagination-bar">
            <button className="pagination-btn" onClick={() => setRulesPage(p => Math.max(0, p - 1))} disabled={rulesPage === 0}>← Prev</button>
            <span className="pagination-info">
              Page {rulesPage + 1} of {totalRulesPages}
              <span className="pagination-sub"> &mdash; showing {pagedRules.length} of {filteredRules.length} rules</span>
            </span>
            <button className="pagination-btn" onClick={() => setRulesPage(p => Math.min(totalRulesPages - 1, p + 1))} disabled={rulesPage === totalRulesPages - 1}>Next →</button>
          </div>
        )}
      </div>

      {/* ── Add Rule Modal ── */}
      {showAddModal && (
        <div className="modal-overlay" onClick={() => setShowAddModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Add Firewall Rule</h2>
              <button className="modal-close" onClick={() => setShowAddModal(false)}>×</button>
            </div>
            <form onSubmit={handleAddRule}>
              <div className="form-grid">
                <div className="form-group">
                  <label>Rule Name *</label>
                  <input type="text" value={newRule.name} onChange={e => setNewRule({...newRule, name: e.target.value})} placeholder="e.g., Block Port 8080" required />
                </div>
                <div className="form-group">
                  <label>Port Number *</label>
                  <input type="text" value={newRule.port} onChange={e => setNewRule({...newRule, port: e.target.value})} placeholder="e.g., 8080 or Any" required />
                </div>
                <div className="form-group">
                  <label>Protocol</label>
                  <select value={newRule.protocol} onChange={e => setNewRule({...newRule, protocol: e.target.value})}>
                    <option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="any">Any</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Action</label>
                  <select value={newRule.action} onChange={e => setNewRule({...newRule, action: e.target.value})}>
                    <option value="Block">Block</option><option value="Allow">Allow</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Direction</label>
                  <select value={newRule.direction} onChange={e => setNewRule({...newRule, direction: e.target.value})}>
                    <option value="Inbound">Inbound</option><option value="Outbound">Outbound</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Source IP (optional)</label>
                  <input type="text" value={newRule.source_ip} onChange={e => setNewRule({...newRule, source_ip: e.target.value})} placeholder="e.g., 192.168.1.100" />
                </div>
                <div className="form-group full-width">
                  <label>Description (optional)</label>
                  <input type="text" value={newRule.description} onChange={e => setNewRule({...newRule, description: e.target.value})} placeholder="Brief description of this rule" />
                </div>
              </div>
              <div className="modal-actions">
                <button type="button" className="btn-cancel" onClick={() => setShowAddModal(false)}>Cancel</button>
                <button type="submit" className="btn-submit">Create Rule</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default Firewall;
