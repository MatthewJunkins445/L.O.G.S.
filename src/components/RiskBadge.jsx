export default function RiskBadge({ port }) {
  if (port.is_critical) {
    return <span className="badge badge-critical">Critical</span>;
  }
  if (port.is_risky) {
    return <span className="badge badge-warning">Risky</span>;
  }
  return <span className="badge badge-ok">Normal</span>;
}
