import './LoadingBar.css';

// Spinning circle — drop inside a button or section
export function Spinner({ size = 16, color = 'currentColor' }) {
  return (
    <svg
      className="spinner-svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth="2.5"
      strokeLinecap="round"
    >
      <path d="M12 2 A10 10 0 0 1 22 12" />
    </svg>
  );
}
