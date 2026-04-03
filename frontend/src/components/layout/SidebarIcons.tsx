/**
 * Custom animated SVG icons for the sidebar.
 * Each icon is network/security themed with unique hover animations.
 * Wrap the parent in `group` class to trigger hover animations.
 */

const S = 18; // default size
const V = "0 0 24 24"; // viewBox

interface IconProps { size?: number; className?: string }

/** Dashboard — 4 grid panels that scale up sequentially */
export function IconDashboard({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      <rect x="3" y="3" width="8" height="8" rx="1.5" className="transition-all duration-200 group-hover:scale-105 origin-[7px_7px]" />
      <rect x="13" y="3" width="8" height="5" rx="1.5" className="transition-all duration-200 delay-75 group-hover:scale-105 origin-[17px_5.5px]" />
      <rect x="13" y="10" width="8" height="11" rx="1.5" className="transition-all duration-200 delay-100 group-hover:scale-105 origin-[17px_15.5px]" />
      <rect x="3" y="13" width="8" height="8" rx="1.5" className="transition-all duration-200 delay-150 group-hover:scale-105 origin-[7px_17px]" />
    </svg>
  );
}

/** Detections — shield with alert pulse */
export function IconNetworkThreats({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" className="transition-all duration-300 group-hover:stroke-[2]" />
      <line x1="12" y1="9" x2="12" y2="13" strokeLinecap="round" className="transition-opacity duration-200 group-hover:opacity-100" opacity="0.8" />
      <circle cx="12" cy="16" r="0.5" fill="currentColor" className="group-hover:animate-[pulse_0.8s_ease-in-out_infinite]" />
      {/* Pulse ring on hover */}
      <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth="0.5" opacity="0" className="group-hover:animate-[ping_1s_ease-out_1]" />
    </svg>
  );
}

/** Devices — laptop with signal waves radiating */
export function IconDevices({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      {/* Laptop body */}
      <rect x="4" y="5" width="16" height="11" rx="1.5" />
      <path d="M2 19h20" strokeLinecap="round" />
      {/* Signal waves */}
      <path d="M17 3c1.5 1 2.5 2.5 2.5 4.5" strokeLinecap="round" opacity="0" className="group-hover:opacity-60 transition-opacity duration-200 delay-100" />
      <path d="M19 1.5c2 1.5 3.5 3.5 3.5 6" strokeLinecap="round" opacity="0" className="group-hover:opacity-40 transition-opacity duration-200 delay-200" />
    </svg>
  );
}

/** Attack Paths — nodes connected by path that lights up */
export function IconAttackPaths({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      {/* Path lines */}
      <path d="M4 6h4l4 6-4 6H4" strokeLinejoin="round" className="transition-all duration-300 group-hover:stroke-[2]" />
      <path d="M12 12h8" strokeLinecap="round" />
      {/* Nodes */}
      <circle cx="4" cy="6" r="2" fill="currentColor" opacity="0.6" className="group-hover:opacity-1 transition-opacity duration-150" />
      <circle cx="12" cy="12" r="2" fill="currentColor" opacity="0.6" className="group-hover:opacity-1 transition-opacity duration-150 delay-100" />
      <circle cx="20" cy="12" r="2" fill="currentColor" opacity="0.6" className="group-hover:opacity-1 transition-opacity duration-150 delay-200" />
      <circle cx="4" cy="18" r="2" fill="currentColor" opacity="0.6" className="group-hover:opacity-1 transition-opacity duration-150 delay-75" />
    </svg>
  );
}

/** Console — terminal prompt with blinking cursor */
export function IconConsole({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      {/* Terminal frame */}
      <rect x="2" y="4" width="20" height="16" rx="2" />
      {/* Prompt arrow */}
      <path d="M6 10l3 2-3 2" strokeLinecap="round" strokeLinejoin="round" className="transition-transform duration-200 group-hover:translate-x-0.5" />
      {/* Cursor line */}
      <line x1="12" y1="14" x2="17" y2="14" strokeLinecap="round" opacity="0.6" className="group-hover:animate-[pulse_0.8s_ease-in-out_infinite]" />
      {/* Title bar dots */}
      <circle cx="5.5" cy="6.5" r="0.7" fill="currentColor" opacity="0.3" />
      <circle cx="8" cy="6.5" r="0.7" fill="currentColor" opacity="0.3" />
      <circle cx="10.5" cy="6.5" r="0.7" fill="currentColor" opacity="0.3" />
    </svg>
  );
}

/** Sources — cloud with streaming data arrows */
export function IconSources({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      {/* Cloud shape */}
      <path d="M6 19a4 4 0 01-.78-7.93A7 7 0 0118.74 10H19a4 4 0 010 8H6z" />
      {/* Download arrows */}
      <line x1="9" y1="13" x2="9" y2="17" strokeLinecap="round" opacity="0" className="group-hover:opacity-70 transition-opacity duration-150" />
      <polyline points="7,15.5 9,17.5 11,15.5" strokeLinecap="round" strokeLinejoin="round" opacity="0" className="group-hover:opacity-70 transition-opacity duration-150 delay-75" />
      <line x1="15" y1="13" x2="15" y2="17" strokeLinecap="round" opacity="0" className="group-hover:opacity-70 transition-opacity duration-150 delay-100" />
      <polyline points="13,15.5 15,17.5 17,15.5" strokeLinecap="round" strokeLinejoin="round" opacity="0" className="group-hover:opacity-70 transition-opacity duration-150 delay-150" />
    </svg>
  );
}

/** Patterns — fingerprint scan lines */
export function IconPatterns({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      {/* Fingerprint arcs */}
      <path d="M12 3a9 9 0 00-9 9" strokeLinecap="round" opacity="0.5" className="group-hover:opacity-80 transition-opacity duration-150" />
      <path d="M12 6a6 6 0 00-6 6" strokeLinecap="round" opacity="0.6" className="group-hover:opacity-90 transition-opacity duration-150 delay-50" />
      <path d="M12 9a3 3 0 00-3 3" strokeLinecap="round" opacity="0.7" className="group-hover:opacity-100 transition-opacity duration-150 delay-100" />
      <path d="M12 3a9 9 0 019 9" strokeLinecap="round" opacity="0.5" className="group-hover:opacity-80 transition-opacity duration-150 delay-150" />
      <path d="M12 6a6 6 0 016 6" strokeLinecap="round" opacity="0.6" className="group-hover:opacity-90 transition-opacity duration-150 delay-200" />
      <path d="M12 9a3 3 0 013 3" strokeLinecap="round" opacity="0.7" className="group-hover:opacity-100 transition-opacity duration-150 delay-250" />
      {/* Center dot */}
      <circle cx="12" cy="12" r="1" fill="currentColor" />
      {/* Scan line */}
      <line x1="3" y1="18" x2="21" y2="18" strokeLinecap="round" opacity="0" className="group-hover:opacity-40 group-hover:animate-[scan_1s_ease-in-out_1]" />
    </svg>
  );
}

/** Interfaces — ethernet plug with active signal */
export function IconInterfaces({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      {/* RJ45 plug shape */}
      <rect x="6" y="8" width="12" height="10" rx="1" />
      <rect x="8" y="5" width="8" height="5" rx="0.5" />
      {/* Contact pins */}
      <line x1="9" y1="8" x2="9" y2="5" />
      <line x1="11" y1="8" x2="11" y2="5" />
      <line x1="13" y1="8" x2="13" y2="5" />
      <line x1="15" y1="8" x2="15" y2="5" />
      {/* Activity indicator */}
      <circle cx="12" cy="21" r="1" fill="currentColor" opacity="0" className="group-hover:opacity-80 group-hover:animate-[pulse_0.6s_ease-in-out_infinite]" />
      <line x1="12" y1="18" x2="12" y2="20" strokeLinecap="round" opacity="0" className="group-hover:opacity-60 transition-opacity duration-200" />
    </svg>
  );
}

/** Settings — two horizontal sliders that shift on hover */
export function IconSettings({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      {/* Slider tracks */}
      <line x1="4" y1="8" x2="20" y2="8" strokeLinecap="round" opacity="0.4" />
      <line x1="4" y1="16" x2="20" y2="16" strokeLinecap="round" opacity="0.4" />
      <line x1="4" y1="12" x2="20" y2="12" strokeLinecap="round" opacity="0.4" />
      {/* Slider knobs — shift on hover */}
      <circle cx="9" cy="8" r="2.5" fill="currentColor" opacity="0.8" className="transition-transform duration-300 group-hover:translate-x-1" />
      <circle cx="15" cy="12" r="2.5" fill="currentColor" opacity="0.8" className="transition-transform duration-300 group-hover:-translate-x-1.5" />
      <circle cx="7" cy="16" r="2.5" fill="currentColor" opacity="0.8" className="transition-transform duration-300 group-hover:translate-x-2" />
    </svg>
  );
}

/** Topology — network graph with connected nodes */
export function IconTopology({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      {/* Central hub */}
      <circle cx="12" cy="10" r="2.5" fill="currentColor" opacity="0.7" className="group-hover:opacity-1 transition-opacity duration-200" />
      {/* Branch nodes */}
      <circle cx="4" cy="18" r="2" fill="currentColor" opacity="0.5" className="group-hover:opacity-80 transition-opacity duration-200 delay-75" />
      <circle cx="20" cy="18" r="2" fill="currentColor" opacity="0.5" className="group-hover:opacity-80 transition-opacity duration-200 delay-150" />
      <circle cx="5" cy="5" r="1.5" fill="currentColor" opacity="0.5" className="group-hover:opacity-80 transition-opacity duration-200 delay-100" />
      <circle cx="19" cy="5" r="1.5" fill="currentColor" opacity="0.5" className="group-hover:opacity-80 transition-opacity duration-200 delay-200" />
      {/* Connections */}
      <line x1="12" y1="12" x2="4" y2="16" strokeLinecap="round" opacity="0.4" className="transition-opacity duration-200 group-hover:opacity-70" />
      <line x1="12" y1="12" x2="20" y2="16" strokeLinecap="round" opacity="0.4" className="transition-opacity duration-200 group-hover:opacity-70" />
      <line x1="10" y1="9" x2="6" y2="6" strokeLinecap="round" opacity="0.4" className="transition-opacity duration-200 group-hover:opacity-70" />
      <line x1="14" y1="9" x2="18" y2="6" strokeLinecap="round" opacity="0.4" className="transition-opacity duration-200 group-hover:opacity-70" />
      {/* Pulse on hover */}
      <circle cx="12" cy="10" r="5" stroke="currentColor" strokeWidth="0.5" opacity="0" className="group-hover:animate-[ping_1.5s_ease-out_1]" />
    </svg>
  );
}

/** Documentation — open book with flipping page */
export function IconDocumentation({ size = S, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox={V} fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      {/* Book spine */}
      <path d="M12 4v16" opacity="0.3" />
      {/* Left page */}
      <path d="M4 5c2-1 4-1 8 0v16c-4-1-6-1-8 0V5z" className="transition-transform duration-300 origin-[12px_12px]" />
      {/* Right page */}
      <path d="M20 5c-2-1-4-1-8 0v16c4-1 6-1 8 0V5z" className="transition-transform duration-300 origin-[12px_12px]" />
      {/* Text lines left */}
      <line x1="7" y1="9" x2="10" y2="9" strokeWidth="1" opacity="0.3" />
      <line x1="7" y1="12" x2="10" y2="12" strokeWidth="1" opacity="0.3" />
      {/* Text lines right */}
      <line x1="14" y1="9" x2="17" y2="9" strokeWidth="1" opacity="0.3" />
      <line x1="14" y1="12" x2="17" y2="12" strokeWidth="1" opacity="0.3" />
      {/* Flip effect */}
      <path d="M12 4c2.5 0.5 4 1 6.5 0" strokeWidth="1" opacity="0" className="group-hover:opacity-50 transition-opacity duration-200" />
    </svg>
  );
}
