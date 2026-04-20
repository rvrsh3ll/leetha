import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { getDeviceIcon } from "./icons";
import { DEVICE_TYPE_COLORS } from "@/lib/constants";
import { Wifi, Cable, HelpCircle, Globe } from "lucide-react";

export interface TopologyNodeData {
  type: string;
  hostname: string | null;
  ip: string | null;
  manufacturer: string | null;
  confidence: number;
  is_gateway: boolean;
  is_online?: boolean;
  is_self?: boolean;
  os_family: string | null;
  connection_type?: string;
  [key: string]: unknown;
}

const CONNECTION_ICON = {
  wireless: { Icon: Wifi, color: "#22d3ee", label: "WiFi" },
  wired: { Icon: Cable, color: "#3b82f6", label: "Wired" },
  unknown: { Icon: HelpCircle, color: "#64748b", label: "" },
} as const;

export const TopologyNode = memo(function TopologyNode({ data, selected }: NodeProps) {
  const d = data as TopologyNodeData;
  const isInternet = d.type === "internet";

  // Internet node — special rendering
  if (isInternet) {
    return (
      <div
        className={`
          relative flex flex-col items-center gap-2 rounded-xl border px-6 py-4 transition-all
          ${selected ? "ring-2 ring-orange-500 border-orange-500" : "border-border/50"}
          bg-card min-w-[140px]
        `}
        style={{ boxShadow: selected ? "0 0 20px rgba(249,115,22,0.3)" : "0 2px 10px rgba(0,0,0,0.3)" }}
      >
        <Handle type="target" position={Position.Top} className="!bg-orange-500 !w-2.5 !h-2.5 !border-0" />
        <div className="flex items-center justify-center text-orange-400">
          <Globe size={48} />
        </div>
        <div className="text-center">
          <div className="font-semibold text-base text-orange-400">Internet</div>
        </div>
        <Handle type="source" position={Position.Bottom} className="!bg-orange-500 !w-2.5 !h-2.5 !border-0" />
      </div>
    );
  }

  const DeviceIcon = getDeviceIcon(d.type);
  const color = DEVICE_TYPE_COLORS[d.type] ?? "#64748b";
  const isInfra = ["router", "switch", "access_point", "firewall", "gateway", "mesh_router"].includes(d.type);
  const connType = d.connection_type ?? "unknown";
  const conn = CONNECTION_ICON[connType as keyof typeof CONNECTION_ICON] ?? CONNECTION_ICON.unknown;

  // Smart label: for infra, show type + manufacturer if no hostname
  const typeLabel = d.type ? d.type.replace(/_/g, " ") : null;
  const label = d.hostname
    || (isInfra && d.manufacturer ? `${d.manufacturer} ${typeLabel ?? ""}`.trim() : null)
    || d.manufacturer
    || d.ip
    || "Unknown";

  const isOnline = d.is_online ?? true;
  const isSelf = d.is_self ?? false;

  return (
    <div
      className={`
        relative flex flex-col items-center gap-2 rounded-xl border px-5 py-4 transition-all cursor-pointer
        ${selected ? "ring-2 ring-blue-500 border-blue-500" : isSelf ? "border-emerald-500/50 ring-1 ring-emerald-500/20" : "border-border/50 hover:border-border"}
        ${isInfra ? "bg-card min-w-[170px]" : "bg-card/80 min-w-[150px]"}
        ${!isOnline ? "opacity-50" : ""}
      `}
      style={{
        boxShadow: selected ? `0 0 20px ${color}40` : isSelf ? "0 0 15px rgba(16,185,129,0.15), 0 2px 10px rgba(0,0,0,0.3)" : "0 2px 10px rgba(0,0,0,0.3)",
      }}
    >
      {/* Online/offline indicator */}
      <div
        className={`absolute top-2 right-2 w-2.5 h-2.5 rounded-full ${isOnline ? "bg-green-500 animate-pulse" : "bg-red-500/60"}`}
        title={isOnline ? "Online" : "Offline"}
      />

      <Handle type="target" position={Position.Top} className="!bg-blue-500 !w-2.5 !h-2.5 !border-0" />

      <div className="flex items-center justify-center" style={{ color }}>
        <DeviceIcon size={isInfra ? 52 : 42} />
      </div>

      <div className="text-center space-y-0.5">
        <div className={`font-semibold leading-tight truncate ${isInfra ? "text-base max-w-[160px]" : "text-sm max-w-[140px]"}`}>
          {label}
        </div>
        {d.all_ips && (d.all_ips as string[]).length > 1 ? (
          <div className="text-xs text-muted-foreground leading-tight font-mono space-y-0">
            {(d.all_ips as string[]).map((ip, i) => (
              <div key={i}>{ip}</div>
            ))}
          </div>
        ) : d.ip ? (
          <div className="text-xs text-muted-foreground leading-tight font-mono">{d.ip}</div>
        ) : null}
        {d.manufacturer && d.hostname && (
          <div className={`text-[11px] text-muted-foreground/60 leading-tight truncate ${isInfra ? "max-w-[150px]" : "max-w-[130px]"}`}>
            {d.manufacturer}
          </div>
        )}
      </div>

      {/* Connection type + gateway + self badges */}
      <div className="flex items-center gap-1.5 flex-wrap justify-center">
        {d.is_self && (
          <div className="text-[10px] uppercase tracking-wider font-bold px-2.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
            Leetha
          </div>
        )}
        {d.is_gateway && (
          <div className="text-[10px] uppercase tracking-wider font-bold px-2.5 py-0.5 rounded bg-blue-500/20 text-blue-400">
            Gateway
          </div>
        )}
        {connType !== "unknown" && (
          <div
            className="flex items-center gap-1 text-[9px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded"
            style={{ background: `${conn.color}15`, color: conn.color }}
          >
            <conn.Icon size={10} />
            {conn.label}
          </div>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-blue-500 !w-2.5 !h-2.5 !border-0" />
    </div>
  );
});
