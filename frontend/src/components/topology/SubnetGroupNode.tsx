import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";

export interface SubnetGroupData {
  label: string;
  subnet: string;
  device_count: number;
  infra_count: number;
  client_count: number;
  [key: string]: unknown;
}

export const SubnetGroupNode = memo(function SubnetGroupNode({ data, selected }: NodeProps) {
  const d = data as SubnetGroupData;

  return (
    <div
      className={`
        flex flex-col items-center gap-1 rounded-xl border-2 border-dashed px-6 py-3 transition-all cursor-default
        ${selected ? "border-blue-500 bg-blue-500/10" : "border-blue-500/30 bg-blue-500/5"}
      `}
      style={{ minWidth: 180 }}
    >
      <Handle type="target" position={Position.Top} className="!bg-blue-400 !w-3 !h-3 !border-0" />

      <div className="text-center">
        <div className="text-sm font-bold text-blue-400">{d.label}</div>
        <div className="text-[11px] font-mono text-muted-foreground">{d.subnet}</div>
      </div>

      <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground/70">
        {d.infra_count > 0 && (
          <span>{d.infra_count} infra</span>
        )}
        <span>{d.client_count} client{d.client_count !== 1 ? "s" : ""}</span>
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-blue-400 !w-3 !h-3 !border-0" />
    </div>
  );
});
