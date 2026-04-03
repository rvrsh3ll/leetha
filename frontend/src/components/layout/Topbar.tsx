// frontend/src/components/layout/Topbar.tsx
import { cn } from "@/lib/utils";
import type { WsStatus } from "@/hooks/use-websocket";

interface TopbarProps {
  title: string;
  wsStatus: WsStatus;
}

export function Topbar({ title, wsStatus }: TopbarProps) {
  const statusColor: Record<WsStatus, string> = {
    idle: "bg-muted-foreground/40",
    connecting: "bg-warning",
    connected: "bg-success",
    reconnecting: "bg-destructive",
  };

  return (
    <header className="flex items-center justify-between px-6 h-12 bg-background/50">
      <h1 className="text-sm font-semibold text-foreground/80">{title}</h1>
      <div className="flex items-center gap-2">
        <span className={cn("w-1.5 h-1.5 rounded-full", statusColor[wsStatus])} />
        <span className="text-[10px] text-muted-foreground/50">
          {wsStatus === "connected" ? "Live" : wsStatus}
        </span>
      </div>
    </header>
  );
}
