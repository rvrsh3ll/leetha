// frontend/src/components/shared/StatCard.tsx
import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  label: string;
  value: string | number;
  sub: string;
  icon: LucideIcon;
  accent?: "primary" | "destructive" | "success" | "warning" | "info";
}

const accentClasses: Record<string, string> = {
  primary: "text-primary",
  destructive: "text-destructive",
  success: "text-success",
  warning: "text-warning",
  info: "text-info",
};

export function StatCard({ label, value, sub, icon: Icon, accent = "primary" }: StatCardProps) {
  return (
    <div className="rounded-lg bg-card border border-border px-4 py-3 flex items-center justify-between gap-3">
      <div className="flex items-center gap-3 min-w-0">
        <Icon size={16} className={cn("shrink-0", accentClasses[accent])} />
        <div className="min-w-0">
          <div className="text-xs font-medium text-muted-foreground truncate">{label}</div>
          <div className="text-[10px] text-muted-foreground/60 truncate">{sub}</div>
        </div>
      </div>
      <span className={cn("text-xl font-bold tabular-nums shrink-0", accentClasses[accent])}>
        {value}
      </span>
    </div>
  );
}
