import { useState, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { authHeaders } from "@/lib/api";
import { cn } from "@/lib/utils";
import { BookOpen, Loader2, AlertCircle, ChevronDown, ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";

const WIKI_PAGES = [
  { slug: "home", title: "Overview" },
  { slug: "getting-started", title: "Getting Started" },
  { slug: "how-it-works", title: "How It Works" },
  { slug: "fingerprint-sources", title: "Fingerprint Sources" },
  { slug: "passive-discovery", title: "Passive Discovery" },
  { slug: "active-probing", title: "Active Probing" },
  { slug: "interface-types", title: "Interface Types & VPN" },
  { slug: "attack-surface", title: "Attack Surface Analysis" },
  { slug: "spoofing-detection", title: "Spoofing Detection" },
  { slug: "web-dashboard", title: "Web Dashboard" },
  { slug: "cli-reference", title: "CLI Reference" },
];

export default function Info() {
  const { slug = "home" } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  const currentPage = WIKI_PAGES.find((p) => p.slug === slug);
  const currentIndex = WIKI_PAGES.findIndex((p) => p.slug === slug);
  const prevPage = currentIndex > 0 ? WIKI_PAGES[currentIndex - 1] : null;
  const nextPage = currentIndex < WIKI_PAGES.length - 1 ? WIKI_PAGES[currentIndex + 1] : null;

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as HTMLElement)) {
        setMenuOpen(false);
      }
    }
    if (menuOpen) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [menuOpen]);

  const { data, isLoading, error } = useQuery({
    queryKey: ["wiki", slug],
    queryFn: async () => {
      const res = await fetch(`/api/wiki/${encodeURIComponent(slug)}`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json() as Promise<{ slug: string; title: string; html: string }>;
    },
    staleTime: 60000,
    retry: 1,
  });

  const goTo = (pageSlug: string) => {
    navigate(`/docs/${pageSlug}`);
    setMenuOpen(false);
  };

  return (
    <div className="relative flex flex-col h-full -m-6">
      {/* Floating top bar */}
      <div className="sticky top-0 z-10 flex items-center gap-2 px-4 py-2.5 border-b border-border bg-card/95 backdrop-blur-md">
        {/* Article dropdown */}
        <div ref={menuRef} className="relative">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setMenuOpen(!menuOpen)}
            className="gap-1.5 bg-card/90 border-border/60"
          >
            <BookOpen className="h-3.5 w-3.5" />
            <span className="max-w-[200px] truncate">{currentPage?.title ?? "Documentation"}</span>
            <ChevronDown className={`h-3.5 w-3.5 transition-transform ${menuOpen ? "rotate-180" : ""}`} />
          </Button>

          {menuOpen && (
            <div className="absolute top-full left-0 mt-1 w-64 rounded-lg border border-border bg-card/95 backdrop-blur-md shadow-xl py-1 max-h-[60vh] overflow-y-auto z-50">
              <div className="px-3 py-1.5 border-b border-border mb-1">
                <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Articles</span>
              </div>
              {WIKI_PAGES.map((page) => (
                <button
                  key={page.slug}
                  onClick={() => goTo(page.slug)}
                  className={cn(
                    "w-full text-left px-3 py-1.5 text-sm transition-colors",
                    slug === page.slug
                      ? "bg-primary text-primary-foreground font-medium"
                      : "text-muted-foreground hover:bg-secondary hover:text-foreground"
                  )}
                >
                  {page.title}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Prev / Next nav */}
        <div className="ml-auto flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            disabled={!prevPage}
            onClick={() => prevPage && goTo(prevPage.slug)}
            className="gap-1 text-xs text-muted-foreground"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
            {prevPage?.title ?? ""}
          </Button>
          <span className="text-[10px] text-muted-foreground/50">
            {currentIndex + 1} / {WIKI_PAGES.length}
          </span>
          <Button
            variant="ghost"
            size="sm"
            disabled={!nextPage}
            onClick={() => nextPage && goTo(nextPage.slug)}
            className="gap-1 text-xs text-muted-foreground"
          >
            {nextPage?.title ?? ""}
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {/* Content — full width */}
      <div className="flex-1 overflow-y-auto">
        {isLoading ? (
          <div className="flex items-center justify-center h-64 text-muted-foreground">
            <Loader2 size={20} className="animate-spin mr-2" /> Loading...
          </div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center h-64 text-muted-foreground gap-2">
            <AlertCircle size={24} className="text-destructive" />
            <p className="text-sm font-medium">Failed to load documentation</p>
            <p className="text-xs">{error instanceof Error ? error.message : "Unknown error"}</p>
          </div>
        ) : data?.html ? (
          <div className="max-w-4xl mx-auto px-10 py-8">
            <h1 className="text-2xl font-bold mb-6 pb-4 border-b border-border">{data.title}</h1>
            <div className="wiki-content" dangerouslySetInnerHTML={{ __html: data.html }} />
          </div>
        ) : (
          <div className="flex items-center justify-center h-64 text-muted-foreground">
            <p className="text-sm">Page not found</p>
          </div>
        )}
      </div>
    </div>
  );
}
