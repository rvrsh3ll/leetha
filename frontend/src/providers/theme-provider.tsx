// frontend/src/providers/theme-provider.tsx
import { createContext, useContext, useEffect, useState, useCallback } from "react";

type Theme = "dark" | "light";

export interface AppearanceSettings {
  theme: Theme;
  accentColor: string;        // HSL base value e.g. "217 91% 60%"
  fontSize: number;           // base rem multiplier: 14, 15, 16
  fontFamily: "system" | "inter" | "mono";
  sidebarWidth: "compact" | "default" | "wide";
  tableRowDensity: "compact" | "default" | "comfortable";
  animationsEnabled: boolean;
  highContrast: boolean;
}

const DEFAULT_APPEARANCE: AppearanceSettings = {
  theme: "dark",
  accentColor: "217 91% 60%",   // blue
  fontSize: 15,
  fontFamily: "system",
  sidebarWidth: "default",
  tableRowDensity: "default",
  animationsEnabled: true,
  highContrast: false,
};

const ACCENT_PRESETS: Array<{ name: string; value: string; preview: string }> = [
  { name: "Blue", value: "217 91% 60%", preview: "#3b82f6" },
  { name: "Cyan", value: "189 94% 43%", preview: "#06b6d4" },
  { name: "Green", value: "142 76% 36%", preview: "#16a34a" },
  { name: "Emerald", value: "160 84% 39%", preview: "#10b981" },
  { name: "Purple", value: "271 91% 65%", preview: "#a855f7" },
  { name: "Violet", value: "258 90% 66%", preview: "#8b5cf6" },
  { name: "Pink", value: "330 81% 60%", preview: "#ec4899" },
  { name: "Rose", value: "350 89% 60%", preview: "#f43f5e" },
  { name: "Orange", value: "25 95% 53%", preview: "#f97316" },
  { name: "Amber", value: "38 92% 50%", preview: "#f59e0b" },
  { name: "Red", value: "0 84% 60%", preview: "#ef4444" },
  { name: "Slate", value: "215 16% 47%", preview: "#64748b" },
];

export { ACCENT_PRESETS };

interface ThemeContextValue {
  theme: Theme;
  appearance: AppearanceSettings;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
  updateAppearance: (patch: Partial<AppearanceSettings>) => void;
  resetAppearance: () => void;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

const STORAGE_KEY = "leetha-theme";
const APPEARANCE_KEY = "leetha-appearance";

function loadAppearance(): AppearanceSettings {
  try {
    const saved = localStorage.getItem(APPEARANCE_KEY);
    if (saved) return { ...DEFAULT_APPEARANCE, ...JSON.parse(saved) };
  } catch { /* ignore */ }
  // Migrate old theme key
  const oldTheme = localStorage.getItem(STORAGE_KEY);
  if (oldTheme === "light") return { ...DEFAULT_APPEARANCE, theme: "light" };
  return { ...DEFAULT_APPEARANCE };
}

function applyAppearance(a: AppearanceSettings) {
  const root = document.documentElement;

  // Theme class
  root.classList.remove("light", "dark");
  root.classList.add(a.theme);

  // Accent color
  root.style.setProperty("--primary", a.accentColor);
  root.style.setProperty("--ring", a.accentColor);

  // Font size
  root.style.fontSize = `${a.fontSize}px`;

  // Font family
  const fonts: Record<string, string> = {
    system: "ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    inter: "'Inter', ui-sans-serif, system-ui, sans-serif",
    mono: "ui-monospace, 'Cascadia Code', 'Fira Code', Menlo, Consolas, monospace",
  };
  const fontValue = fonts[a.fontFamily] ?? fonts.system ?? "";
  root.style.setProperty("--font-sans", fontValue);

  // Animations
  if (!a.animationsEnabled) {
    root.style.setProperty("--transition-speed", "0s");
    root.classList.add("no-animations");
  } else {
    root.style.removeProperty("--transition-speed");
    root.classList.remove("no-animations");
  }

  // High contrast
  if (a.highContrast) {
    root.classList.add("high-contrast");
  } else {
    root.classList.remove("high-contrast");
  }

  // Persist
  localStorage.setItem(APPEARANCE_KEY, JSON.stringify(a));
  localStorage.setItem(STORAGE_KEY, a.theme);
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [appearance, setAppearance] = useState<AppearanceSettings>(loadAppearance);

  useEffect(() => {
    applyAppearance(appearance);
  }, [appearance]);

  const setTheme = useCallback((t: Theme) => {
    setAppearance((prev) => ({ ...prev, theme: t }));
  }, []);

  const toggleTheme = useCallback(() => {
    setAppearance((prev) => ({ ...prev, theme: prev.theme === "dark" ? "light" : "dark" }));
  }, []);

  const updateAppearance = useCallback((patch: Partial<AppearanceSettings>) => {
    setAppearance((prev) => ({ ...prev, ...patch }));
  }, []);

  const resetAppearance = useCallback(() => {
    setAppearance(DEFAULT_APPEARANCE);
  }, []);

  return (
    <ThemeContext.Provider value={{ theme: appearance.theme, appearance, setTheme, toggleTheme, updateAppearance, resetAppearance }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}
