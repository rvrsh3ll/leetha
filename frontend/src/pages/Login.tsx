import { useState, FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { loginWithToken } from "@/lib/api";
import { setAuth } from "@/lib/auth";
import { AlertCircle, Loader2 } from "lucide-react";

export default function Login() {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const result = await loginWithToken(token.trim());
      if (result.valid) {
        setAuth(token.trim(), result.role);
        navigate("/", { replace: true });
      }
    } catch {
      setError("Invalid or revoked token.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      className="relative flex min-h-screen items-center justify-center overflow-hidden"
      style={{ background: "#0a0a0f", fontFamily: "'Inter', system-ui, sans-serif" }}
    >
      {/* Grid background */}
      <div
        className="pointer-events-none fixed inset-0"
        style={{
          backgroundImage:
            "linear-gradient(rgba(255,255,255,0.024) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.024) 1px, transparent 1px)",
          backgroundSize: "60px 60px",
        }}
      />

      {/* Scan line */}
      <div
        className="pointer-events-none fixed left-0 h-[2px] w-full"
        style={{
          background: "linear-gradient(90deg, transparent, rgba(0,212,255,0.2), transparent)",
          animation: "scanDown 25s linear infinite",
          zIndex: 1,
        }}
      />

      {/* Corner frames */}
      <div className="pointer-events-none absolute inset-0">
        {/* Top-left */}
        <div
          className="absolute left-8 top-8 h-20 w-20"
          style={{ borderLeft: "1px solid rgba(0,212,255,0.2)", borderTop: "1px solid rgba(0,212,255,0.2)" }}
        />
        {/* Bottom-right */}
        <div
          className="absolute bottom-8 right-8 h-20 w-20"
          style={{ borderRight: "1px solid rgba(0,212,255,0.2)", borderBottom: "1px solid rgba(0,212,255,0.2)" }}
        />
      </div>

      {/* Main content */}
      <div className="relative z-10 flex flex-col items-center px-4 text-center" style={{ maxWidth: "550px" }}>
        {/* Overline */}
        <div
          className="mb-6 flex items-center gap-4"
          style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "0.7rem",
            letterSpacing: "0.3em",
            textTransform: "uppercase",
            color: "#00d4ff",
          }}
        >
          <span className="h-px w-10" style={{ background: "rgba(0,212,255,0.2)" }} />
          Passive Network Fingerprinting
          <span className="h-px w-10" style={{ background: "rgba(0,212,255,0.2)" }} />
        </div>

        {/* Title with glitch-style highlight */}
        <h1
          className="mb-4"
          style={{
            fontSize: "clamp(2.5rem, 7vw, 4.5rem)",
            fontWeight: 800,
            lineHeight: 1,
            letterSpacing: "-0.03em",
            color: "#e8e8f0",
          }}
        >
          <span
            style={{
              background: "linear-gradient(135deg, #00d4ff, #7b61ff)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
            }}
          >
            Leetha
          </span>
        </h1>

        {/* Subtitle */}
        <p
          className="mb-8"
          style={{
            fontSize: "1.05rem",
            color: "#8a8a9a",
            lineHeight: 1.7,
            maxWidth: "450px",
          }}
        >
          Identify every device on your network by analyzing broadcast traffic,
          protocol fingerprints, and behavioral patterns — without sending a single packet.
        </p>

        {/* Meta items */}
        <div
          className="mb-10 flex flex-wrap items-center justify-center gap-6"
          style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "0.75rem",
            color: "#8a8a9a",
          }}
        >
          <span className="flex items-center gap-2">
            <span style={{ color: "#00d4ff" }}>&#9670;</span> DHCP / mDNS / TLS
          </span>
          <span className="flex items-center gap-2">
            <span style={{ color: "#00d4ff" }}>&#9670;</span> 315 Probe Plugins
          </span>
          <span className="flex items-center gap-2">
            <span style={{ color: "#00d4ff" }}>&#9670;</span> Real-Time Analysis
          </span>
        </div>

        {/* Login form */}
        <form onSubmit={handleSubmit} className="w-full space-y-4" style={{ maxWidth: "380px" }}>
          <div>
            <label
              htmlFor="token"
              className="mb-2 block text-left"
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: "0.65rem",
                letterSpacing: "0.15em",
                textTransform: "uppercase",
                color: "#55556a",
              }}
            >
              Access Token
            </label>
            <input
              id="token"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="ltk_..."
              autoFocus
              autoComplete="off"
              className="w-full outline-none transition-all"
              style={{
                height: "48px",
                padding: "0 1rem",
                background: "#161622",
                border: "1px solid #1e1e30",
                color: "#e8e8f0",
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: "0.85rem",
                borderRadius: 0,
              }}
              onFocus={(e) => {
                e.target.style.borderColor = "rgba(0,212,255,0.4)";
                e.target.style.boxShadow = "0 0 0 1px rgba(0,212,255,0.1)";
              }}
              onBlur={(e) => {
                e.target.style.borderColor = "#1e1e30";
                e.target.style.boxShadow = "none";
              }}
            />
          </div>

          {error && (
            <div
              className="flex items-center gap-2 px-3 py-2 text-sm"
              style={{
                background: "rgba(255,107,53,0.1)",
                border: "1px solid rgba(255,107,53,0.2)",
                color: "#ff6b35",
              }}
            >
              <AlertCircle className="h-4 w-4 shrink-0" />
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !token.trim()}
            className="flex w-full items-center justify-center gap-2 transition-all"
            style={{
              height: "48px",
              background: "#00d4ff",
              color: "#0a0a0f",
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "0.8rem",
              fontWeight: 600,
              letterSpacing: "0.1em",
              textTransform: "uppercase",
              border: "none",
              cursor: loading || !token.trim() ? "not-allowed" : "pointer",
              opacity: loading || !token.trim() ? 0.4 : 1,
              borderRadius: 0,
            }}
            onMouseEnter={(e) => {
              if (!loading && token.trim()) {
                e.currentTarget.style.background = "#fff";
                e.currentTarget.style.boxShadow = "0 0 30px rgba(0,212,255,0.2)";
              }
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "#00d4ff";
              e.currentTarget.style.boxShadow = "none";
            }}
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Authenticating...
              </>
            ) : (
              <>Authenticate &rarr;</>
            )}
          </button>
        </form>

      </div>

      {/* Scanline animation keyframes */}
      <style>{`
        @keyframes scanDown {
          0% { top: -2px; opacity: 0; }
          5% { opacity: 1; }
          95% { opacity: 1; }
          100% { top: 100%; opacity: 0; }
        }
        ::placeholder {
          color: #55556a !important;
        }
      `}</style>
    </div>
  );
}
