"use client";

export function riskTone(v: number): "ok" | "warn" | "fail" {
  return v > 66 ? "fail" : v > 33 ? "warn" : "ok";
}

export function RiskValue({ score }: { score: number | null | undefined }) {
  if (score === null || score === undefined) return <span className="mono-dim">—</span>;
  const tone = riskTone(score);
  const color = tone === "fail" ? "var(--fail)" : tone === "warn" ? "var(--warn)" : "var(--ok)";
  return <span style={{ color, fontFamily: "var(--font-mono)" }}>{Math.round(score)}</span>;
}

export function RiskGauge({ score }: { score: number | null }) {
  const v = Math.max(0, Math.min(100, Math.round(score ?? 0)));
  const tone = riskTone(v);
  const color = tone === "fail" ? "var(--fail)" : tone === "warn" ? "var(--warn)" : "var(--ok)";
  return (
    <div className="gauge" role="img" aria-label={`risk score ${v} of 100`}>
      <span className="gv" style={{ color }}>
        {String(v).padStart(2, "0")}
      </span>
      <div className="dial-track">
        <div className="dial-fill" style={{ width: `${v}%`, color }} />
      </div>
      <span className="cell-id">/100 · normalized CVSS average</span>
    </div>
  );
}
