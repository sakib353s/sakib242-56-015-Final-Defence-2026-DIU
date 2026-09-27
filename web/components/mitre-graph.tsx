"use client";
/* Hierarchical "fishing-net" MITRE graph — the tree (technique →
   sub-techniques → hosts → signatures) is computed from THIS system's real
   data and suspended on Verlet springs. The cursor parts the mesh like a net
   under water; dragging a node carries its neighbourhood with inertia and
   the whole web sways back into the tree on release. No pulses, no flashing —
   motion comes from springs, easing, sheen gradients and soft shadows. */
import { useEffect, useRef, useState } from "react";

export interface GNode { id: string; label: string; kind: string; weight: number }
export interface GLink { source: string; target: string; value: number }

interface Sim {
  x: number; y: number; px: number; py: number;   // Verlet state
  tx: number; ty: number;                          // tree anchor
  sc: number; hl: number; born: number;
}

const COLOR: Record<string, string> = {
  technique: "#2563eb",
  sub: "#7c3aed",
  "host-src": "#d97706",
  "host-dst": "#16a34a",
  "host-both": "#0284c7",
  sig: "#db2777",
};
const KIND_LABEL: Record<string, string> = {
  technique: "technique", sub: "sub-technique", "host-src": "source host",
  "host-dst": "target host", "host-both": "host (src+dst)", sig: "detection signature",
};
const KIND_RANK: Record<string, number> = {
  technique: 0, sub: 1, "host-src": 2, "host-dst": 2, "host-both": 2, sig: 3,
};

const hexA = (hex: string, a: number) =>
  `rgba(${parseInt(hex.slice(1, 3), 16)},${parseInt(hex.slice(3, 5), 16)},${parseInt(hex.slice(5, 7), 16)},${a})`;

/* Tidy top-down tree: BFS parentage from technique roots, leaves spread
   evenly across the width, every parent centred over its children. */
function treeLayout(nodes: GNode[], links: GLink[], W: number, H: number) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const adj = new Map<string, string[]>();
  for (const l of links) {
    if (!byId.has(l.source) || !byId.has(l.target)) continue;
    (adj.get(l.source) ?? adj.set(l.source, []).get(l.source)!).push(l.target);
    (adj.get(l.target) ?? adj.set(l.target, []).get(l.target)!).push(l.source);
  }
  let roots = nodes.filter((n) => n.kind === "technique").map((n) => n.id);
  if (!roots.length && nodes.length) {
    roots = [nodes.reduce((a, b) => (b.weight > a.weight ? b : a)).id];
  }
  const children = new Map<string, string[]>();
  const depth = new Map<string, number>();
  const visited = new Set(roots);
  roots.forEach((r) => depth.set(r, 0));
  const queue = [...roots];
  while (queue.length) {
    const id = queue.shift()!;
    const kids = (adj.get(id) ?? []).filter((x) => !visited.has(x));
    kids.sort((a, b) => {
      const na = byId.get(a)!, nb = byId.get(b)!;
      return (KIND_RANK[na.kind] ?? 9) - (KIND_RANK[nb.kind] ?? 9)
        || nb.weight - na.weight || a.localeCompare(b);
    });
    for (const k of kids) {
      visited.add(k);
      children.set(id, [...(children.get(id) ?? []), k]);
      depth.set(k, (depth.get(id) ?? 0) + 1);
      queue.push(k);
    }
  }
  let maxDepth = 0;
  depth.forEach((d) => { maxDepth = Math.max(maxDepth, d); });
  const orphans = nodes.filter((n) => !visited.has(n.id));
  for (const o of orphans) depth.set(o.id, roots.length ? 1 : 0);

  const leaves: string[] = [];
  const dfs = (id: string) => {
    const ch = children.get(id);
    if (!ch?.length) { leaves.push(id); return; }
    for (const c of ch) dfs(c);
  };
  roots.forEach(dfs);
  const all = [...leaves, ...orphans.map((o) => o.id)];
  const L = Math.max(1, all.length);

  const layerH = maxDepth > 0 ? Math.min(128, (H - 88) / maxDepth) : 0;
  const top = maxDepth > 0 ? (H - layerH * maxDepth) / 2 + 26 : H / 2;
  const xs = (i: number) => L === 1 ? W / 2 : 58 + (i * (W - 116)) / (L - 1);

  const pos = new Map<string, { tx: number; ty: number }>();
  const xOf = new Map<string, number>();
  all.filter((id) => !children.get(id)?.length)
    .forEach((id, i) => xOf.set(id, xs(i)));
  const put = (id: string): number => {
    const known = xOf.get(id);
    if (known != null) return known;
    const ch = children.get(id) ?? [];
    const v = ch.length ? ch.reduce((a, c) => a + put(c), 0) / ch.length : W / 2;
    xOf.set(id, v);
    return v;
  };
  roots.forEach(put);
  for (const n of nodes) {
    pos.set(n.id, { tx: xOf.get(n.id) ?? W / 2, ty: top + (depth.get(n.id) ?? 0) * layerH });
  }
  return pos;
}

export function MitreGraph({ nodes, links, recentPerMin, height = 520 }:
  { nodes: GNode[]; links: GLink[]; recentPerMin: number; height?: number }) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const sims = useRef<Map<string, Sim>>(new Map());
  const dataRef = useRef({ nodes, links, recentPerMin });
  const [hover, setHover] = useState<GNode | null>(null);
  const dragRef = useRef<string | null>(null);
  const hoverIdRef = useRef<string | null>(null);

  dataRef.current = { nodes, links, recentPerMin };

  useEffect(() => {
    const canvas = canvasRef.current!;
    const wrap = wrapRef.current!;
    const ctx = canvas.getContext("2d")!;
    let raf = 0;
    let W = 0, H = 0, dpr = 1;

    const resize = () => {
      dpr = window.devicePixelRatio || 1;
      W = wrap.clientWidth; H = height;
      canvas.width = W * dpr; canvas.height = H * dpr;
      canvas.style.width = `${W}px`; canvas.style.height = `${H}px`;
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(wrap);

    const radius = (n: GNode) =>
      n.kind === "technique" ? 22 : Math.min(18, 6 + Math.sqrt(Math.max(1, n.weight)) * 2.8);

    let layoutKey = "";
    let rest = new Map<string, number>();      // "s>t" → rest length
    let neighbors = new Set<string>();
    let nbFor: string | null = null;

    const tick = (t: number) => {
      raf = requestAnimationFrame(tick);
      const { nodes, links } = dataRef.current;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);

      // faint dot grid — light theme graph paper
      ctx.fillStyle = "#e8edf4";
      for (let gx = 24; gx < W; gx += 26)
        for (let gy = 22; gy < H; gy += 26) { ctx.beginPath(); ctx.arc(gx, gy, 0.7, 0, 7); ctx.fill(); }

      // (re)anchor the tree when topology or size changes; sims keep position
      const key = `${W}x${H}|${nodes.map((n) => n.id).sort().join(",")}|${links.map((l) => l.source + ">" + l.target).sort().join(",")}`;
      if (key !== layoutKey) {
        layoutKey = key;
        const targets = treeLayout(nodes, links, W, H);
        for (const n of nodes) {
          const tp = targets.get(n.id)!;
          let s = sims.current.get(n.id);
          if (!s) {
            s = { x: tp.tx, y: tp.ty - 22, px: tp.tx, py: tp.ty - 34, tx: tp.tx, ty: tp.ty, sc: 0, hl: 0, born: t };
            sims.current.set(n.id, s);
          } else { s.tx = tp.tx; s.ty = tp.ty; }
        }
        const live = new Set(nodes.map((n) => n.id));
        for (const id of [...sims.current.keys()]) if (!live.has(id)) sims.current.delete(id);
        rest = new Map();
        for (const l of links) {
          const a = targets.get(l.source), b = targets.get(l.target);
          if (!a || !b) continue;
          rest.set(l.source + ">" + l.target,
            Math.max(64, Math.min(190, Math.hypot(b.tx - a.tx, b.ty - a.ty))));
        }
      }

      const m = mouse.current;
      const dragId = dragRef.current;

      // hover hit-test (canvas owns emphasis; React owns the tooltip card)
      let hovId: string | null = null;
      if (m && !dragId) {
        for (let i = nodes.length - 1; i >= 0; i--) {
          const n = nodes[i]; const s = sims.current.get(n.id);
          if (!s) continue;
          const r = radius(n) * Math.max(1, s.sc) + 7;
          if ((m.x - s.x) ** 2 + (m.y - s.y) ** 2 < r * r) { hovId = n.id; break; }
        }
      }
      if (hovId !== hoverIdRef.current) {
        hoverIdRef.current = hovId;
        setHover(hovId ? nodes.find((n) => n.id === hovId) ?? null : null);
      }
      const activeId = dragId ?? hovId;
      if (activeId !== nbFor) {
        nbFor = activeId;
        neighbors = new Set(activeId ? [activeId] : []);
        if (activeId) for (const l of links) {
          if (l.source === activeId) neighbors.add(l.target);
          if (l.target === activeId) neighbors.add(l.source);
        }
      }

      // --- Verlet integration: anchor springs + cursor parting the net ---
      const R = 130;
      for (const n of nodes) {
        const s = sims.current.get(n.id)!;
        if (n.id === dragId && m) {
          const nx = s.x + (m.x - s.x) * 0.4, ny = s.y + (m.y - s.y) * 0.4;
          s.px = s.x; s.py = s.y; s.x = nx; s.y = ny;
          s.hl += (1 - s.hl) * 0.2;
        } else {
          let vx = (s.x - s.px) * 0.9, vy = (s.y - s.py) * 0.9;
          const aw = n.kind === "technique" ? 0.06 : n.kind === "sub" ? 0.034 : 0.028;
          vx += (s.tx - s.x) * aw; vy += (s.ty - s.y) * aw;
          let lift = 0;
          if (m) {
            const dx = s.x - m.x, dy = s.y - m.y;
            const d = Math.hypot(dx, dy);
            if (d < R) {
              const f = (1 - d / R) ** 2 * 3.2;
              const dd = Math.max(1, d);
              vx += (dx / dd) * f; vy += (dy / dd) * f;
              lift = 1 - d / R;
            }
          }
          s.hl += (lift - s.hl) * 0.12;
          s.px = s.x; s.py = s.y; s.x += vx; s.y += vy;
        }
        const target = n.id === activeId ? 1.22 : 1;
        s.sc += (target - s.sc) * 0.16;
      }

      // --- link constraints: the threads of the net ---
      for (let it = 0; it < 3; it++) {
        for (const l of links) {
          const a = sims.current.get(l.source), b = sims.current.get(l.target);
          if (!a || !b) continue;
          const rl = rest.get(l.source + ">" + l.target) ?? 110;
          const dx = b.x - a.x, dy = b.y - a.y;
          const d = Math.max(1, Math.hypot(dx, dy));
          const pct = ((d - rl) / d) * 0.45;
          const ca = l.source === dragId, cb = l.target === dragId;
          if (ca && cb) continue;
          const wa = ca ? 0 : cb ? 1 : 0.5, wb = cb ? 0 : ca ? 1 : 0.5;
          a.x += dx * pct * wa; a.y += dy * pct * wa;
          b.x -= dx * pct * wb; b.y -= dy * pct * wb;
        }
      }

      for (const n of nodes) {
        const s = sims.current.get(n.id)!;
        const r = radius(n);
        s.x = Math.max(r + 10, Math.min(W - r - 10, s.x));
        s.y = Math.max(r + 26, Math.min(H - r - 22, s.y));
      }

      // --- links: calm threads, tinted + weighted toward the active node ---
      const byId = new Map(nodes.map((n) => [n.id, n]));
      ctx.lineCap = "round";
      for (const l of links) {
        const a = sims.current.get(l.source), b = sims.current.get(l.target);
        const an = byId.get(l.source), bn = byId.get(l.target);
        if (!a || !b || !an || !bn) continue;
        const age = Math.min(1, (t - Math.max(a.born, b.born)) / 600);
        if (age <= 0) continue;
        const touch = !!activeId && (l.source === activeId || l.target === activeId);
        const dim = activeId && !touch && !(neighbors.has(l.source) && neighbors.has(l.target));
        const glow = Math.max(a.hl, b.hl);
        const base = (0.2 + Math.min(0.3, l.value * 0.045)) * age;
        const alpha = Math.min(0.85, base * (touch ? 2.4 : dim ? 0.32 : 1) + glow * 0.18);
        const g = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
        g.addColorStop(0, hexA(COLOR[an.kind] ?? "#2563eb", touch ? alpha : alpha * 0.75));
        g.addColorStop(1, hexA(COLOR[bn.kind] ?? "#2563eb", touch ? alpha : alpha * 0.75));
        ctx.strokeStyle = g;
        ctx.lineWidth = Math.min(4.5, (1 + Math.min(3, l.value * 0.3)) * (touch ? 1.5 : 1));
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
      }

      // --- nodes: gradient spheres on soft shadows, spring scale, no pulses ---
      for (const n of nodes) {
        const s = sims.current.get(n.id)!;
        const ease = 1 - Math.pow(1 - Math.min(1, (t - s.born) / 550), 3);
        const rr = radius(n) * s.sc * ease;
        if (rr <= 0.4) continue;
        const col = COLOR[n.kind] ?? "#2563eb";
        const isAct = n.id === activeId;
        const dim = !!activeId && !neighbors.has(n.id);
        ctx.save();
        ctx.globalAlpha = dim ? 0.38 : ease;
        if (n.kind === "technique") {
          ctx.strokeStyle = hexA(col, 0.22);
          ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.arc(s.x, s.y, rr + 8, 0, 7); ctx.stroke();
        }
        if (s.hl > 0.02) {
          ctx.strokeStyle = hexA(col, 0.35 * s.hl);
          ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.arc(s.x, s.y, rr + 5 + 4 * s.hl, 0, 7); ctx.stroke();
        }
        ctx.shadowColor = hexA(col, 0.3 + 0.32 * s.hl);
        ctx.shadowBlur = 8 + 16 * s.hl + (n.kind === "technique" ? 8 : 0);
        ctx.shadowOffsetY = 2 + 3 * s.hl;
        ctx.fillStyle = col;
        ctx.beginPath(); ctx.arc(s.x, s.y, rr, 0, 7); ctx.fill();
        ctx.shadowColor = "transparent"; ctx.shadowBlur = 0; ctx.shadowOffsetY = 0;
        const sheen = ctx.createRadialGradient(s.x - rr * 0.35, s.y - rr * 0.5, rr * 0.15, s.x, s.y, rr);
        sheen.addColorStop(0, "rgba(255,255,255,0.55)");
        sheen.addColorStop(0.55, "rgba(255,255,255,0.08)");
        sheen.addColorStop(1, "rgba(255,255,255,0)");
        ctx.fillStyle = sheen;
        ctx.beginPath(); ctx.arc(s.x, s.y, rr, 0, 7); ctx.fill();
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 2;
        ctx.stroke();
        const label = n.kind === "sig" && n.label.length > 26 ? n.label.slice(0, 25) + "…" : n.label;
        ctx.font = isAct ? "600 12px ui-monospace, Menlo, monospace"
          : n.kind === "technique" ? "600 12px ui-monospace, Menlo, monospace"
            : "10.5px ui-monospace, Menlo, monospace";
        ctx.fillStyle = isAct ? "#0f172a" : dim ? "#94a3b8" : "#475569";
        ctx.textAlign = "center";
        ctx.fillText(n.kind === "technique" ? `${label} · ${n.weight}` : label, s.x, s.y + rr + 14);
        ctx.restore();
      }

      // tooltip follows its node through the mesh, every frame
      if (activeId && tipRef.current) {
        const s = sims.current.get(activeId);
        const n = byId.get(activeId);
        if (s && n) {
          const tw = 230;
          const x = Math.min(s.x + radius(n) * s.sc + 14, W - tw - 10);
          const y = Math.max(8, Math.min(s.y - 30, H - 84));
          tipRef.current.style.transform = `translate(${x}px, ${y}px)`;
        }
      }

      canvas.style.cursor = dragId ? "grabbing" : hovId ? "grab" : "default";
    };
    raf = requestAnimationFrame(tick);

    const mouse = { current: null as { x: number; y: number } | null };
    const pos = (e: PointerEvent) => {
      const b = canvas.getBoundingClientRect();
      return { x: e.clientX - b.left, y: e.clientY - b.top };
    };
    const down = (e: PointerEvent) => {
      const p = pos(e);
      mouse.current = p;
      for (const [id, s] of sims.current) {
        const n = dataRef.current.nodes.find((x) => x.id === id);
        if (!n) continue;
        const r = radius(n) * Math.max(1, s.sc) + 8;
        if ((p.x - s.x) ** 2 + (p.y - s.y) ** 2 < r * r) {
          dragRef.current = id;
          canvas.setPointerCapture(e.pointerId);
          return;
        }
      }
    };
    const move = (e: PointerEvent) => { mouse.current = pos(e); };
    const up = (e: PointerEvent) => {
      dragRef.current = null;
      try { canvas.releasePointerCapture(e.pointerId); } catch { /* not captured */ }
    };
    const leave = () => { if (!dragRef.current) mouse.current = null; };
    canvas.addEventListener("pointerdown", down);
    canvas.addEventListener("pointermove", move);
    canvas.addEventListener("pointerup", up);
    canvas.addEventListener("pointercancel", up);
    canvas.addEventListener("pointerleave", leave);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      canvas.removeEventListener("pointerdown", down);
      canvas.removeEventListener("pointermove", move);
      canvas.removeEventListener("pointerup", up);
      canvas.removeEventListener("pointercancel", up);
      canvas.removeEventListener("pointerleave", leave);
    };
  }, [height]);

  const conns = hover ? links.filter((l) => l.source === hover.id || l.target === hover.id).length : 0;

  return (
    <div ref={wrapRef} style={{ position: "relative", height, overflow: "hidden", borderRadius: 10, background: "linear-gradient(180deg,#ffffff, #fbfcfe)" }}>
      <style>{`@keyframes cwb-tip{from{opacity:0;transform:translateY(5px) scale(.96)}to{opacity:1;transform:none}}`}</style>
      <canvas ref={canvasRef} style={{ display: "block", touchAction: "none" }} />
      {hover && (
        <div ref={tipRef} style={{ position: "absolute", left: 0, top: 0, pointerEvents: "none", zIndex: 5, willChange: "transform" }}>
          <div className="panel" style={{
            width: 230, padding: "8px 11px", fontSize: 11.5,
            boxShadow: "var(--shadow-2)", animation: "cwb-tip .18s ease-out",
          }}>
            <b style={{ fontFamily: "var(--font-mono)" }}>{hover.label}</b>
            <div className="dim">{KIND_LABEL[hover.kind] ?? hover.kind} · {hover.weight} event{hover.weight === 1 ? "" : "s"} · {conns} link{conns === 1 ? "" : "s"}</div>
            {hover.kind === "technique" && (
              <div className="dim" style={{ marginTop: 2 }}>{dataRef.current.recentPerMin.toFixed(1)} ev/min · last 5 min</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
