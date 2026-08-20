import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Box,
  Check,
  ChevronDown,
  CircleDot,
  Clock3,
  Code2,
  Download,
  FileJson,
  Fingerprint,
  GitBranch,
  Hexagon,
  Network,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  Sparkles,
  Upload,
  X,
  Zap,
} from "lucide-react";

type NodeKind = "service" | "package" | "maintainer" | "vulnerability" | "deployment";
type EdgeType = "DEPENDS_ON" | "MAINTAINS" | "AFFECTED_BY" | "SIMILAR_TO" | "DEPLOYED_AS";

interface GraphNode {
  id: number;
  kind: NodeKind;
  name: string;
  owner?: string;
  tier?: string;
  severity?: string;
  status?: string;
  description?: string;
  x?: number;
  y?: number;
}

interface GraphEdge {
  id: number;
  source: number;
  target: number;
  type: EdgeType;
  scope?: string;
}

interface Incident {
  id: string;
  packageId: number;
  title: string;
  package: string;
  version: string;
  severity: string;
  discoveredAt: string;
  publishedAt: string;
  window: string;
  summary: string;
  signal: string;
}

interface PlaybookItem {
  id: string;
  title: string;
  detail: string;
  owner: string;
  eta: string;
}

interface AppState {
  incident: Incident;
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  playbook: PlaybookItem[];
  hydraLive: boolean;
  generatedAt: string;
}

interface ImpactService {
  id: number;
  name: string;
  owner: string;
  tier: string;
  path: string[];
  hops: number;
}

interface ScanResult {
  source: "hydradb" | "snapshot";
  query: string;
  parameters: { badId: number; maxDepth: number };
  readEpoch?: number;
  elapsedMs: number;
  services: ImpactService[];
  metrics: {
    affectedServices: number;
    criticalServices: number;
    dependencyPaths: number;
    exposedCredentials: number;
  };
  relatedRisk: { maintainer: string; siblingPackage: string; confidence: number };
}

const nodeTone: Record<NodeKind, string> = {
  service: "service",
  package: "package",
  maintainer: "maintainer",
  vulnerability: "vulnerability",
  deployment: "deployment",
};

function shortName(name: string): string {
  if (name.length <= 22) return name;
  return `${name.slice(0, 20)}…`;
}

function GraphMap({
  graph,
  scan,
  scanning,
}: {
  graph: AppState["graph"];
  scan: ScanResult | null;
  scanning: boolean;
}) {
  const [selected, setSelected] = useState<number | null>(101);
  const nodeById = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph.nodes]);
  const affectedNames = useMemo(
    () => new Set(scan?.services.flatMap((service) => service.path) ?? []),
    [scan],
  );

  return (
    <div className={`graph-stage ${scanning ? "is-scanning" : ""}`}>
      <div className="graph-toolbar">
        <div className="graph-legend" aria-label="Graph legend">
          <span><i className="legend-dot service" /> Service</span>
          <span><i className="legend-dot package" /> Package</span>
          <span><i className="legend-dot risk" /> Active risk</span>
        </div>
        <button className="icon-button" aria-label="Center graph"><Search size={15} /></button>
      </div>

      <svg className="network-map" viewBox="0 0 1000 900" role="img" aria-label="Dependency graph showing affected services">
        <defs>
          <marker id="arrow-safe" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" />
          </marker>
          <marker id="arrow-risk" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" />
          </marker>
          <radialGradient id="scan-wave">
            <stop offset="55%" stopColor="#f65f45" stopOpacity="0" />
            <stop offset="82%" stopColor="#f65f45" stopOpacity=".24" />
            <stop offset="100%" stopColor="#f65f45" stopOpacity="0" />
          </radialGradient>
        </defs>

        <g className="graph-edges">
          {graph.edges.map((edge) => {
            const source = nodeById.get(edge.source);
            const target = nodeById.get(edge.target);
            if (!source || !target) return null;
            const risk = affectedNames.has(source.name) && affectedNames.has(target.name);
            const midX = ((source.x ?? 0) + (target.x ?? 0)) / 2;
            const curve = edge.type === "DEPENDS_ON" ? -22 : 28;
            return (
              <path
                key={edge.id}
                className={`graph-edge ${risk ? "risk" : ""} edge-${edge.type.toLowerCase()}`}
                d={`M ${source.x} ${source.y} Q ${midX} ${((source.y ?? 0) + (target.y ?? 0)) / 2 + curve} ${target.x} ${target.y}`}
                markerEnd={edge.type === "DEPENDS_ON" ? `url(#arrow-${risk ? "risk" : "safe"})` : undefined}
              />
            );
          })}
        </g>

        {scanning && <circle className="scan-wave" cx="682" cy="326" r="30" fill="url(#scan-wave)" />}

        <g className="graph-nodes">
          {graph.nodes.map((node) => {
            const compromised = node.status === "compromised";
            const affected = affectedNames.has(node.name);
            const isSelected = selected === node.id;
            return (
              <g
                key={node.id}
                className={`graph-node ${nodeTone[node.kind]} ${affected ? "affected" : ""} ${compromised ? "compromised" : ""} ${isSelected ? "selected" : ""}`}
                transform={`translate(${node.x ?? 0} ${node.y ?? 0})`}
                role="button"
                tabIndex={0}
                aria-label={`${node.kind}: ${node.name}`}
                onClick={() => setSelected(node.id)}
                onKeyDown={(event) => event.key === "Enter" && setSelected(node.id)}
              >
                {compromised && <circle className="node-pulse" r="43" />}
                <circle className="node-ring" r={node.kind === "service" ? 24 : 20} />
                <circle className="node-core" r={node.kind === "service" ? 16 : 13} />
                {node.kind === "service" ? <rect className="node-glyph" x="-6" y="-5" width="12" height="10" rx="2" /> : <circle className="node-glyph" r="4" />}
                <text className="node-label" x="0" y={node.kind === "service" ? 42 : 36} textAnchor="middle">{shortName(node.name)}</text>
                {node.tier && <text className="node-meta" x="0" y="57" textAnchor="middle">{node.tier}</text>}
              </g>
            );
          })}
        </g>
      </svg>

      <div className="graph-caption">
        <span><Network size={14} /> {graph.nodes.length} entities · {graph.edges.length} relationships</span>
        <span>Traversal depth ≤ 5</span>
      </div>
    </div>
  );
}

function ImportDialog({ onClose }: { onClose: () => void }) {
  const [serviceName, setServiceName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!file || !serviceName.trim()) return;
    setBusy(true);
    setStatus(null);
    try {
      const lockfile = JSON.parse(await file.text()) as unknown;
      const response = await fetch("/api/ingest/lockfile", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ serviceName, lockfile }),
      });
      const result = (await response.json()) as { message?: string; error?: string; nodes?: number; relationships?: number };
      if (!response.ok) throw new Error(result.error ?? "Import failed");
      setStatus(`${result.message} ${result.nodes} entities and ${result.relationships} relationships found.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "The selected file is not valid JSON.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="import-title" onMouseDown={(event) => event.stopPropagation()}>
        <button className="dialog-close" onClick={onClose} aria-label="Close"><X size={18} /></button>
        <div className="dialog-icon"><FileJson size={22} /></div>
        <p className="eyebrow">Graph ingestion</p>
        <h2 id="import-title">Import an npm lockfile</h2>
        <p className="dialog-copy">HydraShield turns every resolved package into a versioned node and writes dependency relationships directly to HydraDB.</p>
        <label>
          Service name
          <input value={serviceName} onChange={(event) => setServiceName(event.target.value)} placeholder="payments-api" autoFocus />
        </label>
        <label className="file-drop">
          <Upload size={20} />
          <span>{file ? file.name : "Choose package-lock.json"}</span>
          <input type="file" accept="application/json,.json" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
        </label>
        {status && <p className="import-status" role="status">{status}</p>}
        <button className="primary-button wide" disabled={!file || !serviceName.trim() || busy} onClick={submit}>
          {busy ? <RefreshCw className="spin" size={16} /> : <GitBranch size={16} />}
          {busy ? "Building graph…" : "Build dependency graph"}
        </button>
      </section>
    </div>
  );
}

export default function App() {
  const [state, setState] = useState<AppState | null>(null);
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showImport, setShowImport] = useState(false);
  const [completed, setCompleted] = useState<Set<string>>(new Set());
  const graphRef = useRef<HTMLDivElement>(null);

  const runScan = useCallback(async () => {
    if (!state) return;
    setScanning(true);
    setError(null);
    try {
      const [response] = await Promise.all([
        fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ packageId: state.incident.packageId }),
        }),
        new Promise((resolve) => setTimeout(resolve, 850)),
      ]);
      if (!response.ok) throw new Error("The blast-radius query did not complete.");
      setScan((await response.json()) as ScanResult);
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  }, [state]);

  useEffect(() => {
    fetch("/api/state")
      .then(async (response) => {
        if (!response.ok) throw new Error("HydraShield API is unavailable.");
        setState((await response.json()) as AppState);
      })
      .catch((loadError: unknown) => setError(loadError instanceof Error ? loadError.message : "Could not load incident"));
  }, []);

  useEffect(() => {
    if (state && !scan && !scanning) void runScan();
  }, [state, scan, scanning, runScan]);

  const downloadBrief = () => {
    if (!state || !scan) return;
    const payload = JSON.stringify({ incident: state.incident, impact: scan, playbook: state.playbook }, null, 2);
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([payload], { type: "application/json" }));
    link.download = `${state.incident.id}-incident-brief.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  if (!state) {
    return (
      <main className="loading-screen">
        <Hexagon className="loading-mark" size={42} />
        <p>{error ?? "Mapping the dependency graph…"}</p>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="HydraShield home">
          <span className="brand-mark"><Hexagon size={24} /><ShieldAlert size={13} /></span>
          <span><strong>Hydra</strong>Shield</span>
        </a>
        <nav aria-label="Primary navigation">
          <a className="active" href="#incident">Incident</a>
          <a href="#graph">Graph</a>
          <a href="#response">Response</a>
          <a href="#query">Query</a>
        </nav>
        <div className="top-actions">
          <span className={`engine-status ${state.hydraLive ? "live" : ""}`}>
            <i /> {state.hydraLive ? "HydraDB live" : "Demo snapshot"}
          </span>
          <button className="quiet-button" onClick={() => setShowImport(true)}><Upload size={15} /> Import lockfile</button>
        </div>
      </header>

      <main id="top">
        <section className="incident-strip" id="incident">
          <div className="incident-id"><AlertTriangle size={16} /> Active incident <span>HSA-2026-0042</span></div>
          <p>{state.incident.summary}</p>
          <button onClick={downloadBrief} disabled={!scan}><Download size={15} /> Export brief</button>
        </section>

        <section className="hero-head">
          <div>
            <p className="eyebrow">Supply-chain command center · 09:06 PT</p>
            <h1>See the blast radius<br /><em>before it spreads.</em></h1>
          </div>
          <div className="incident-card">
            <div className="incident-card-head">
              <span className="severity-pill">Critical</span>
              <span><Clock3 size={14} /> Published {state.incident.publishedAt}</span>
            </div>
            <code>{state.incident.package}@{state.incident.version}</code>
            <p>{state.incident.title}</p>
            <div className="attack-clock">
              <span>Publish</span><i /><strong>{state.incident.window}</strong><i /><span>Detection</span>
            </div>
          </div>
        </section>

        <section className="metric-rail" aria-label="Impact summary">
          <article><span>Affected services</span><strong>{scan?.metrics.affectedServices ?? "–"}</strong><small>transitive closure</small></article>
          <article><span>Tier 0 exposed</span><strong>{scan?.metrics.criticalServices ?? "–"}</strong><small>customer critical</small></article>
          <article><span>Dependency hops</span><strong>{scan?.metrics.dependencyPaths ?? "–"}</strong><small>across all paths</small></article>
          <article><span>Query time</span><strong>{scan ? `${scan.elapsedMs}ms` : "–"}</strong><small>{scan?.source === "hydradb" ? "HydraDB causal read" : "demo traversal"}</small></article>
          <article className="risk-metric"><span>Confidence</span><strong>{scan ? `${scan.relatedRisk.confidence}%` : "–"}</strong><small>shared identity risk</small></article>
        </section>

        <section className="workspace" id="graph" ref={graphRef}>
          <div className="panel graph-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Live dependency topology</p>
                <h2>Organization exposure graph</h2>
              </div>
              <button className="primary-button" onClick={() => void runScan()} disabled={scanning}>
                {scanning ? <RefreshCw className="spin" size={16} /> : <Play size={15} fill="currentColor" />}
                {scanning ? "Traversing…" : "Run impact scan"}
              </button>
            </div>
            <GraphMap graph={state.graph} scan={scan} scanning={scanning} />
          </div>

          <aside className="panel impact-panel">
            <div className="panel-heading compact">
              <div>
                <p className="eyebrow">Exact paths</p>
                <h2>What is exposed</h2>
              </div>
              <span className="count-badge">{scan?.services.length ?? 0}</span>
            </div>
            {error && <p className="error-banner">{error}</p>}
            <div className="service-list">
              {scan?.services.map((service, index) => (
                <article className="service-row" key={service.id} style={{ "--delay": `${index * 70}ms` } as React.CSSProperties}>
                  <div className="service-title">
                    <span className="service-icon"><Box size={15} /></span>
                    <div><strong>{service.name}</strong><span>{service.owner} · {service.tier}</span></div>
                    <b>{service.hops} hop{service.hops === 1 ? "" : "s"}</b>
                  </div>
                  <div className="path-chain">
                    {service.path.map((segment, segmentIndex) => (
                      <span key={segment}>{segmentIndex > 0 && <ArrowRight size={11} />}<code>{segment}</code></span>
                    ))}
                  </div>
                </article>
              ))}
            </div>
            <div className="correlation-card">
              <div><Fingerprint size={18} /><span><small>Identity correlation</small><strong>Shared publisher detected</strong></span></div>
              <p><code>{scan?.relatedRisk.maintainer}</code> also maintains lookalike <code>{scan?.relatedRisk.siblingPackage}</code>.</p>
              <button>Investigate cluster <ArrowRight size={13} /></button>
            </div>
          </aside>
        </section>

        <section className="response-grid" id="response">
          <div className="panel playbook-panel">
            <div className="panel-heading">
              <div><p className="eyebrow">Generated containment plan</p><h2>Break the chain</h2></div>
              <span className="plan-eta"><Zap size={14} /> 18 min to contain</span>
            </div>
            <div className="playbook-list">
              {state.playbook.map((item, index) => {
                const done = completed.has(item.id);
                return (
                  <button
                    key={item.id}
                    className={`playbook-row ${done ? "done" : ""}`}
                    onClick={() => setCompleted((current) => {
                      const next = new Set(current);
                      if (next.has(item.id)) next.delete(item.id); else next.add(item.id);
                      return next;
                    })}
                  >
                    <span className="step-number">{done ? <Check size={15} /> : String(index + 1).padStart(2, "0")}</span>
                    <span><strong>{item.title}</strong><small>{item.detail}</small></span>
                    <span className="step-owner">{item.owner}<small>{item.eta}</small></span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="panel timeline-panel">
            <div className="panel-heading compact"><div><p className="eyebrow">Attack clock</p><h2>Six minutes to exposure</h2></div><Activity size={20} /></div>
            <ol className="timeline">
              <li><time>09:00:00</time><span><strong>Malicious version published</strong><small>Registry accepts @scope/request@7.4.2</small></span></li>
              <li><time>09:01:14</time><span><strong>First CI resolution</strong><small>event-relay resolves the poisoned artifact</small></span></li>
              <li><time>09:03:41</time><span><strong>Transitive installs fan out</strong><small>Three upstream packages pull the release</small></span></li>
              <li className="active"><time>09:06:08</time><span><strong>HydraShield closes the graph</strong><small>Four services, seven credentials, one publisher cluster</small></span></li>
            </ol>
          </div>
        </section>

        <section className="panel query-panel" id="query">
          <div className="query-copy">
            <p className="eyebrow">Why a graph database</p>
            <h2>One bounded traversal.<br />No embedding guesswork.</h2>
            <p>HydraDB follows the exact, versioned dependency chain from every service to the compromised artifact. Snapshot-consistent reads keep the answer stable while the incident graph is changing.</p>
            <div className="query-facts">
              <span><CircleDot size={14} /> OpenCypher</span>
              <span><GitBranch size={14} /> 1–5 hops</span>
              <span><Sparkles size={14} /> Graph-native</span>
            </div>
          </div>
          <div className="code-window">
            <div className="code-titlebar"><span><i /><i /><i /></span><code>blast-radius.cypher</code><b>{scan?.source === "hydradb" ? "LIVE" : "DEMO"}</b></div>
            <pre><code>{scan?.query ?? "Waiting for scan…"}</code></pre>
            <div className="query-result"><Check size={14} /><span>{scan?.services.length ?? 0} affected services returned</span><small>{scan?.elapsedMs ?? 0} ms · epoch {scan?.readEpoch ?? "snapshot"}</small></div>
          </div>
        </section>

        <footer>
          <div className="brand footer-brand"><span className="brand-mark"><Hexagon size={22} /><ShieldAlert size={12} /></span><span><strong>Hydra</strong>Shield</span></div>
          <p>Graph-native incident response, built on the HydraDB open-source engine.</p>
          <span><Code2 size={14} /> Hack Hydra · Track 02</span>
        </footer>
      </main>

      {showImport && <ImportDialog onClose={() => setShowImport(false)} />}
    </div>
  );
}
