export type NodeKind =
  | "service"
  | "package"
  | "maintainer"
  | "vulnerability"
  | "deployment";

export type RelationshipType =
  | "DEPENDS_ON"
  | "MAINTAINS"
  | "AFFECTED_BY"
  | "SIMILAR_TO"
  | "DEPLOYED_AS";

export interface GraphNode {
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

export interface GraphEdge {
  id: number;
  source: number;
  target: number;
  type: RelationshipType;
  scope?: string;
  version?: string;
}

export interface LockfileGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface PackageLockEntry {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface PackageLock {
  lockfileVersion?: number;
  packages?: Record<string, PackageLockEntry>;
}

export function stableId(value: string, offset = 10_000): number {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return offset + (hash >>> 0) % 2_000_000_000;
}

function packageNameFromPath(path: string): string {
  const marker = "node_modules/";
  const index = path.lastIndexOf(marker);
  return index === -1 ? path : path.slice(index + marker.length);
}

function resolveDependencyPath(
  sourcePath: string,
  dependency: string,
  packages: Record<string, PackageLockEntry>,
): string | undefined {
  let cursor = sourcePath;
  while (true) {
    const candidate = cursor ? `${cursor}/node_modules/${dependency}` : `node_modules/${dependency}`;
    if (packages[candidate]) return candidate;
    const parentMarker = cursor.lastIndexOf("/node_modules/");
    if (parentMarker === -1) {
      if (!cursor) return undefined;
      cursor = "";
    } else {
      cursor = cursor.slice(0, parentMarker);
    }
  }
}

export function parseNpmLockfile(serviceName: string, lockfile: PackageLock): LockfileGraph {
  if (!lockfile.packages || typeof lockfile.packages !== "object") {
    throw new Error("HydraShield supports npm package-lock files with a packages map (lockfile v2 or v3). ");
  }

  const serviceId = stableId(`service:${serviceName}`);
  const nodes = new Map<number, GraphNode>([
    [serviceId, { id: serviceId, kind: "service", name: serviceName, owner: "Imported", tier: "unclassified" }],
  ]);
  const edges = new Map<number, GraphEdge>();
  const idsByPath = new Map<string, number>();

  for (const [path, entry] of Object.entries(lockfile.packages)) {
    if (path === "" || !entry.version) continue;
    const packageName = entry.name ?? packageNameFromPath(path);
    const displayName = `${packageName}@${entry.version}`;
    const id = stableId(`package:${displayName}`);
    idsByPath.set(path, id);
    nodes.set(id, { id, kind: "package", name: displayName, status: "observed" });
  }

  const root = lockfile.packages[""];
  for (const dependency of Object.keys(root?.dependencies ?? {})) {
    const resolvedPath = resolveDependencyPath("", dependency, lockfile.packages);
    const target = resolvedPath ? idsByPath.get(resolvedPath) : undefined;
    if (!target) continue;
    const id = stableId(`edge:${serviceId}:${target}`);
    edges.set(id, {
      id,
      source: serviceId,
      target,
      type: "DEPENDS_ON",
      scope: "runtime",
    });
  }

  for (const [path, entry] of Object.entries(lockfile.packages)) {
    if (path === "" || !entry.version) continue;
    const source = idsByPath.get(path);
    if (!source) continue;
    for (const dependency of Object.keys(entry.dependencies ?? {})) {
      const resolvedPath = resolveDependencyPath(path, dependency, lockfile.packages);
      const target = resolvedPath ? idsByPath.get(resolvedPath) : undefined;
      if (!target) continue;
      const id = stableId(`edge:${source}:${target}`);
      edges.set(id, {
        id,
        source,
        target,
        type: "DEPENDS_ON",
        scope: "transitive",
      });
    }
  }

  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

export function computeBlastRadius(
  edges: Array<Pick<GraphEdge, "source" | "target">>,
  serviceIds: number[],
  compromisedId: number,
  maxDepth: number,
): Array<{ serviceId: number; path: number[] }> {
  const outgoing = new Map<number, number[]>();
  for (const edge of edges) {
    outgoing.set(edge.source, [...(outgoing.get(edge.source) ?? []), edge.target]);
  }

  const results: Array<{ serviceId: number; path: number[] }> = [];
  for (const serviceId of serviceIds) {
    const queue: number[][] = [[serviceId]];
    const seen = new Set<number>([serviceId]);
    while (queue.length > 0) {
      const path = queue.shift()!;
      const current = path[path.length - 1];
      if (current === compromisedId) {
        results.push({ serviceId, path });
        break;
      }
      if (path.length > maxDepth) continue;
      for (const next of outgoing.get(current) ?? []) {
        if (seen.has(next)) continue;
        seen.add(next);
        queue.push([...path, next]);
      }
    }
  }
  return results;
}
