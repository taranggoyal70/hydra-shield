import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import type { GraphEdge, GraphNode, RelationshipType } from "./domain.js";

interface HydraValue {
  type: string;
  value?: unknown;
}

interface HydraResponse {
  query_id: string;
  columns: string[];
  rows: HydraValue[][];
  read_epoch?: number;
  bookmark?: string;
}

const allowedRelationships = new Set<RelationshipType>([
  "DEPENDS_ON",
  "MAINTAINS",
  "AFFECTED_BY",
  "SIMILAR_TO",
  "DEPLOYED_AS",
]);

function unpack(value: HydraValue): unknown {
  if (value.type === "null") return null;
  if (value.type === "list" && Array.isArray(value.value)) {
    return value.value.map((entry) => unpack(entry as HydraValue));
  }
  return value.value;
}

interface NativePathNode {
  id: number;
  properties?: Record<string, Record<string, unknown>>;
}

interface NativePath {
  nodes?: NativePathNode[];
}

function pathProperty(node: NativePathNode, property: string): unknown {
  const value = node.properties?.[property];
  return value && typeof value === "object" ? Object.values(value)[0] : undefined;
}

export interface HydraServicePath {
  id: number;
  name: string;
  owner: string;
  tier: string;
  path: string[];
  hops: number;
}

export function servicePathsFromRows(rows: Record<string, unknown>[]): HydraServicePath[] {
  const services = new Map<number, HydraServicePath>();
  for (const row of rows) {
    const path = row.path as NativePath | undefined;
    const terminal = path?.nodes?.at(-1);
    if (!terminal || pathProperty(terminal, "kind") !== "service" || !path?.nodes) continue;

    const servicePath: HydraServicePath = {
      id: terminal.id,
      name: String(pathProperty(terminal, "name") ?? terminal.id),
      owner: String(pathProperty(terminal, "owner") ?? "Unassigned"),
      tier: String(pathProperty(terminal, "tier") ?? "Unclassified"),
      path: path.nodes
        .map((node) => String(pathProperty(node, "name") ?? node.id))
        .reverse(),
      hops: path.nodes.length - 1,
    };
    const existing = services.get(terminal.id);
    if (!existing || servicePath.hops < existing.hops) services.set(terminal.id, servicePath);
  }
  return [...services.values()].sort((left, right) => left.id - right.id);
}

function localHydraToken(): string {
  try {
    return readFileSync(path.resolve(process.cwd(), ".hydradb/auth-token"), "utf8").trim();
  } catch {
    return "";
  }
}

export class HydraClient {
  readonly baseUrl: string;
  readonly graphId: string;
  readonly namespace: string;
  readonly cellId: string;
  readonly token: string;
  readonly adminUrl: string;

  constructor() {
    this.baseUrl = process.env.HYDRA_URL ?? "http://127.0.0.1:8443";
    this.adminUrl = process.env.HYDRA_ADMIN_URL ?? "http://127.0.0.1:9090";
    this.graphId = process.env.HYDRA_GRAPH_ID ?? "default";
    this.namespace = process.env.HYDRA_NAMESPACE ?? "hydrashield";
    this.cellId = process.env.HYDRA_CELL_ID ?? "cell-0";
    this.token = process.env.HYDRA_TOKEN ?? localHydraToken();
  }

  async isAvailable(): Promise<boolean> {
    if (!this.token) return false;
    try {
      const response = await fetch(`${this.adminUrl}/readyz`, { signal: AbortSignal.timeout(700) });
      return response.ok;
    } catch {
      return false;
    }
  }

  async query(
    query: string,
    parameters: Record<string, unknown> = {},
  ): Promise<{ rows: Record<string, unknown>[]; readEpoch?: number; bookmark?: string }> {
    if (!this.token) {
      throw new Error("HYDRA_TOKEN is required, or run npm run setup:hydra for local development.");
    }
    const response = await fetch(`${this.baseUrl}/v1/graphs/${this.graphId}/query`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
        "X-Graph-Namespace": this.namespace,
      },
      body: JSON.stringify({
        cell_id: this.cellId,
        query_id: `hydrashield-${randomUUID()}`,
        query,
        parameters,
        consistency: "causal",
        timeout_ms: 8_000,
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HydraDB query failed (${response.status}): ${body.slice(0, 600)}`);
    }

    const payload = (await response.json()) as HydraResponse;
    return {
      rows: payload.rows.map((row) =>
        Object.fromEntries(payload.columns.map((column, index) => [column, unpack(row[index])])),
      ),
      readEpoch: payload.read_epoch,
      bookmark: payload.bookmark,
    };
  }

  async seed(nodes: GraphNode[], edges: GraphEdge[]): Promise<void> {
    await this.query(
      "UNWIND $rows AS row MERGE (n {id: row.vertex}) SET n:Entity, n.kind = row.kind, n.name = row.name, n.owner = row.owner, n.tier = row.tier, n.status = row.status, n.severity = row.severity, n.description = row.description",
      {
        rows: nodes.map((node) => ({
          vertex: node.id,
          kind: node.kind,
          name: node.name,
          owner: node.owner ?? "",
          tier: node.tier ?? "",
          status: node.status ?? "",
          severity: node.severity ?? "",
          description: node.description ?? "",
        })),
      },
    );

    const groups = new Map<RelationshipType, GraphEdge[]>();
    for (const edge of edges) {
      groups.set(edge.type, [...(groups.get(edge.type) ?? []), edge]);
    }
    for (const [type, relationshipEdges] of groups) {
      if (!allowedRelationships.has(type)) throw new Error(`Unsupported relationship type: ${type}`);
      await this.query(
        `UNWIND $rows AS row MATCH (s:Entity {id: row.source}), (d:Entity {id: row.target}) MERGE (s)-[r:${type} {id: row.edge}]->(d) SET r.scope = row.scope, r.version = row.version`,
        {
          rows: relationshipEdges.map((edge) => ({
            edge: edge.id,
            source: edge.source,
            target: edge.target,
            scope: edge.scope ?? "",
            version: edge.version ?? "",
          })),
        },
      );
    }
  }
}
