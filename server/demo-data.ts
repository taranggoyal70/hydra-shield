import type { GraphEdge, GraphNode } from "./domain.js";

export const demoNodes: GraphNode[] = [
  { id: 1, kind: "service", name: "checkout-api", owner: "Commerce", tier: "Tier 0", x: 76, y: 108 },
  { id: 2, kind: "service", name: "identity-gateway", owner: "Identity", tier: "Tier 0", x: 68, y: 266 },
  { id: 3, kind: "service", name: "merchant-console", owner: "Merchant", tier: "Tier 1", x: 112, y: 420 },
  { id: 4, kind: "service", name: "event-relay", owner: "Platform", tier: "Tier 1", x: 162, y: 546 },
  { id: 5, kind: "service", name: "billing-worker", owner: "Revenue", tier: "Tier 0", x: 84, y: 675 },
  { id: 6, kind: "service", name: "docs-site", owner: "DX", tier: "Tier 2", x: 190, y: 790 },
  { id: 101, kind: "package", name: "@scope/request@7.4.2", status: "compromised", severity: "critical", x: 682, y: 326 },
  { id: 102, kind: "package", name: "@scope/http@2.1.0", status: "affected", x: 465, y: 172 },
  { id: 103, kind: "package", name: "event-pipe@4.8.1", status: "affected", x: 472, y: 430 },
  { id: 104, kind: "package", name: "express@5.1.0", status: "clean", x: 392, y: 676 },
  { id: 105, kind: "package", name: "cookie@0.7.2", status: "clean", x: 604, y: 742 },
  { id: 106, kind: "package", name: "oauth-client@3.3.0", status: "affected", x: 346, y: 292 },
  { id: 107, kind: "package", name: "telemetry-core@9.2.1", status: "affected", x: 306, y: 505 },
  { id: 108, kind: "package", name: "@sc0pe/request@7.4.2", status: "suspicious", severity: "high", x: 864, y: 188 },
  { id: 109, kind: "package", name: "stripe@18.4.0", status: "clean", x: 350, y: 812 },
  { id: 201, kind: "maintainer", name: "release-bot-17", status: "token revoked", x: 891, y: 349 },
  { id: 202, kind: "maintainer", name: "core-platform", status: "verified", x: 884, y: 513 },
  { id: 301, kind: "vulnerability", name: "HSA-2026-0042", severity: "critical", description: "Post-install credential exfiltration", x: 850, y: 686 },
];

export const demoEdges: GraphEdge[] = [
  { id: 1001, source: 1, target: 102, type: "DEPENDS_ON", scope: "runtime" },
  { id: 1002, source: 2, target: 106, type: "DEPENDS_ON", scope: "runtime" },
  { id: 1003, source: 3, target: 107, type: "DEPENDS_ON", scope: "runtime" },
  { id: 1004, source: 4, target: 101, type: "DEPENDS_ON", scope: "runtime" },
  { id: 1005, source: 5, target: 103, type: "DEPENDS_ON", scope: "runtime" },
  { id: 1006, source: 5, target: 109, type: "DEPENDS_ON", scope: "runtime" },
  { id: 1007, source: 6, target: 104, type: "DEPENDS_ON", scope: "dev" },
  { id: 1010, source: 102, target: 101, type: "DEPENDS_ON", scope: "transitive" },
  { id: 1011, source: 106, target: 102, type: "DEPENDS_ON", scope: "transitive" },
  { id: 1012, source: 107, target: 103, type: "DEPENDS_ON", scope: "transitive" },
  { id: 1013, source: 103, target: 101, type: "DEPENDS_ON", scope: "transitive" },
  { id: 1014, source: 104, target: 105, type: "DEPENDS_ON", scope: "transitive" },
  { id: 1101, source: 201, target: 101, type: "MAINTAINS" },
  { id: 1102, source: 201, target: 108, type: "MAINTAINS" },
  { id: 1103, source: 202, target: 102, type: "MAINTAINS" },
  { id: 1201, source: 101, target: 301, type: "AFFECTED_BY" },
  { id: 1301, source: 108, target: 101, type: "SIMILAR_TO", scope: "levenshtein:1" },
];

export const activeIncident = {
  id: "hsa-2026-0042",
  packageId: 101,
  title: "Credential-stealing publish",
  package: "@scope/request",
  version: "7.4.2",
  severity: "critical",
  discoveredAt: "09:06 PT",
  publishedAt: "09:00 PT",
  window: "6 minutes",
  summary: "A stolen automation token published a post-install payload that reads developer and CI credentials.",
  signal: "Registry behavior + maintainer graph",
};

export const blastRadiusCypher = `CALL algo.SSpaths({
  sourceNode: $badId,
  relTypes: ['DEPENDS_ON'],
  relDirection: 'incoming',
  maxLen: 5,
  pathCount: 100,
  resultLimit: 1000
})
YIELD path
RETURN path`;
