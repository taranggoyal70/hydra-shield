export type AdvisorySource = "osv-live" | "bundled-osv";

interface OsvEvent {
  introduced?: string;
  fixed?: string;
}

interface OsvVulnerability {
  id?: string;
  aliases?: string[];
  summary?: string;
  database_specific?: { severity?: string };
  affected?: Array<{
    package?: { ecosystem?: string; name?: string };
    ranges?: Array<{ type?: string; events?: OsvEvent[] }>;
  }>;
  references?: Array<{ type?: string; url?: string }>;
}

interface OsvResponse {
  vulns?: OsvVulnerability[];
}

export interface AdvisoryEvidence {
  id: string;
  aliases: string[];
  package: string;
  version: string;
  summary: string;
  severity: string;
  introduced: string;
  fixed: string;
  source: AdvisorySource;
  sourceLabel: string;
  references: string[];
  fetchedAt: string;
}

export function attachAdvisoryEvidence(graph: LockfileGraph, evidence: AdvisoryEvidence) {
  const matches = graph.nodes
    .filter((node) => node.kind === "package" && node.name === `${evidence.package}@${evidence.version}`)
    .map((node) => node.id);
  if (matches.length === 0) return { graph, matches };

  const vulnerabilityId = stableId(`vulnerability:${evidence.id}`);
  return {
    graph: {
      nodes: [
        ...graph.nodes,
        {
          id: vulnerabilityId,
          kind: "vulnerability" as const,
          name: evidence.id,
          severity: evidence.severity.toLowerCase(),
          description: evidence.summary,
        },
      ],
      edges: [
        ...graph.edges,
        ...matches.map((source) => ({
          id: stableId(`edge:${source}:${vulnerabilityId}:affected`),
          source,
          target: vulnerabilityId,
          type: "AFFECTED_BY" as const,
          version: evidence.version,
        })),
      ],
    },
    matches,
  };
}

const packageName = "semver";
const packageVersion = "7.3.7";

const bundledResponse: OsvResponse = {
  vulns: [
    {
      id: "GHSA-c2qf-rxjj-qqgw",
      aliases: ["CVE-2022-25883"],
      summary: "semver vulnerable to Regular Expression Denial of Service",
      database_specific: { severity: "HIGH" },
      affected: [
        {
          package: { ecosystem: "npm", name: packageName },
          ranges: [{ type: "SEMVER", events: [{ introduced: "7.0.0" }, { fixed: "7.5.2" }] }],
        },
      ],
      references: [
        { type: "ADVISORY", url: "https://github.com/advisories/GHSA-c2qf-rxjj-qqgw" },
        { type: "WEB", url: "https://osv.dev/vulnerability/GHSA-c2qf-rxjj-qqgw" },
      ],
    },
  ],
};

export function normalizeOsvResponse(
  payload: OsvResponse,
  requestedPackage: string,
  requestedVersion: string,
  source: AdvisorySource,
): AdvisoryEvidence {
  const vulnerability = payload.vulns?.[0];
  if (!vulnerability?.id) throw new Error("No OSV advisory found for this package version.");

  const affected = vulnerability.affected?.find(
    (entry) => entry.package?.ecosystem?.toLowerCase() === "npm" && entry.package.name === requestedPackage,
  );
  const events = affected?.ranges?.find((range) => range.type === "SEMVER")?.events ?? [];
  const introduced = events.find((event) => event.introduced)?.introduced ?? "unknown";
  const fixed = [...events].reverse().find((event) => event.fixed)?.fixed ?? "not published";
  const references = [...new Set([
    `https://osv.dev/vulnerability/${vulnerability.id}`,
    ...(vulnerability.references?.flatMap((reference) => reference.url ? [reference.url] : []) ?? []),
  ])];

  return {
    id: vulnerability.id,
    aliases: vulnerability.aliases ?? [],
    package: requestedPackage,
    version: requestedVersion,
    summary: vulnerability.summary ?? "Published software supply-chain advisory",
    severity: vulnerability.database_specific?.severity ?? "UNKNOWN",
    introduced,
    fixed,
    source,
    sourceLabel: source === "osv-live" ? "OSV.dev live API" : "Bundled OSV snapshot",
    references,
    fetchedAt: new Date().toISOString(),
  };
}

let cachedEvidence: Promise<AdvisoryEvidence> | undefined;

export function getAdvisoryEvidence(): Promise<AdvisoryEvidence> {
  if (!cachedEvidence) {
    cachedEvidence = fetch("https://api.osv.dev/v1/vulns/GHSA-c2qf-rxjj-qqgw", {
      signal: AbortSignal.timeout(2_500),
    })
      .then(async (response) => {
        if (!response.ok) throw new Error(`OSV returned ${response.status}`);
        return normalizeOsvResponse({ vulns: [await response.json() as OsvVulnerability] }, packageName, packageVersion, "osv-live");
      })
      .catch(() => normalizeOsvResponse(bundledResponse, packageName, packageVersion, "bundled-osv"));
  }
  return cachedEvidence;
}
import { stableId, type LockfileGraph } from "./domain.js";
