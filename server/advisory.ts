import { stableId, type LockfileGraph } from "./domain.js";
import { featuredAdvisory } from "./featured-advisory.js";

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

export interface AdvisoryRange {
  introduced: string;
  fixed: string;
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
  ranges: AdvisoryRange[];
  source: AdvisorySource;
  sourceLabel: string;
  references: string[];
  fetchedAt: string;
}

function compareVersions(left: string, right: string): number {
  const leftParts = left.split("-")[0].split(".").map(Number);
  const rightParts = right.split("-")[0].split(".").map(Number);
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function packageCoordinates(displayName: string) {
  const separator = displayName.lastIndexOf("@");
  if (separator <= 0) return undefined;
  return { name: displayName.slice(0, separator), version: displayName.slice(separator + 1) };
}

function isVersionInRange(version: string, range: AdvisoryRange): boolean {
  return range.introduced !== "unknown"
    && compareVersions(version, range.introduced) >= 0
    && (range.fixed === "not published" || compareVersions(version, range.fixed) < 0);
}

function affectedRanges(
  affectedEntries: OsvVulnerability["affected"],
  requestedPackage: string,
): AdvisoryRange[] {
  return affectedEntries
    ?.filter((entry) => entry.package?.ecosystem?.toLowerCase() === "npm" && entry.package.name === requestedPackage)
    .flatMap((entry) => entry.ranges ?? [])
    .filter((range) => range.type?.toUpperCase() === "SEMVER")
    .flatMap((range) => {
      const intervals: AdvisoryRange[] = [];
      let introduced = "unknown";

      for (const event of range.events ?? []) {
        if (event.introduced) introduced = event.introduced;
        if (event.fixed) {
          intervals.push({ introduced, fixed: event.fixed });
          introduced = "unknown";
        }
      }

      if (introduced !== "unknown") intervals.push({ introduced, fixed: "not published" });
      return intervals;
    }) ?? [];
}

export function attachAdvisoryEvidence(graph: LockfileGraph, evidence: AdvisoryEvidence) {
  const matches = graph.nodes
    .filter((node) => {
      if (node.kind !== "package") return false;
      const coordinates = packageCoordinates(node.name);
      return coordinates?.name === evidence.package
        && evidence.ranges.some((range) => isVersionInRange(coordinates.version, range));
    })
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
          version: graph.nodes.find((node) => node.id === source)?.name.split("@").at(-1) ?? evidence.version,
        })),
      ],
    },
    matches,
  };
}

const bundledResponse: OsvResponse = {
  vulns: [
    {
      id: featuredAdvisory.id,
      aliases: [featuredAdvisory.alias],
      summary: featuredAdvisory.summary,
      database_specific: { severity: featuredAdvisory.severity },
      affected: [
        {
          package: { ecosystem: "npm", name: featuredAdvisory.package },
          ranges: [
            { type: "SEMVER", events: [{ introduced: "7.0.0" }, { fixed: "7.5.2" }] },
            { type: "SEMVER", events: [{ introduced: "6.0.0" }, { fixed: "6.3.1" }] },
            { type: "SEMVER", events: [{ introduced: "2.0.0-alpha" }, { fixed: "5.7.2" }] },
          ],
        },
      ],
      references: [
        { type: "ADVISORY", url: `https://github.com/advisories/${featuredAdvisory.id}` },
        { type: "WEB", url: `https://osv.dev/vulnerability/${featuredAdvisory.id}` },
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

  const ranges = affectedRanges(vulnerability.affected, requestedPackage);
  const primaryRange = ranges.find((range) => isVersionInRange(requestedVersion, range)) ?? ranges[0];
  const introduced = primaryRange?.introduced ?? "unknown";
  const fixed = primaryRange?.fixed ?? "not published";
  const references = [...new Set([
    `https://osv.dev/vulnerability/${vulnerability.id}`,
    ...(vulnerability.id.startsWith("GHSA-") ? [`https://github.com/advisories/${vulnerability.id}`] : []),
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
    ranges,
    source,
    sourceLabel: source === "osv-live" ? "OSV.dev live API" : "Bundled OSV snapshot",
    references,
    fetchedAt: new Date().toISOString(),
  };
}

let cachedEvidence: Promise<AdvisoryEvidence> | undefined;

export function getAdvisoryEvidence(): Promise<AdvisoryEvidence> {
  if (!cachedEvidence) {
    cachedEvidence = fetch(`https://api.osv.dev/v1/vulns/${featuredAdvisory.id}`, {
      signal: AbortSignal.timeout(2_500),
    })
      .then(async (response) => {
        if (!response.ok) throw new Error(`OSV returned ${response.status}`);
        return normalizeOsvResponse({ vulns: [await response.json() as OsvVulnerability] }, featuredAdvisory.package, featuredAdvisory.version, "osv-live");
      })
      .catch(() => normalizeOsvResponse(bundledResponse, featuredAdvisory.package, featuredAdvisory.version, "bundled-osv"));
  }
  return cachedEvidence;
}
