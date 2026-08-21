import { describe, expect, it } from "vitest";
import { attachAdvisoryEvidence, normalizeOsvResponse } from "./advisory.js";

describe("normalizeOsvResponse", () => {
  it("turns an OSV response into judge-facing advisory evidence", () => {
    const evidence = normalizeOsvResponse(
      {
        vulns: [
          {
            id: "GHSA-c2qf-rxjj-qqgw",
            aliases: ["CVE-2022-25883"],
            summary: "semver vulnerable to Regular Expression Denial of Service",
            database_specific: { severity: "HIGH" },
            affected: [
              {
                package: { ecosystem: "npm", name: "semver" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "7.0.0" }, { fixed: "7.5.2" }] }],
              },
            ],
            references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-c2qf-rxjj-qqgw" }],
          },
        ],
      },
      "semver",
      "7.3.7",
      "osv-live",
    );

    expect(evidence).toMatchObject({
      id: "GHSA-c2qf-rxjj-qqgw",
      aliases: ["CVE-2022-25883"],
      package: "semver",
      version: "7.3.7",
      severity: "HIGH",
      introduced: "7.0.0",
      fixed: "7.5.2",
      source: "osv-live",
    });
  });

  it("rejects a response without vulnerability ground truth", () => {
    expect(() => normalizeOsvResponse({ vulns: [] }, "semver", "7.3.7", "osv-live"))
      .toThrow("No OSV advisory found");
  });

  it("links exact vulnerable versions to an advisory node", () => {
    const evidence = normalizeOsvResponse(
      { vulns: [{ id: "GHSA-test", affected: [{ package: { ecosystem: "npm", name: "semver" } }] }] },
      "semver",
      "7.3.7",
      "bundled-osv",
    );
    const result = attachAdvisoryEvidence({
      nodes: [
        { id: 1, kind: "service", name: "release-api" },
        { id: 2, kind: "package", name: "semver@7.3.7" },
        { id: 3, kind: "package", name: "semver@7.5.2" },
      ],
      edges: [],
    }, evidence);

    expect(result.matches).toEqual([2]);
    expect(result.graph.nodes).toContainEqual(expect.objectContaining({ kind: "vulnerability", name: "GHSA-test" }));
    expect(result.graph.edges).toContainEqual(expect.objectContaining({ source: 2, type: "AFFECTED_BY" }));
  });
});
