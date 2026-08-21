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
      ranges: [{ introduced: "7.0.0", fixed: "7.5.2" }],
      source: "osv-live",
    });
  });

  it("rejects a response without vulnerability ground truth", () => {
    expect(() => normalizeOsvResponse({ vulns: [] }, "semver", "7.3.7", "osv-live"))
      .toThrow("No OSV advisory found");
  });

  it("links exact vulnerable versions to an advisory node", () => {
    const evidence = normalizeOsvResponse(
      {
        vulns: [{
          id: "GHSA-test",
          affected: [{
            package: { ecosystem: "npm", name: "semver" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "7.0.0" }, { fixed: "7.5.2" }] }],
          }],
        }],
      },
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

  it("links every installed version inside the affected OSV range", () => {
    const evidence = normalizeOsvResponse(
      {
        vulns: [{
          id: "GHSA-range",
          affected: [{
            package: { ecosystem: "npm", name: "semver" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "7.0.0" }, { fixed: "7.5.2" }] }],
          }],
        }],
      },
      "semver",
      "7.3.7",
      "bundled-osv",
    );
    const result = attachAdvisoryEvidence({
      nodes: [
        { id: 1, kind: "package", name: "semver@7.0.0" },
        { id: 2, kind: "package", name: "semver@7.5.1" },
        { id: 3, kind: "package", name: "semver@7.5.2" },
        { id: 4, kind: "package", name: "other@7.3.7" },
      ],
      edges: [],
    }, evidence);

    expect(result.matches).toEqual([1, 2]);
  });

  it("matches installed packages against every OSV semver interval", () => {
    const evidence = normalizeOsvResponse(
      {
        vulns: [{
          id: "GHSA-c2qf-rxjj-qqgw",
          affected: [{
            package: { ecosystem: "npm", name: "semver" },
            ranges: [
              { type: "SEMVER", events: [{ introduced: "7.0.0" }, { fixed: "7.5.2" }] },
              { type: "SEMVER", events: [{ introduced: "6.0.0" }, { fixed: "6.3.1" }] },
              { type: "SEMVER", events: [{ introduced: "2.0.0-alpha" }, { fixed: "5.7.2" }] },
            ],
          }],
        }],
      },
      "semver",
      "7.3.7",
      "bundled-osv",
    );
    const result = attachAdvisoryEvidence({
      nodes: [
        { id: 1, kind: "package", name: "semver@7.3.7" },
        { id: 2, kind: "package", name: "semver@6.3.0" },
        { id: 3, kind: "package", name: "semver@5.7.1" },
        { id: 4, kind: "package", name: "semver@7.5.2" },
        { id: 5, kind: "package", name: "semver@6.3.1" },
        { id: 6, kind: "package", name: "semver@5.7.2" },
      ],
      edges: [],
    }, evidence);

    expect(evidence.ranges).toEqual([
      { introduced: "7.0.0", fixed: "7.5.2" },
      { introduced: "6.0.0", fixed: "6.3.1" },
      { introduced: "2.0.0-alpha", fixed: "5.7.2" },
    ]);
    expect(result.matches).toEqual([1, 2, 3]);
  });
});
