import { describe, expect, it } from "vitest";
import { computeBlastRadius, parseNpmLockfile } from "./domain.js";

describe("computeBlastRadius", () => {
  it("returns every service with a transitive path to the compromised package", () => {
    const result = computeBlastRadius(
      [
        { source: 1, target: 10 },
        { source: 2, target: 11 },
        { source: 11, target: 10 },
        { source: 3, target: 12 },
      ],
      [1, 2, 3],
      10,
      5,
    );

    expect(result).toEqual([
      { serviceId: 1, path: [1, 10] },
      { serviceId: 2, path: [2, 11, 10] },
    ]);
  });
});

describe("parseNpmLockfile", () => {
  it("turns an npm v3 lockfile into a service-to-package graph", () => {
    const graph = parseNpmLockfile("checkout-api", {
      lockfileVersion: 3,
      packages: {
        "": { name: "checkout-api", dependencies: { express: "^5.1.0" } },
        "node_modules/express": {
          version: "5.1.0",
          dependencies: { cookie: "0.7.2" },
        },
        "node_modules/cookie": { version: "0.7.2" },
      },
    });

    expect(graph.nodes.map((node) => node.name)).toEqual([
      "checkout-api",
      "express@5.1.0",
      "cookie@0.7.2",
    ]);
    expect(graph.edges).toHaveLength(2);
    expect(graph.edges.every((edge) => edge.type === "DEPENDS_ON")).toBe(true);
  });
});
