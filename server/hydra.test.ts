import { describe, expect, it } from "vitest";
import { servicePathsFromRows } from "./hydra.js";

describe("servicePathsFromRows", () => {
  it("hydrates, reverses and deduplicates native HydraDB service paths", () => {
    const service = {
      id: 4,
      properties: {
        kind: { String: "service" },
        name: { String: "event-relay" },
        owner: { String: "Platform" },
        tier: { String: "Tier 1" },
      },
    };
    const rows = [
      {
        path: {
          nodes: [
            { id: 101, properties: { kind: { String: "package" }, name: { String: "request@7.4.2" } } },
            service,
          ],
        },
      },
      { path: { nodes: [{ id: 102, properties: { kind: { String: "package" } } }, service] } },
      { path: { nodes: [{ id: 103, properties: { kind: { String: "package" } } }] } },
    ];

    expect(servicePathsFromRows(rows)).toEqual([
      {
        id: 4,
        name: "event-relay",
        owner: "Platform",
        tier: "Tier 1",
        path: ["event-relay", "request@7.4.2"],
        hops: 1,
      },
    ]);
  });
});
