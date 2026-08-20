import { describe, expect, it } from "vitest";
import { terminalNodeIdsForKind } from "./hydra.js";

describe("terminalNodeIdsForKind", () => {
  it("extracts and deduplicates service endpoints from native HydraDB paths", () => {
    const service = {
      id: 4,
      properties: { kind: { String: "service" }, name: { String: "event-relay" } },
    };
    const rows = [
      { path: { nodes: [{ id: 101, properties: { kind: { String: "package" } } }, service] } },
      { path: { nodes: [{ id: 102, properties: { kind: { String: "package" } } }, service] } },
      { path: { nodes: [{ id: 103, properties: { kind: { String: "package" } } }] } },
    ];

    expect(terminalNodeIdsForKind(rows, "service")).toEqual([4]);
  });
});
