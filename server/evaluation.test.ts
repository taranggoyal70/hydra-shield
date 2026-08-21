import { describe, expect, it } from "vitest";
import { evaluateBlastRadiusCases } from "./evaluation.js";

describe("evaluateBlastRadiusCases", () => {
  it("reports precision, recall and F1 against labeled service exposure", () => {
    const result = evaluateBlastRadiusCases([
      {
        edges: [{ source: 1, target: 10 }, { source: 2, target: 11 }, { source: 11, target: 10 }],
        serviceIds: [1, 2, 3],
        compromisedId: 10,
        maxDepth: 5,
        expectedServiceIds: [1, 2],
      },
      {
        edges: [{ source: 4, target: 12 }],
        serviceIds: [4],
        compromisedId: 13,
        maxDepth: 5,
        expectedServiceIds: [],
      },
    ]);

    expect(result.cases).toBe(2);
    expect(result.truePositives).toBe(2);
    expect(result.falsePositives).toBe(0);
    expect(result.falseNegatives).toBe(0);
    expect(result.precision).toBe(1);
    expect(result.recall).toBe(1);
    expect(result.f1).toBe(1);
  });
});
