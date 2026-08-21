import { computeBlastRadius } from "./domain.js";

interface EvaluationCase {
  id: string;
  edges: Array<{ source: number; target: number }>;
  serviceIds: number[];
  compromisedId: number;
  maxDepth: number;
  expectedServiceIds: number[];
}

export interface EvaluationResult {
  cases: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
}

export function evaluateBlastRadiusCases(cases: EvaluationCase[]): EvaluationResult {
  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;

  for (const testCase of cases) {
    const predicted = new Set(computeBlastRadius(
      testCase.edges,
      testCase.serviceIds,
      testCase.compromisedId,
      testCase.maxDepth,
    ).map((result) => result.serviceId));
    const expected = new Set(testCase.expectedServiceIds);
    for (const serviceId of predicted) {
      if (expected.has(serviceId)) truePositives += 1;
      else falsePositives += 1;
    }
    for (const serviceId of expected) {
      if (!predicted.has(serviceId)) falseNegatives += 1;
    }
  }

  const precision = truePositives + falsePositives === 0
    ? 1
    : truePositives / (truePositives + falsePositives);
  const recall = truePositives + falseNegatives === 0
    ? 1
    : truePositives / (truePositives + falseNegatives);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  return { cases: cases.length, truePositives, falsePositives, falseNegatives, precision, recall, f1 };
}

const regressionCorpus: EvaluationCase[] = [
  {
    id: "direct-and-transitive",
    edges: [
      { source: 1, target: 101 },
      { source: 2, target: 102 },
      { source: 102, target: 101 },
      { source: 3, target: 103 },
    ],
    serviceIds: [1, 2, 3],
    compromisedId: 101,
    maxDepth: 5,
    expectedServiceIds: [1, 2],
  },
  {
    id: "version-isolation",
    edges: [{ source: 4, target: 201 }, { source: 5, target: 202 }],
    serviceIds: [4, 5],
    compromisedId: 201,
    maxDepth: 5,
    expectedServiceIds: [4],
  },
  {
    id: "cycle-and-depth-bound",
    edges: [
      { source: 6, target: 301 },
      { source: 301, target: 302 },
      { source: 302, target: 301 },
      { source: 302, target: 303 },
    ],
    serviceIds: [6, 7],
    compromisedId: 303,
    maxDepth: 5,
    expectedServiceIds: [6],
  },
];

export function runEvaluationBenchmark(iterations = 200) {
  const timings: number[] = [];
  let result = evaluateBlastRadiusCases(regressionCorpus);
  for (let index = 0; index < iterations; index += 1) {
    const started = performance.now();
    result = evaluateBlastRadiusCases(regressionCorpus);
    timings.push(performance.now() - started);
  }
  timings.sort((left, right) => left - right);
  const percentile = (value: number) => timings[Math.min(timings.length - 1, Math.floor(timings.length * value))] ?? 0;

  return {
    ...result,
    corpus: "3 labeled graphs: transitive, version-isolated, cyclic",
    iterations,
    p50Ms: Number(percentile(0.5).toFixed(3)),
    p95Ms: Number(percentile(0.95).toFixed(3)),
    methodology: "Expected service exposure is hand-labeled; predictions execute the same bounded traversal used by snapshot fallback.",
  };
}
