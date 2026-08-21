import { blastRadiusCypher } from "../server/demo-data.js";
import { HydraClient, servicePathsFromRows } from "../server/hydra.js";

const hydra = new HydraClient();
if (!await hydra.isAvailable()) {
  throw new Error("HydraDB is not reachable. Start it and seed the graph before running this benchmark.");
}

const iterations = 50;
const timings: number[] = [];
let services = 0;

await hydra.query(blastRadiusCypher, { badId: 101 });
for (let index = 0; index < iterations; index += 1) {
  const started = performance.now();
  const result = await hydra.query(blastRadiusCypher, { badId: 101 });
  timings.push(performance.now() - started);
  services = servicePathsFromRows(result.rows).length;
}

timings.sort((left, right) => left - right);
const percentile = (value: number) => timings[Math.min(timings.length - 1, Math.floor(timings.length * value))] ?? 0;

console.log(JSON.stringify({
  engine: "HydraDB",
  consistency: "causal",
  dataset: { entities: 18, relationships: 17, affectedServices: services },
  iterations,
  p50Ms: Number(percentile(0.5).toFixed(2)),
  p95Ms: Number(percentile(0.95).toFixed(2)),
  maxMs: Number((timings.at(-1) ?? 0).toFixed(2)),
  queryBudget: { traversalsPerScan: 1, correlationQueriesPerScan: 1, resultLimit: 1_000 },
  costNote: "Self-hosted HydraDB exposes no per-query billing metric; query count and result bounds are reported instead.",
}, null, 2));
