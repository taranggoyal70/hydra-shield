import { runEvaluationBenchmark } from "../server/evaluation.js";

const result = runEvaluationBenchmark(1_000);
console.log(JSON.stringify(result, null, 2));
