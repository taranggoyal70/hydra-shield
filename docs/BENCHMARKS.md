# Evaluation methodology

HydraShield keeps correctness and performance evidence deliberately small, reproducible and honest.

## Correctness corpus

`npm run benchmark` runs three hand-labeled dependency graphs:

1. Direct and transitive exposure with an unaffected negative service.
2. Two installed versions where only the exact vulnerable node is exposed.
3. A cyclic graph that proves traversal termination and the depth bound.

Precision, recall and F1 compare returned service IDs with the hand-labeled ground truth. This corpus is a regression harness, not a claim about the organizers' held-out evaluation dataset.

## HydraDB latency

`npm run benchmark:hydra` executes one warm-up followed by 50 causal HydraDB traversals. It reports p50, p95 and maximum end-to-end client latency. The included development-machine sample produced:

| Metric | Result |
| --- | ---: |
| p50 | 0.96 ms |
| p95 | 1.83 ms |
| max | 2.74 ms |
| Affected services | 5 |
| Traversal queries per scan | 1 |
| Correlation queries per scan | 1 |
| Result limit | 1,000 paths |

HydraDB is self-hosted in this project and does not expose a per-query billing metric. HydraShield reports query count and explicit traversal/result bounds instead of inventing a cost estimate.
