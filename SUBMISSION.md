# HydraShield - Hack Hydra submission packet

## One-line summary

HydraShield turns a real software advisory into an exact, explainable service blast radius and a prioritized containment plan using HydraDB graph traversal.

## Track

Track 02A - Supply-chain blast radius.

## Problem

An advisory names a package and version range, but responders still need to discover which applications actually resolved the vulnerable artifact through direct or transitive dependencies. Flat inventory searches miss paths, duplicate versions create ambiguity, and similarity search cannot prove exposure.

## Solution

HydraShield ingests npm v2/v3 lockfiles as a versioned dependency graph, normalizes live OSV and GitHub Advisory evidence, links exact vulnerable versions to advisory nodes, and executes a bounded reverse traversal in HydraDB. The result is every exposed service, its owner and criticality, and the exact dependency path that justifies containment.

## Why HydraDB matters

The core result is not a keyword match. HydraDB performs the reverse, multi-hop dependency traversal and returns native paths under causal consistency. Its graph model also connects packages to advisories, maintainers and one-edit typosquat candidates. Without HydraDB, HydraShield loses exact transitive exposure, path-level explanations and graph-native correlation.

## Proof points

- Real advisory: GHSA-c2qf-rxjj-qqgw / CVE-2022-25883 from OSV and the GitHub Advisory Database.
- Real engine: local Docker flow seeds HydraDB and returns a read epoch from the bounded OpenCypher traversal.
- Real ingestion: npm v2/v3 lockfiles become versioned package nodes and dependency relationships.
- Correctness: three hand-labeled graphs cover direct/transitive exposure, version isolation, cycles and depth bounds.
- Performance: `npm run benchmark:hydra` reports p50, p95, max latency, query count and result bounds.
- Honest hosted mode: Vercel clearly labels the deterministic reference mode when no stateful HydraDB node is attached.

## Links

- Live demo: https://hydra-shield-six.vercel.app
- Repository: https://github.com/taranggoyal70/hydra-shield
- Demo video: TODO
- OSV record: https://osv.dev/vulnerability/GHSA-c2qf-rxjj-qqgw

## Three-minute demo script

### 0:00-0:25 - The problem

“An advisory tells security which package is vulnerable. It does not tell responders which production services actually resolve that exact version, how the dependency reached them, or what to contain first.”

### 0:25-0:50 - Real evidence

Open HydraShield. Point out the live OSV source, GitHub-reviewed GHSA, CVE alias, affected range and fixed version. Explain that the public advisory is real while the enterprise estate is intentionally simulated.

### 0:50-1:35 - HydraDB blast radius

Run the impact scan. Show the five affected services and expand the exact paths. Point to direct and three-hop transitive exposure. Highlight that the query runs as one bounded reverse traversal, not a fuzzy search.

### 1:35-2:00 - Graph-native enrichment

Show `AFFECTED_BY`, `MAINTAINS` and `SIMILAR_TO` relationships. Open the one-edit `senver` candidate to demonstrate how the same graph expands from vulnerability response into supply-chain investigation.

### 2:00-2:25 - Ingestion and evaluation

Import a small `package-lock.json` containing `semver@7.3.7`. Show the exact OSV match linked to the graph. Point to precision, recall, F1 and p95, then open the raw evaluation endpoint.

### 2:25-2:50 - Response

Use the generated plan: freeze only affected deploys, pin 7.5.2, re-resolve lockfiles and promote patched artifacts. Export the incident brief.

### 2:50-3:00 - Close

“HydraShield turns public advisory evidence into an exact containment decision. HydraDB is what makes every answer fast, transitive and explainable.”

## Required capture checklist

- [ ] Record the demo at 1440p or 1080p with browser zoom around 90%.
- [ ] Keep the final video at or below 3 minutes.
- [ ] Show the HydraDB live badge during the locally recorded traversal.
- [ ] Show the read epoch in the query result.
- [ ] Show the OSV source and external advisory link.
- [ ] Show the raw evaluation JSON briefly.
- [ ] Upload to an accessible YouTube or Vimeo URL.
- [ ] Replace the video TODO above.
- [ ] Submit the official Google Form before 11:59 PM PT.
