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

Speak calmly and treat this as a product walkthrough, not a memorized pitch. The words in bold brackets are actions, not narration.

### 0:00-0:25 - Introduction

**[Start at the top of the page.]**

“Hi, I’m Tarang, and this is HydraShield.

When a vulnerability is published, teams learn which package is affected. They still need to know which services use that exact version, how it reached them, and what to fix first. HydraShield answers that as an explainable dependency graph.”

### 0:25-0:48 - Real vulnerability evidence

**[Scroll to the advisory evidence.]**

“This is a real GitHub-reviewed advisory, also known as CVE-2022-25883. The evidence comes from OSV, including the affected range and first fixed version. The company dependency estate is simulated, but the vulnerability evidence is real.”

### 0:48-1:28 - Find the blast radius

**[Scroll to the graph and click Run impact scan.]**

“Now I’ll run the impact scan.

HydraDB starts at the vulnerable package and follows dependencies backwards. One bounded traversal finds five affected services, including three customer-critical Tier 0 services.

This is more than a list. Each service includes the exact exposure path. Checkout reaches the package in two hops, while Identity reaches it through a three-hop transitive chain. That path is the proof a responder needs before stopping a deployment.”

### 1:28-1:50 - Investigate a related threat

**[Click Inspect typosquat candidate.]**

“The graph also finds related supply-chain signals. Here, `senver` is only one edit away from `semver`. Inspecting it focuses the suspicious node and shows the relationship without losing the original incident context.”

### 1:50-2:15 - Import a real lockfile

**[Click Import lockfile. Enter `payments-api`, choose `demo/vulnerable-package-lock.json`, and click Build dependency graph.]**

“HydraShield can also ingest a normal npm package-lock file. I’ll import this service as payments-api. Resolved packages become versioned graph nodes, dependency links are preserved, and the exact vulnerable version connects to the OSV advisory. There is no separate inventory to maintain by hand.”

### 2:15-2:38 - Prove correctness and performance

**[Close the dialog and point to the evaluation card, then the query result.]**

“The result is measurable, not just visually convincing. The regression covers transitive dependencies, version isolation, cycles, and depth limits, and reports precision, recall, F1, and p95 latency.

In local mode this scan runs against HydraDB, and the read epoch proves it came from a causally consistent graph read.”

### 2:38-2:55 - Turn evidence into action

**[Scroll to the containment plan and mark the first item complete.]**

“Finally, HydraShield turns the result into an action plan: freeze only affected deployments, pin the fixed version, re-resolve the lockfiles, and promote patched services. The incident brief can also be exported for the response team.”

### 2:55-3:00 - Close

**[Return briefly to the graph.]**

“HydraShield turns a public advisory into an exact containment decision. HydraDB makes that decision fast, transitive, and explainable.”

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
