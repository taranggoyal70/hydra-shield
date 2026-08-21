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

Here’s the problem. A security advisory tells you what is broken, but not what inside your company is in danger. It’s like a fire alarm that detects smoke but cannot name the rooms burning.

HydraShield gives you that map.”

### 0:25-0:48 - Real vulnerability evidence

**[Scroll to the advisory evidence.]**

“This is a real GitHub-reviewed vulnerability from OSV. HydraShield pulls in the affected versions and the first safe version. The company services are simulated, but the security evidence is real.”

### 0:48-1:28 - Find the blast radius

**[Scroll to the graph and click Run impact scan.]**

“Now watch what happens when I run the scan.

HydraDB starts with the bad package and walks backwards through the dependency chain. It finds five affected services. Three are customer-critical.

The important part is the proof. Every answer includes the exact path. Checkout reaches the package in two steps. Identity never installed it directly, but is still exposed three levels down. A normal package search can miss that.”

### 1:28-1:50 - Investigate a related threat

**[Click Inspect typosquat candidate.]**

“It also catches something else. `Senver` is only one letter away from `semver`. That could be a typosquat. I can inspect it without leaving the original investigation.”

### 1:50-2:15 - Import a real lockfile

**[Click Import lockfile. Enter `payments-api`, choose `demo/vulnerable-package-lock.json`, and click Build dependency graph.]**

“Teams do not build this graph by hand. HydraShield uses the package-lock files they already have.

I’ll import payments-api. Its packages and dependency links enter the graph, and the vulnerable version connects to the advisory automatically.”

### 2:15-2:38 - Prove correctness and performance

**[Close the dialog and point to the evaluation card, then the query result.]**

“A good-looking graph means nothing if the answer is wrong. So I test hidden dependencies, different versions, cycles, and depth limits. HydraShield reports precision, recall, F1, and latency.

This read epoch also shows that the answer came from a consistent HydraDB snapshot.”

### 2:38-2:55 - Turn evidence into action

**[Scroll to the containment plan and mark the first item complete.]**

“Most security tools stop at the alert. HydraShield keeps going. It shows what to pause, which safe version to use, what to rebuild, and what can stay running. I can also export the incident for the response team.”

### 2:55-3:00 - Close

**[Return briefly to the graph.]**

“HydraShield turns one public warning into an exact list of what is at risk, proof of why, and a plan to fix it. That is incident response powered by HydraDB.”

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
