import express from "express";
import path from "node:path";
import { activeIncident, blastRadiusCypher, correlationCypher, demoEdges, demoNodes } from "./demo-data.js";
import { computeBlastRadius, parseNpmLockfile } from "./domain.js";
import { HydraClient, servicePathsFromRows } from "./hydra.js";

const playbook = [
  { id: "freeze", title: "Freeze affected deploys", detail: "Pause promotion for every service returned by the traversal.", owner: "Platform", eta: "Now" },
  { id: "pin", title: "Pin the last trusted version", detail: "Override @scope/request to 7.4.1 in every affected lockfile.", owner: "Service owners", eta: "4 min" },
  { id: "rotate", title: "Rotate exposed credentials", detail: "Revoke CI, registry, cloud and developer tokens reachable during install.", owner: "Security", eta: "12 min" },
  { id: "rebuild", title: "Rebuild from clean runners", detail: "Invalidate caches and rebuild artifacts created after 09:00 PT.", owner: "Release", eta: "18 min" },
];

function snapshotScan(packageId: number) {
  const serviceNodes = demoNodes.filter((node) => node.kind === "service");
  const dependencyEdges = demoEdges.filter((edge) => edge.type === "DEPENDS_ON");
  const paths = computeBlastRadius(
    dependencyEdges,
    serviceNodes.map((node) => node.id),
    packageId,
    5,
  );
  const nodeById = new Map(demoNodes.map((node) => [node.id, node]));

  return paths.map(({ serviceId, path: nodePath }) => {
    const service = nodeById.get(serviceId)!;
    return {
      id: service.id,
      name: service.name,
      owner: service.owner,
      tier: service.tier,
      path: nodePath.map((id) => nodeById.get(id)?.name ?? String(id)),
      hops: nodePath.length - 1,
    };
  });
}

export function createApp(hydra = new HydraClient()) {
  const app = express();
  app.use(express.json({ limit: "4mb" }));

  app.get("/api/health", async (_request, response) => {
    const hydraLive = await hydra.isAvailable();
    response.json({ ok: true, hydraLive, engine: hydraLive ? "HydraDB live" : "Demo snapshot" });
  });

  app.get("/api/state", async (_request, response) => {
    const hydraLive = await hydra.isAvailable();
    response.json({
      incident: activeIncident,
      graph: { nodes: demoNodes, edges: demoEdges },
      playbook,
      hydraLive,
      generatedAt: new Date().toISOString(),
    });
  });

  app.post("/api/scan", async (request, response) => {
    const packageId = Number(request.body?.packageId ?? activeIncident.packageId);
    if (!Number.isSafeInteger(packageId) || packageId < 0) {
      response.status(400).json({ error: "packageId must be a positive integer" });
      return;
    }

    const started = performance.now();
    let source: "hydradb" | "snapshot" = "snapshot";
    let readEpoch: number | undefined;
    let liveServices: ReturnType<typeof servicePathsFromRows> | undefined;
    let relatedRisk = {
      maintainer: "release-bot-17",
      siblingPackage: "@sc0pe/request@7.4.2",
      confidence: 94,
    };

    if (await hydra.isAvailable()) {
      try {
        const [result, correlation] = await Promise.all([
          hydra.query(blastRadiusCypher, { badId: packageId }),
          hydra.query(correlationCypher, { badId: packageId }),
        ]);
        source = "hydradb";
        readEpoch = result.readEpoch;
        liveServices = servicePathsFromRows(result.rows);
        const match = correlation.rows[0];
        if (match) {
          relatedRisk = {
            maintainer: String(match.maintainer),
            siblingPackage: String(match.sibling),
            confidence: 94,
          };
        }
      } catch (error) {
        console.error("HydraDB scan failed; returning the deterministic demo snapshot", error);
      }
    }

    const services = liveServices ?? snapshotScan(packageId);
    const criticalServices = services.filter((service) => service.tier === "Tier 0").length;

    response.json({
      source,
      query: blastRadiusCypher,
      parameters: { badId: packageId, maxDepth: 5 },
      readEpoch,
      elapsedMs: Math.max(1, Math.round(performance.now() - started)),
      services,
      metrics: {
        affectedServices: services.length,
        criticalServices,
        dependencyPaths: services.reduce((total, service) => total + service.hops, 0),
        exposedCredentials: 7,
      },
      relatedRisk,
    });
  });

  app.post("/api/ingest/lockfile", async (request, response) => {
    const serviceName = String(request.body?.serviceName ?? "").trim();
    if (!serviceName || !request.body?.lockfile) {
      response.status(400).json({ error: "serviceName and lockfile are required" });
      return;
    }

    try {
      const graph = parseNpmLockfile(serviceName, request.body.lockfile);
      const hydraLive = await hydra.isAvailable();
      if (hydraLive) await hydra.seed(graph.nodes, graph.edges);
      response.status(201).json({
        mode: hydraLive ? "ingested" : "preview",
        serviceName,
        nodes: graph.nodes.length,
        relationships: graph.edges.length,
        message: hydraLive
          ? "Lockfile graph written to HydraDB."
          : "Lockfile parsed. Start HydraDB to persist this graph.",
      });
    } catch (error) {
      response.status(422).json({ error: error instanceof Error ? error.message.trim() : "Invalid lockfile" });
    }
  });

  if (process.env.NODE_ENV === "production") {
    const directory = path.resolve(process.cwd(), "dist");
    app.use(express.static(directory));
    app.get("/*splat", (_request, response) => response.sendFile(path.join(directory, "index.html")));
  }

  return app;
}

export async function seedDemo(hydra = new HydraClient()): Promise<void> {
  await hydra.seed(demoNodes, demoEdges);
}
