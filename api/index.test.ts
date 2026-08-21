import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createVercelApp } from "./index.js";

let server: Server | undefined;

afterEach(async () => {
  if (!server) return;
  await new Promise<void>((resolve, reject) => {
    server?.close((error) => error ? reject(error) : resolve());
  });
  server = undefined;
});

async function request(path: string) {
  server = createServer(createVercelApp());
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("HTTP server did not bind to a port");
  return fetch(`http://127.0.0.1:${address.port}${path}`);
}

describe("Vercel API rewrite entrypoint", () => {
  it("serves advisory JSON when Vercel routes /api/advisory through api/index", async () => {
    const response = await request("/api/index?path=advisory");

    expect(response.headers.get("content-type")).toContain("application/json");
    await expect(response.json()).resolves.toMatchObject({
      id: "GHSA-c2qf-rxjj-qqgw",
      package: "semver",
      version: "7.3.7",
    });
  });
});
