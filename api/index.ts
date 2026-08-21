import express from "express";
import { createApp } from "../server/app.js";

export function createVercelApp(): ReturnType<typeof express> {
  const app = express();

  app.use((request, _response, next) => {
    const url = new URL(request.url, "http://vercel.local");
    const rewrittenPath = url.searchParams.get("path");
    if (request.path === "/api/index" && rewrittenPath?.trim()) {
      url.searchParams.delete("path");
      const query = url.searchParams.toString();
      request.url = `/api/${rewrittenPath.replace(/^\/+/, "")}${query ? `?${query}` : ""}`;
    }
    next();
  });

  app.use(createApp());
  return app;
}

const app: ReturnType<typeof express> = createVercelApp();

export default app;
