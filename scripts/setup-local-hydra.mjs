import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const directory = path.resolve(process.cwd(), ".hydradb");
const tokenPath = path.join(directory, "auth-token");

await mkdir(directory, { recursive: true });
await writeFile(tokenPath, randomBytes(32).toString("base64url"), { mode: 0o600 });

console.log(`Generated a local HydraDB token at ${tokenPath}`);
