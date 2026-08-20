import { seedDemo } from "./app.js";
import { HydraClient } from "./hydra.js";

const hydra = new HydraClient();
if (!(await hydra.isAvailable())) {
  throw new Error(`HydraDB is not ready at ${hydra.adminUrl}`);
}

await seedDemo(hydra);
console.log("HydraShield demo graph seeded into HydraDB");
