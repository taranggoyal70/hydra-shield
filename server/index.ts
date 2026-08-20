import { createApp, seedDemo } from "./app.js";
import { HydraClient } from "./hydra.js";

const port = Number(process.env.PORT ?? 8787);
const hydra = new HydraClient();

if (await hydra.isAvailable()) {
  try {
    await seedDemo(hydra);
    console.log("HydraDB demo graph ready");
  } catch (error) {
    console.error("HydraDB is reachable but demo seeding failed", error);
  }
}

createApp(hydra).listen(port, "127.0.0.1", () => {
  console.log(`HydraShield API listening on http://127.0.0.1:${port}`);
});
