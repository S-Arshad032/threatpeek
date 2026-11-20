// Entry point: reads env, builds the app, listens.
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { createApp } from "./app.js";
import { loadEnv } from "./env.js";

dotenv.config({ path: path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../.env"), quiet: true });

const env = loadEnv(process.env);
const app = createApp({ env });

app.listen(env.PORT, () => {
  // Only booleans about the layers; never key values.
  console.log(
    `ThreatPeek server on port ${env.PORT} (safebrowsing: ${Boolean(env.GOOGLE_SAFE_BROWSING_KEY)}, ai: ${env.aiActive}, mode: ${env.NODE_ENV})`,
  );
});
