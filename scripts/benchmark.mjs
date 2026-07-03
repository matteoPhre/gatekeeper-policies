import { performance } from "node:perf_hooks";
import {
  PasswordComplexityEngine,
  PasswordExpiryEngine,
  PasswordRotationEngine,
} from "../dist/policy-core.js";

const ITERATIONS = Number.parseInt(process.env.BENCH_ITERATIONS ?? "5000", 10);
const MIN_COMPLEXITY_OPS = Number.parseFloat(
  process.env.BENCH_MIN_COMPLEXITY_OPS_PER_SEC ?? "15000",
);
const MIN_ROTATION_OPS = Number.parseFloat(
  process.env.BENCH_MIN_ROTATION_OPS_PER_SEC ?? "12000",
);
const MIN_EXPIRY_OPS = Number.parseFloat(
  process.env.BENCH_MIN_EXPIRY_OPS_PER_SEC ?? "50000",
);

function assertThreshold(metricName, value, threshold) {
  if (value < threshold) {
    throw new Error(
      `${metricName} regression detected: ${value.toFixed(2)} < ${threshold.toFixed(2)} ops/sec`,
    );
  }
}

async function measureAsyncOpsPerSec(task) {
  const start = performance.now();
  for (let index = 0; index < ITERATIONS; index += 1) {
    await task();
  }
  const elapsedMs = performance.now() - start;
  return (ITERATIONS / elapsedMs) * 1000;
}

async function run() {
  const complexity = new PasswordComplexityEngine({
    minLength: 12,
    maxLength: 128,
    normalizeTrim: true,
    normalizeUnicode: true,
    unicodeNormalizationForm: "NFKC",
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSymbols: true,
    denyList: [],
    preventRepeatedChars: false,
    maxRepeatedChars: 3,
    preventSequentialChars: false,
    maxSequentialChars: 3,
  });

  const rotation = new PasswordRotationEngine(
    {
      historyLimit: 5,
      blockSubstringsFromPreviousSecrets: false,
      minPreviousSecretSubstringLength: 4,
    },
    {
      getPasswordHistory: async () => ["h1", "h2", "h3", "h4", "h5"],
    },
  );

  const expiry = new PasswordExpiryEngine({ expiryDays: 90 });

  const complexityOps = await measureAsyncOpsPerSec(async () => {
    await complexity.evaluate("StrongPassword#2026");
  });

  const rotationOps = await measureAsyncOpsPerSec(async () => {
    await rotation.evaluate("StrongPassword#2026", "user-1", async () => false);
  });

  const expiryOps = await measureAsyncOpsPerSec(async () => {
    await expiry.evaluate("2026-03-01T00:00:00.000Z");
  });

  assertThreshold("complexity", complexityOps, MIN_COMPLEXITY_OPS);
  assertThreshold("rotation", rotationOps, MIN_ROTATION_OPS);
  assertThreshold("expiry", expiryOps, MIN_EXPIRY_OPS);

  process.stdout.write(
    [
      `complexity: ${complexityOps.toFixed(2)} ops/sec`,
      `rotation: ${rotationOps.toFixed(2)} ops/sec`,
      `expiry: ${expiryOps.toFixed(2)} ops/sec`,
    ].join("\n") + "\n",
  );
}

await run();
