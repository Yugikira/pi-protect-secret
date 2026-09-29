import * as assert from "assert";
import { resolveConfig } from "../config.js";

console.log("=== Running Config Tests ===");

// 1. Test fallback to environment variable when settings.json has no protectsecret
const originalEnv = { ...process.env };

try {
	delete process.env.TYPESAFE_API_KEY;
	delete process.env.typesafe_api_key;
	delete process.env.OPENROUTER_API_KEY;
	delete process.env.openrouter_api_key;

	// No env, no settings
	let cfg = resolveConfig();
	assert.strictEqual(cfg.provider, "typesafe");
	assert.strictEqual(cfg.threshold, 0.75);
	assert.strictEqual(cfg.model, "jev-latest");
	assert.strictEqual(cfg.apiKey, "");

	// Env set for TypeSafe
	process.env.typesafe_api_key = "test_typesafe_key";
	cfg = resolveConfig();
	assert.strictEqual(cfg.provider, "typesafe");
	assert.strictEqual(cfg.apiKey, "test_typesafe_key");
	assert.strictEqual(cfg.model, "jev-latest");

	// Threshold override via options/flag
	cfg = resolveConfig({ thresholdOverride: 0.9 });
	assert.strictEqual(cfg.threshold, 0.9);

	// Env set for OpenRouter (when TypeSafe is not set)
	delete process.env.typesafe_api_key;
	process.env.OPENROUTER_API_KEY = "test_openrouter_key";
	cfg = resolveConfig();
	assert.strictEqual(cfg.provider, "openrouter");
	assert.strictEqual(cfg.apiKey, "test_openrouter_key");
	assert.strictEqual(cfg.model, "typesafe/jev-1.13");

	console.log("✓ Config resolution tests passed.");
} finally {
	process.env = originalEnv;
}

console.log("\n🎉 ALL CONFIG TESTS PASSED SUCCESSFULLY!\n");
