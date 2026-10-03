import * as assert from "assert";
import type { ResolvedConfig } from "../config.js";
import { evaluateWithJev } from "../evaluator.js";

console.log("=== Running Evaluator Tests (Pi 1.0.0 ModelRegistry) ===");

const baseConfig: ResolvedConfig = {
	provider: "typesafe",
	model: "jev-latest",
	threshold: 0.75,
	apiKey: "",
	blockMessage: "Blocked by Secret Guard",
};

async function runEvaluatorTests() {
	// 1. High risk probability > threshold -> block: true
	const mockHighRiskRegistry = {
		findOfType: () => ({ type: "classifier", provider: "typesafe", id: "jev-latest" }),
		classify: async () => ({
			stopReason: "stop",
			answers: {
				is_secret_reveal: { type: "bool", probability: 0.96 },
			},
		}),
	};

	let res = await evaluateWithJev(
		"python -c 'print(os.environ)'",
		baseConfig,
		{ hasUI: false, modelRegistry: mockHighRiskRegistry as any },
	);
	assert.strictEqual(res.block, true, "High risk should be blocked");
	assert.strictEqual(res.probability, 0.96);
	assert.strictEqual(res.reason, baseConfig.blockMessage);
	console.log("✓ High risk probability blocking verified.");

	// 2. Low risk probability <= threshold -> block: false
	const mockLowRiskRegistry = {
		findOfType: () => ({ type: "classifier", provider: "typesafe", id: "jev-latest" }),
		classify: async () => ({
			stopReason: "stop",
			answers: {
				is_secret_reveal: { type: "bool", probability: 0.05 },
			},
		}),
	};

	res = await evaluateWithJev(
		"python -c 'print(os.getcwd())'",
		baseConfig,
		{ hasUI: false, modelRegistry: mockLowRiskRegistry as any },
	);
	assert.strictEqual(res.block, false, "Low risk should be allowed");
	assert.strictEqual(res.probability, 0.05);
	console.log("✓ Low risk probability pass verified.");

	// 3. Provider error in non-interactive mode -> fail secure (block: true)
	const mockErrorRegistry = {
		findOfType: () => ({ type: "classifier", provider: "typesafe", id: "jev-latest" }),
		classify: async () => ({
			stopReason: "error",
			errorMessage: "Rate limit exceeded",
		}),
	};

	res = await evaluateWithJev(
		"python script.py",
		baseConfig,
		{ hasUI: false, modelRegistry: mockErrorRegistry as any },
	);
	assert.strictEqual(res.block, true, "Error in non-interactive mode should fail secure");
	assert.ok(res.error?.includes("Rate limit exceeded"));
	console.log("✓ Provider error fail-secure verified.");

	// 4. Provider error in interactive mode with user approval -> block: false, bypassedByUser: true
	const mockInteractiveUi = {
		notify: () => {},
		select: async (_prompt: string, options: string[]) => options[1], // "Allow command this time"
	};

	res = await evaluateWithJev(
		"python script.py",
		baseConfig,
		{ hasUI: true, ui: mockInteractiveUi, modelRegistry: mockErrorRegistry as any },
	);
	assert.strictEqual(res.block, false, "Interactive user bypass should allow");
	assert.strictEqual(res.bypassedByUser, true);
	console.log("✓ Interactive user bypass on failure verified.");

	// 5. Model not found in catalog
	const mockEmptyRegistry = {
		findOfType: () => undefined,
	};

	res = await evaluateWithJev(
		"python script.py",
		baseConfig,
		{ hasUI: false, modelRegistry: mockEmptyRegistry as any },
	);
	assert.strictEqual(res.block, true, "Missing model should fail secure");
	assert.ok(res.error?.includes("not in Pi's catalog"));
	console.log("✓ Model not found handling verified.");

	// 6. Custom baseUrl and apiKey passed to classify
	let capturedModel: any;
	let capturedOptions: any;
	const mockCaptureRegistry = {
		findOfType: (_t: string, p: string, id: string) => ({ type: "classifier", provider: p, id, baseUrl: "https://default" }),
		classify: async (model: any, _context: any, options: any) => {
			capturedModel = model;
			capturedOptions = options;
			return {
				stopReason: "stop",
				answers: { is_secret_reveal: { type: "bool", probability: 0.1 } },
			};
		},
	};

	const customConfig: ResolvedConfig = {
		...baseConfig,
		baseUrl: "https://custom.endpoint.com/v1",
		apiKey: "sk-custom-secret",
	};

	await evaluateWithJev(
		"python script.py",
		customConfig,
		{ hasUI: false, modelRegistry: mockCaptureRegistry as any },
	);
	assert.strictEqual(capturedModel.baseUrl, "https://custom.endpoint.com/v1", "Custom baseUrl should be honored");
	assert.strictEqual(capturedOptions.apiKey, "sk-custom-secret", "Custom apiKey should be passed");
	console.log("✓ Custom baseUrl and apiKey options verified.");

	console.log("\n🎉 ALL EVALUATOR TESTS PASSED SUCCESSFULLY!\n");
}

runEvaluatorTests().catch((err) => {
	console.error("Evaluator test failed:", err);
	process.exit(1);
});
