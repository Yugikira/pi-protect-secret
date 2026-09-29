import * as cp from "child_process";
import { resolveConfig } from "../config.js";
import { evaluateWithJev } from "../evaluator.js";

async function testLiveJev() {
	console.log("=== Testing Live Jev Evaluation ===");

	// If TYPESAFE_API_KEY is not in process.env, check if it's available via pwsh
	if (!process.env.TYPESAFE_API_KEY && !process.env.typesafe_api_key) {
		try {
			const pwshKey = cp
				.execSync('pwsh -NoLogo -Command "Write-Output $env:typesafe_api_key"', {
					encoding: "utf-8",
					timeout: 5000,
				})
				.trim();
			if (pwshKey) {
				process.env.typesafe_api_key = pwshKey;
				console.log("Loaded typesafe_api_key from PowerShell profile for this live test.");
			}
		} catch {
			// ignore
		}
	}

	const config = resolveConfig();
	if (!config.apiKey) {
		console.log("⚠️ No API key found. Skipping live API test.");
		return;
	}

	console.log(`Using provider: ${config.provider}, model: ${config.model}`);

	// 1. Test high risk command (should have probability > 0.75)
	const riskyCmd = "python -c \"import os; print(os.environ['OPENAI_API_KEY'])\"";
	console.log(`Evaluating risky command: ${riskyCmd}`);
	const riskyResult = await evaluateWithJev(riskyCmd, config);
	console.log(`Risky command result:`, {
		block: riskyResult.block,
		probability: riskyResult.probability,
	});

	if (!riskyResult.probability) {
		console.log("Risky result error:", riskyResult.error);
	}

	// 2. Test benign command that contains the word "env" but doesn't dump secrets
	const safeEnvCmd = "python -c \"import os; print('Current working dir is:', os.getcwd())\"";
	console.log(`\nEvaluating safe command: ${safeEnvCmd}`);
	const safeResult = await evaluateWithJev(safeEnvCmd, config);
	console.log(`Safe command result:`, {
		block: safeResult.block,
		probability: safeResult.probability,
	});

	if (safeResult.probability !== undefined) {
		console.log(`✓ Jev evaluated safe command risk probability: ${safeResult.probability}`);
		if (!safeResult.block) {
			console.log(`✓ Correctly allowed safe command (probability <= ${config.threshold}).`);
		}
	}

	console.log("\n🎉 Live Jev test completed successfully!");
}

testLiveJev().catch((err) => {
	console.error("Live Jev test error:", err);
});
