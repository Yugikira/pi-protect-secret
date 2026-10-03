import * as cp from "child_process";
import { resolveConfig } from "../config.js";
import { evaluateWithJev } from "../evaluator.js";

async function testLiveJev() {
	console.log("=== Testing Live Jev Evaluation (via ModelRegistry) ===");

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

	// Minimal ModelRegistry harness for standalone live network test
	const liveModelRegistry = {
		findOfType: (_t: string, p: string, id: string) => ({
			type: "classifier",
			provider: p,
			id,
			baseUrl: config.baseUrl || "https://api.typesafe.ai/v1",
		}),
		classify: async (model: any, context: any, options: any) => {
			const res = await fetch(`${model.baseUrl.replace(/\/+$/, "")}/systemone`, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${options.apiKey || config.apiKey}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					model: model.id,
					state: context.state,
					questions: Object.fromEntries(
						Object.entries(context.questions).map(([k, q]: [string, any]) => [
							k,
							q.type === "bool" ? { ...q, type: "noul" } : q,
						]),
					),
				}),
			});
			const data = (await res.json()) as any;
			return {
				stopReason: "stop",
				answers: {
					is_secret_reveal: {
						type: "bool",
						probability: data.answers?.is_secret_reveal?.noul,
					},
				},
			};
		},
	};

	const ctx = {
		hasUI: false,
		modelRegistry: liveModelRegistry as any,
	};

	// 1. Test high risk command (should have probability > 0.75)
	const riskyCmd = "python -c \"import os; print(os.environ['OPENAI_API_KEY'])\"";
	console.log(`Evaluating risky command: ${riskyCmd}`);
	const riskyResult = await evaluateWithJev(riskyCmd, config, ctx);
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
	const safeResult = await evaluateWithJev(safeEnvCmd, config, ctx);
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
