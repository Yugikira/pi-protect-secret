# Implementation Plan: `pi-protect-secret` Extension

## 1. Overview & Objective
`pi-protect-secret` is a Pi Coding Agent extension designed to prevent the agent from reading secret credentials (such as API keys, SSH private keys, tokens, and `.env` credentials) through the `read` or `bash` tools.

Instead of relying solely on regex, the extension uses a multi-tiered pipeline:
1. Fast-path whitelist for safe environment variable existence checks (zero latency).
2. Regex suspicion pre-filter on command lines, arguments, and local script files (zero latency for benign commands like `git status`, `npm test`, `cargo build`).
3. Fast-path hard-block for obvious direct credential dumps (`cat .env`, `echo $API_KEY`, etc.).
4. TypeSafe AI's Jev model evaluation (`noul` primitive) via TypeSafe direct API or OpenRouter Decisions API with a probability threshold (default: `0.75`).
5. Fail-safe user prompt via UI if the evaluation service is temporarily unavailable.

When blocked, the tool execution is halted and returns the required instruction to the agent:
> `Do **NOT** read any credentials by yourself, ask the user and state why you would like to check the credentials.`

---

## 2. Multi-Tiered Evaluation Pipeline

```
[Tool Call: read or bash]
       │
       ▼
[Stage 1: Session Status Check]
Is protection disabled via flag (--protect-secret-disabled) or /protect-secret command?
   ├── Yes ──► [Allow]
   └── No  ──► Proceed
       │
       ▼
[Stage 2: Fast-Path Whitelist (0ms)]
Is it an allowed existence check?
   • Bash: `[ -n "$VAR" ]`, `[ -z "$VAR" ]`, `test -n "$VAR"`, `test -z "$VAR"`,
           `test -v VAR`, `[[ -v VAR ]]`, `${VAR:+exists}`, `printenv VAR >/dev/null`
   • PowerShell: `Test-Path env:VAR`, `[bool]$env:VAR`, `[string]::IsNullOrEmpty($env:VAR)`
   ├── Yes ──► [Allow Immediately]
   └── No  ──► Proceed
       │
       ▼
[Stage 3: Regex Suspicion Filter (0ms)]
Does the command, inline script, or target script file on disk mention:
   • Secret files: `.env`, `.env.*`, `credentials`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `.netrc`, `.npmrc`
   • Sensitive environment variables: `*KEY*`, `*SECRET*`, `*TOKEN*`, `*AUTH*`, `*PASS*`, `*CRED*`
   • Credential access APIs: `os.environ`, `os.getenv`, `process.env`, `Get-ChildItem env:`, etc.
   ├── No (e.g. `git status`, `npm test`, `cargo build`, pure logic scripts) ──► [Allow Immediately]
   └── Yes ──► Proceed
       │
       ▼
[Stage 4: Fast-Path Hard Block (0ms)]
Is it an obvious direct secret dump (e.g. `read('.env')`, `cat .env`, `echo $API_KEY`, `$env:SECRET`)?
   ├── Yes ──► [Block Immediately & Warn]
   └── No  ──► Proceed to Jev
       │
       ▼
[Stage 5: Jev Model Evaluation (TypeSafe / OpenRouter)]
Send `noul` question to Jev:
"Does this command or file read attempt to access, print, reveal, extract, or dump secret credentials, private keys, API keys, passwords, authentication tokens, or sensitive contents from environment variables or .env files to stdout or file, rather than merely verifying whether a variable exists?"
   ├── Probability > 0.75 (or configured threshold) ──► [Block & Warn]
   ├── Probability ≤ 0.75                            ──► [Allow]
   └── API Error / Timeout:
          ├── Interactive Mode (UI available) ──► Prompt user: [Allow / Block]
          └── Non-Interactive Mode             ──► Fail secure [Block & Warn]
```

---

## 3. Configuration & API Key Resolution

### Provider Selection
* If specified in `settings.json` under `"protectsecret": { "provider": "typesafe" | "openrouter" }`, use that provider.
* Otherwise auto-detect:
  * If `TYPESAFE_API_KEY` / `typesafe_api_key` is present $\rightarrow$ `typesafe` (model: `jev-latest`)
  * Else if `OPENROUTER_API_KEY` / `openrouter_api_key` is present $\rightarrow$ `openrouter` (model: `typesafe/jev-1.13`)

### API Key Resolution
* **Priority 1**: `~/.pi/agent/settings.json` $\rightarrow$ `protectsecret.apiKey`
* **Priority 2**: Environment variables (`process.env.TYPESAFE_API_KEY`, `process.env.typesafe_api_key`, `process.env.OPENROUTER_API_KEY`, `process.env.openrouter_api_key`)

### Supported `settings.json` Structure
```json
{
  "protectsecret": {
    "provider": "typesafe",
    "apiKey": "ts_...",
    "model": "jev-latest",
    "threshold": 0.75,
    "baseUrl": "https://api.typesafe.ai"
  }
}
```

---

## 4. Architecture & File Structure

* `package.json`: Extension package descriptor declaring `@typesafe-ai/sdk` and Pi entry point `"pi": { "extensions": ["./index.ts"] }`.
* `config.ts`: Configuration loader resolving settings from `settings.json`, environment variables, CLI flags, and defaults.
* `heuristics.ts`:
  * Existence-check whitelist matcher.
  * Regex suspicion detector (command string + script file content inspector).
  * Fast-path hard-block rules.
* `evaluator.ts`:
  * Jev System One client supporting both TypeSafe direct API (`/v1/systemone`) and OpenRouter Decisions API (`/api/alpha/decisions`).
  * Fallback handler: prompts user in interactive mode if API fails; blocks in non-interactive mode.
* `index.ts`:
  * Pi lifecycle event listener for `tool_call` (`read` and `bash`).
  * Slash command `/protect-secret` (displays stats and allows runtime toggle).
  * CLI flags `--protect-secret-disabled` and `--protect-secret-threshold <val>`.
  * Status line widget in terminal UI.

---

## 5. Implementation Steps

1. Create `package.json` with dependencies and Pi extension configuration.
2. Install npm dependencies (`@typesafe-ai/sdk`).
3. Implement `config.ts` (loading settings, env vars, provider selection, thresholds).
4. Implement `heuristics.ts` (whitelist, suspicion scanner, script file inspector, hard blocks).
5. Implement `evaluator.ts` (TypeSafe + OpenRouter decisions client, prompt & criteria, UI fallback).
6. Implement `index.ts` (Pi extension entry point, tool interception, UI notifications, commands & flags).
7. Add comprehensive unit/integration test scripts to verify:
   * Safe existence checks pass through (`[ -n "$FOO" ]`, `Test-Path env:FOO`).
   * Benign commands pass through without delay (`git status`, `npm test`).
   * Direct credential reads are blocked instantly (`cat .env`, `echo $API_KEY`).
   * Suspicious scripts and commands are evaluated by Jev correctly.
8. Verify extension loading with `pi --extension ./index.ts` or standalone tests.
