# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-03

### Added
- Native Pi 1.0.0 classifier model support via `ctx.modelRegistry.classify()` with question type `"bool"`.
- Support for intercepting Windows built-in `powershell` tool alongside `bash`.
- Comprehensive PowerShell protection: hardened heuristics against native PowerShell credential access (`[Environment]::GetEnvironmentVariables()`, `Get-Content env:`, `gci env:`, `dir env:`, `ls env:`, `Get-Variable`).
- Added dedicated unit test suite in `tests/evaluator.test.ts` verifying classifier risk thresholds, error handling, interactive bypass, and custom `baseUrl`/`apiKey` options.
- Added `powershell` test coverage in `tests/extension.test.ts` for safe commands, whitelisted existence checks, and hard-blocked credential dumps.
- Declared `@earendil-works/pi-coding-agent` and `@earendil-works/pi-ai` in `peerDependencies` per Pi 1.0.0 package guidelines.

### Changed
- Simplified `evaluator.ts` into a lightweight, native wrapper around `ctx.modelRegistry.classify()`, completely removing legacy HTTP fallback logic and custom wire translations.
- Streamlined authentication & provider auto-detection: automatically checks Pi's credential store via `ctx.modelRegistry.getProviderAuthStatus()`, enabling OpenRouter `/login` OAuth sessions to work seamlessly with zero manual configuration.
- Honored custom `protectsecret.baseUrl` on the primary classifier path.
- Fixed regex trailing word boundary `\b` bug in segment inspection for colon-terminated commands (`dir env:`, `ls env:`).
- Updated default base URLs to v1 endpoints (`https://api.typesafe.ai/v1` and `https://openrouter.ai/api/v1`).
- Upgraded TypeScript declarations to use official `@earendil-works/pi-coding-agent` and `@earendil-works/pi-ai` types in `devDependencies`.

### Removed
- Removed runtime dependency on `@typesafe-ai/sdk`.
- Removed handwritten and partial `pi-agent.d.ts` declaration file in favor of official package types.

---

## [0.1.0] - 2026-09-29

### Added
- Initial release of `pi-protect-secret` extension for Pi coding agent.
- Multi-stage credential leak prevention:
  - 0ms sensitive file path detection for `read` tool (`.env`, private keys, credential JSON files).
  - 0ms anchored existence check whitelist (`[ -n "$KEY" ]`, `Test-Path env:KEY`).
  - 0ms heuristic suspicion scanning for shell commands and referenced scripts.
  - 0ms hard-block floor for obvious direct credential dumps (`cat .env`, `echo $API_KEY`, etc.).
  - Deep risk evaluation using TypeSafe Jev System One model.
- `/protect-secret` slash command for session stats, inspection, and runtime toggling.
- CLI flags `--protect-secret-disabled` and `--protect-secret-threshold`.
- Safe interactive bypass confirmation dialog and fail-closed non-interactive fallback.
