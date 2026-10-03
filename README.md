# pi-protect-secret

`pi-protect-secret` is a Pi Coding Agent extension that prevents the AI agent from accessing, dumping, or reading secret credentials (such as API keys, SSH private keys, auth tokens, and `.env` credentials) through the `read`, `bash`, or `powershell` tools.

Instead of relying purely on regex patterns, `pi-protect-secret` combines **zero-latency local pre-filtering** with **Pi 1.0.0's native classifier API** running **TypeSafe AI's Jev model** to accurately evaluate whether a command or script attempts to reveal sensitive credentials.

---

## Key Features

1. **Multi-Tiered Zero-Delay Protection**:
   * **Allowed Existence Checks (0ms)**: Whitelists commands that safely test whether an environment variable exists or is non-empty without printing the secret value (e.g. `[ -n "$KEY" ]`, `test -v KEY`, `Test-Path env:KEY`).
   * **Benign Dev Bypasses (0ms)**: Common development commands (`git status`, `npm test`, `cargo build`, `ls`, compiling code) bypass deep evaluation instantly.
   * **Hard Block on Direct Dumps (0ms)**: Obvious credential reads (`read('.env')`, `cat .env`, `echo $API_KEY`, `$env:SECRET`) are blocked immediately without network calls.
   * **Deep Evaluation via TypeSafe Jev**: Complex or ambiguous scripts (Python `os.environ`, PowerShell scripts, inline code) are evaluated using TypeSafe's Jev model. Commands with a probability above `0.75` are blocked.

2. **Native Pi 1.0.0 Classifier Integration**:
   * Calls TypeSafe's Jev model through Pi's native `ctx.modelRegistry.classify()` using question type `"bool"`.
   * Automatically uses your existing Pi credentials (e.g. `TYPESAFE_API_KEY`, `OPENROUTER_API_KEY`, or OpenRouter `/login` OAuth session).
   * Zero external runtime SDK dependencies.
   * Intercepts both `bash` and Windows `powershell` tools alongside `read`.

3. **Compliant Agent Warning**:
   When blocked, the tool call is halted and returns the exact prompt instruction:
   > `Do **NOT** read any credentials by yourself, ask the user and state why you would like to check the credentials.`

4. **Session Controls**:
   * Slash command `/protect-secret`: Check active status, model, threshold, and block statistics, or toggle protection on/off.
   * CLI flags: `--protect-secret-disabled` and `--protect-secret-threshold <number>`.

---

## Configuration

### API Key Resolution
The extension resolves your API key in the following priority order:
1. `~/.pi/agent/settings.json` under `"protectsecret": { "apiKey": "..." }`
2. Environment variables: `TYPESAFE_API_KEY` or `typesafe_api_key` (or `OPENROUTER_API_KEY` for OpenRouter).

### `settings.json` Configuration
You can optionally configure `pi-protect-secret` in `~/.pi/agent/settings.json`:

```json
{
  "packages": [
    "git:github.com/Yugikira/pi-protect-secret"
  ],
  "protectsecret": {
    "provider": "typesafe",
    "model": "jev-latest",
    "threshold": 0.75
  }
}
```

To use OpenRouter instead:
```json
{
  "protectsecret": {
    "provider": "openrouter",
    "model": "typesafe/jev-1.13",
    "threshold": 0.75
  }
}
```

---

## Whitelisted vs Blocked Commands

| Command | Action | Reason |
| :--- | :--- | :--- |
| `read(".env")` | ❌ **Blocked** | Sensitive file access |
| `cat .env` / `type .env` | ❌ **Blocked** | Direct secret dump |
| `echo $OPENAI_API_KEY` | ❌ **Blocked** | Direct variable print |
| `[ -n "$API_KEY" ]` | ✅ **Allowed** | Harmless existence check |
| `test -v API_KEY` | ✅ **Allowed** | Harmless existence check |
| `echo ${API_KEY:+set}` | ✅ **Allowed** | Expands to literal string "set" |
| `Test-Path env:API_KEY` | ✅ **Allowed** | PowerShell existence check |
| `[string]::IsNullOrEmpty($env:KEY)`| ✅ **Allowed** | PowerShell existence check |
| `git status` / `npm test` | ✅ **Allowed** | Benign command (0ms bypass) |
| `python -c "import os; print(os.environ['KEY'])"` | ❌ **Blocked** | Jev evaluated probability > 0.75 |

---

## Running Tests

Run the test suite:
```bash
# Heuristic & regex whitelist unit tests
npx tsx tests/heuristics.test.ts

# Configuration resolution tests
npx tsx tests/config.test.ts

# Pi extension lifecycle & mock tool integration tests
npx tsx tests/extension.test.ts

# Live TypeSafe Jev evaluation test
npx tsx tests/live-jev.test.ts
```
