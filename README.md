# Make AI Model Manager

A tiny local web app to **scan and bulk-update AI model versions** (Claude, Gemini) across all your Make.com scenarios. No more opening 47 scenarios one-by-one to change `claude-3-5-sonnet` to `claude-sonnet-4-6`.

- Zero dependencies — pure Node.js (uses only stdlib).
- One JS file + one JSON config. Move the folder, it moves with you.
- Uses the official Make.com API — no browser automation, no scraping.

## What it does

1. **Connects** to your Make.com account with your API token.
2. **Scans** every scenario in the selected organization. For each AI module it finds, it checks whether the model ID matches one of your rules.
3. **Shows** you exactly which scenarios + modules need an update.
4. **Patches** them in bulk, in one click. Full blueprint PATCH — all your other settings stay intact.

### Supported rule shape

Each rule has one or more `from` patterns (regex, case-insensitive) and a single `to` target. Example:

```json
{
  "from": ["^claude-opus"],
  "to": "claude-opus-4-7",
  "toLabel": "Claude Opus 4.7"
}
```

This sweeps any model starting with `claude-opus` (e.g. `claude-opus-4-1-20250805`, `claude-opus-4-5-20251101`) to `claude-opus-4-7`.

Default rules ship for Claude Opus / Sonnet / Haiku and Gemini Pro / Flash. Add your own via the UI.

## Setup

**Prereq:** Node.js 18+.

```bash
git clone https://github.com/arielmoatti/make-ai-model-manager.git
cd make-ai-model-manager
npm start
```

Open http://localhost:3000. You'll be prompted to paste your **Make.com API token** — create one at `https://<your-zone>.make.com/users/me/api` (needs `scenarios:read` and `scenarios:write`). It's stored locally in `make-ai-model-manager.secret.json` next to the script and never leaves your machine.

### Custom port

```bash
node make-ai-model-manager.js --port=8080
```

## Files

| File | Purpose | Gitignored |
|------|---------|------------|
| `make-ai-model-manager.js` | The entire app (server + embedded HTML + client JS) | no |
| `make-ai-model-manager.json` | Your rules + last-used org/team | no (ships with defaults) |
| `make-ai-model-manager.secret.json` | Your API token | **yes** |

## Safety notes

- The app **validates** the token against Make.com on save — bad tokens are rejected before they're stored.
- Every PATCH goes to `/api/v2/scenarios/{id}` with the full blueprint. Make.com refuses the PATCH if the blueprint references deleted connections or webhooks — so broken scenarios are surfaced, not silently corrupted.
- Rate limits are respected: exponential backoff (0 / 1.5s / 4s / 10s / 25s), honors `Retry-After` headers, paces 400ms between scenarios.
- Pre-existing broken scenarios (dangling connection/hook references) will fail with a clear error — not caused by this tool.

## Screenshots

_(add when published)_

## License

MIT — see [LICENSE](LICENSE).
