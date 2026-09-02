# Decisions

## 2026-09-02
- Session started: read DECISIONS.md — did not exist yet, created now per AGENTS.md.
- Reviewed project (service-to-service token broker). Recorded review findings as todos (see current todo list). No code changes made yet.

## Task: logger object for handleDatabaseError
Planned next steps:
1. Create `back/utils/logger.js` — plain object with `log/info/warn/error` methods that `console.log` (per request, not returning responses).
2. Rework `back/core/db_handle_error.js`: accept a `logger` (instead of Express `res`) and `console.log` through it instead of `res.status().json()`.
3. Wire `back/core/db_check_connection.ts` to import and pass `logger`.
4. Typecheck (`npx tsc --noEmit` in `back/`) after changes; note results in DECISIONS.md.

## Progress
- Created `back/utils/logger.js` (`log/info/warn/error` — all `console.log`, no responses).
- `back/core/db_handle_error.js` now accepts `logger` (not `res`) and logs instead of `res.status().json()`.
- `back/core/db_check_connection.ts` imports and passes `logger`.
- `npx tsc --noEmit` passes (exit 0).

## Task: register safe@back with key@back after deploy
Context: key@back exposes `POST /register` (`{ project, url }` → `{ baseKey }`). safe@back has unused `KEY_BACK_URL` env. key@back runs on free Render.com → may sleep → need big timeout + retries.

Planned next steps (write BEFORE code):
1. Create `safe/back/core/register_with_key.js`:
   - POST to `${KEY_BACK_URL}/register` with `{ project: 'safe@back', url: process.env.SAFE_BACK_URL }` (project falls back to env `KEY_PROJECT_ID || 'safe@back'`).
   - Big per-request timeout (e.g. 120s) + retry loop (e.g. 5 attempts with growing backoff) to handle Render cold start.
   - On success: ensure `safe/back/storage/` exists (mkdir -p style), write received `baseKey` into `storage/baseKey.json` (record project, url, savedAt).
   - Log result; never throw unhandled (fire-and-forget safe).
2. Wire it into `safe/back/app.js` startup (call after `app.listen`, non-blocking so server starts immediately).
3. Add env vars to `safe/back/.env`: `KEY_PROJECT_ID=safe@back`, `SAFE_BACK_URL=` (user fills with deployed URL). Keep `KEY_BACK_URL` (points to key@back).
4. Add `storage/` to `safe/back/.gitignore` (baseKey is a secret).
5. Smoke-test locally: run the register function against local key@back (DB up) → confirm storage/baseKey.json created.

Progress:
- Added `safe/back/core/register_with_key.js` — POSTs to `${KEY_BACK_URL}/register` with `{ project: KEY_PROJECT_ID || 'safe@back', url: SAFE_BACK_URL }`; axios timeout 120s, 5 attempts with growing backoff (10/20/30/40s); on success writes `storage/baseKey.json` (table-safe, created via mkdir recursive). Returns baseKey or null; never throws.
- Wired into `safe/back/app.js` startup (import + `registerWithKeyBack()` after `app.listen`, non-blocking).
- Added env vars to `safe/back/.env`: `KEY_PROJECT_ID=safe@back`, `SAFE_BACK_URL=` (user fills after deploy). Added `storage` to `safe/back/.gitignore`.
- Smoke-tested against a mock key@back `/register`: confirmed payload `{project:'safe@back', url:...}`, storage dir auto-created, baseKey persisted. Error path also verified: ECONNREFUSED → 5 retries with growing backoff, returns null after final failure.
- Note: key@back `npm start` fails locally on Node 18 ESM/ts-node (pre-existing, unrelated). Real key@back on Render is what safe@back will hit via KEY_BACK_URL.
- No server left running (mock and any dev processes stopped).

## Task: add public_ip to key@back /get-updates
Progress:
- Imported `getPublicIP` from `core/get_public_ip.js` (already existed) into `app.ts`.
- Added `public_ip` (awaited) to `GET /get-updates` response.
- `npx tsc --noEmit` passes.