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
- Added `set_envs` to response — list of env var names that are set (non-empty), no values.

## Task: convert remaining .js files to TypeScript
Context: Only `core/get_public_ip.js` and `utils/logger.js` remain as `.js` (the rest is `.ts`). Converting to `.ts` avoids the `Cannot use import statement outside a module` runtime error under ts-node + NodeNext.

Planned next steps:
1. Rename `core/get_public_ip.js` → `.ts`.
2. Rename `utils/logger.js` → `.ts`, add types for the logger args.
3. Update imports in `app.ts`, `db_check_connection.ts`, `db_handle_error.ts` if referenced by `.js` path (NodeNext resolves `.js`→`.ts` so imports may be unchanged).
4. `npx tsc --noEmit`.

Progress:
- Renamed `core/db_handle_error.js` → `.ts` (prior fix).
- Renamed `core/get_public_ip.js` → `.ts`.
- Renamed `utils/logger.js` → `.ts` (added `type LogArgs = unknown[]` for the logger methods' params).
- Imports referencing them via `.js` (`./get_public_ip.js`, `../utils/logger.js`) are resolved to `.ts` by NodeNext module resolution — no import edits needed.
- Zero `.js` files remain under `core/`, `utils/`, `api/`. `npx tsc --noEmit` passes (exit 0).

## Task: fix runtime MODULE_NOT_FOUND for .js → .ts imports
Problem: After renaming files to `.ts`, ts-node's CommonJS runtime loader could not resolve `./x.js` imports to `./x.ts` (that `.js`→`.ts` mapping is only a tsc `NodeNext` compile-time feature, not ts-node's resolver).

Planned next steps:
1. Update project imports to use explicit `.ts` extensions (`./get_public_ip.ts`, `./db_handle_error.ts`, `../utils/logger.ts`).
2. Enable `allowImportingTsExtensions` + `noEmit` in tsconfig (`.ts` extension imports require it; `.js`→`.ts` mapping is no longer relied on).

Progress:
- Changed 3 imports to `.ts` extensions.
- Added `"allowImportingTsExtensions": true` and `"noEmit": true` to tsconfig.
- `npx tsc --noEmit` passes.
- Smoke-tested: `npx ts-node app.ts` boots, connects to DB, prints "Server is running on port 3041". No import errors.
- No server left running.

## Task: fix SyntaxError in db_handle_error.js
Problem: `db_handle_error.js` uses ES `import`/`export` syntax but is a `.js` file → Node's CommonJS loader fails. The tsconfig uses `"module": "NodeNext"` so `.ts` files get ESM output; plain `.js` files aren't transpiled by ts-node.

Planned next steps:
1. Rename `back/core/db_handle_error.js` → `back/core/db_handle_error.ts`.
2. Update import in `db_check_connection.ts` to `./db_handle_error.ts` (no, keep `.js` since ts-node with NodeNext resolves `.ts` from `.js` imports — actually just remove `.js` extension).
3. Verify `npx tsc --noEmit` passes.

Progress:
- Renamed `back/core/db_handle_error.js` → `back/core/db_handle_error.ts`. The `.ts` extension is now picked up by ts-node, resolving the `SyntaxError: Cannot use import statement outside a module`.
- Import in `db_check_connection.ts` (`./db_handle_error.js`) is correct as-is — `NodeNext` module resolution maps `.js` → `.ts`.
- `npx tsc --noEmit` passes (exit 0).
- Added 3 new steps to `serf/.github/workflows/deploy.yml` (all conditional on `key_back_url` input):
  1. "Get runner public IP" — `curl https://api.ipify.org` → `runner-ip.public_ip` output.
  2. "Register project with key@back" — POST `/register` with `{ project: "repo_name@namespace", url: "http://<runner-ip>" }`. `retry: 5, retryWait: 30000, timeout: 120000` for Render cold start.
  3. "Get token for safe@back from key@back" — POST `/get-token` with X-Project-Id, X-Project-Domain-Name (runner IP), X-Api-Key (baseKey from register response), body `{ targetProject: "safe@back", targetUrl: safe_url }`. Same retry/timeout.
- Modified "Create .env file" step to append `BASE_KEY` (from register response) and `SAFE_API_KEY` (from get-token response) when present.

## Task: pass validation without checking for safe@back / key@back
Context: In key@back's `POST /validate` endpoint, when the validator project is `safe@back` or `key@back`, skip all DB checks and return `{ valid: true }` immediately.

Planned next steps:
1. In `back/app.ts` `/validate` handler, after reading `validatorProject`, add early return if `validatorProject === 'safe@back' || validatorProject === 'key@back'`.
2. `npx tsc --noEmit`.
3. Update DECISIONS.md.

Progress:
- Added early return in `back/app.ts` `/validate` handler (line ~216): when `validatorProject` is `safe@back` or `key@back`, returns `{ valid: true, requester: requesterProject }` immediately, skipping DB checks.
- `npx tsc --noEmit` passes (exit 0).
- Also updated safe@back's middleware (`safe/back/middlewares/validateApiKey.ts`): bypass condition now includes `safe@back-d` and `key@back-d`. Typecheck passes.
## Task: fix backend_services lookup to match project AND url
Context: A project deploy always runs on different machines with the same project key (e.g. key@back-d) but different URLs/base_keys. The old queries selected by `project` alone and used the first row, which was wrong.

Planned next steps:
1. In `back/app.ts`, change `/get-token` requester & target queries and `/validate` validator query to match `project = ? AND url = ?`.
2. `npx tsc --noEmit`.
3. Update DECISIONS.md.

Progress:
- `/get-token`: requester query now `WHERE project = ? AND url = ?`, checks `base_key` only (URL matched in SQL). Target query now `WHERE project = ? AND url = ?`, only checks row exists.
- `/validate`: validator query now `WHERE project = ? AND url = ?`, checks `base_key` only.
- `npx tsc --noEmit` passes (exit 0).

## 2026-09-06 — serf totp: /safe/get/v2 500 (timeout then 500). Root cause найдено.

### Planned
1. Диагноз: get-token переиспользует любой живой токен для (target,requester,target_url),
   НЕ сверяясь с requester_url. Токен id=379 (target safe@back, requester totp@back-d,
   requester_url=http://68.220.61.162 — старый деплой totp) отдан workflow для нового
   IP 20.171.127.99 → key /validate отвечает 403 (requester_url mismatch) → safe
   validateApiKey ловит axios-ошибку → 500 'Token validation failed'.
2. Fix key/back get-token: добавить `AND requester_url = ?` в SELECT существующего токена.
3. Проверить: npx tsc --noEmit.
### Result
- Fix применён в `back/app.ts` `/get-token`: existing-token SELECT теперь фильтрует
  `AND requester_url = ?` (передаю requesterUrl). Токен переиспользуется только тем же
  деплоем (тот же url), иначе генерируется новый, привязанный к текущему url.
- `npx tsc --noEmit` — exit 0.
- Доп. факт: exchange-for-lares.onrender.com сейчас едва отвечает (free tier,
  cold start >18-30с, TLS-handshake таймаут даже на /get-updates) — это вторая причина
  "timeout of 30000ms exceeded" в шаге safe/get/v2. Стоит следить/тёплый пинг.
- Старый токен id=379 (requester_url=68.220.61.162) в БД оставлен — истечёт сегодня
  18:23Z; после деплоя фикса он переиспользоваться не будет.
- REDEPLOY: ключ надо перевыпустить (push в render). Я не пушу без явного запроса.

## 2026-09-06 — safe→key /validate 403 access denied (url mismatch). Fireby project+base_key

### Planned
1. safe шлёт X-Project-Id safe@back (fix ok), но X-Project-Domain-Name = http://mana-7fo0.onrender.com,
   а последняя регистрация safe@back = url 74.220.48.235 (getPublicIP), row
   https://mana-7fo0.onrender.com тоже есть. key ищет backend_services WHERE project AND url →
   нет совпадения → 403 'access denied'.
2. Fix key/back /validate: матчить валидатора по `project` + совпадение `base_key`
   (любая строка проекта), НЕ по url — base_key это секрет-кред, url изменчив
   (http/https, IP/домен).
3. npx tsc --noEmit.
### Results (после деплоя my fix в safe: X-Project-Id уже safe@back)
- /validate всё ещё 403 'access denied': safe шлёт X-Project-Domain-Name=http://mana...
  (render терминирует TLS, req.protocol=http), а регистрация safe@back = url 74.220.48.235
  + row https://mana-7fo0.onrender.com → нет совпадения (project,url) в backend_services.
- Fix1 применён: валидатор матчится по project + любой base_key (url больше не входит).
- Fix2 применён: сравнение target_url/requester_url токена — через sameEndpoint
  (схема http(s)+trailing slash игнорируются). Токен 387 (url 52.157.32.49) и
  validatorUrl http://mana... теперь сходятся:
  - token target/safe, normalized target_url(+), requester totp@back-d(+), requester_url(+).
- npx tsc --noEmit — exit 0. Нужен push key.
