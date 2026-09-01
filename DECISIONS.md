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