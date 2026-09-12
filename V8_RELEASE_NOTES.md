# GODSEYE v8 — Working Scan & Device Controls

- Fixed Scan Now workflow by replacing the filesystem trigger with a SQLite scan-request queue.
- Scanner polls the queue every second between scheduled cycles.
- Dashboard shows queued/running/completed/failed scan state.
- Added a real Add Device modal and `POST /api/v1/devices` endpoint.
- Added MAC validation and duplicate-MAC protection.
- Fixed missing `re` import used by MAC validation.
- Scanner initializes the scan-request table itself so web/scanner startup order is safe.
- Header user label is explicitly `admin` with a separate caret.
- Preserves the screenshot-matched GODSEYE UI.
