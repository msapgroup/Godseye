# GODSEYE 1.7.1 — Sidebar Navigation Fix

This maintenance release fixes sidebar navigation in the main dashboard.

## Changes

- Replaced fragile inline `onclick` navigation handlers with one delegated JavaScript click handler on the sidebar.
- Added `type="button"` to every sidebar navigation button so browser/form defaults cannot submit or swallow navigation clicks.
- Explicitly exposes `window.showView` for existing in-page actions that open another dashboard view.
- Makes view activation explicit (`display:block`) and updates `aria-hidden` / `aria-current` state.
- Adds hash-backed navigation (`#devices`, `#network`, `#tools`, etc.) so refresh/back-to-view behavior is deterministic.
- Loads the selected view's data when it opens and isolates loader failures so one broken API panel cannot disable navigation.
- Restores the selected hash view after login/boot.

This fix applies to every sidebar entry under Overview, Management, and Administration.
