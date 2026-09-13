# GODSEYE v4.9 — Admin Card Layouts

- Adds an admin-only **Arrange Cards** control to dashboard pages with movable card groups.
- Cards can be dragged horizontally or vertically within their page section.
- Layouts are stored in SQLite and apply globally, so the administrator controls the appliance layout rather than only one browser.
- Changes auto-save and are audited as `ui_layout_saved`.
- Per-page Reset restores the GODSEYE default order.
- Supports dashboard stat cards, Monitoring summaries, Network Tools, report cards, traffic source cards, integrations/analytics, notifications, map summaries and other card grids.
- Standalone Network Tools also supports admin arrangement.
- Non-admin users can see the saved layout but cannot change it.
