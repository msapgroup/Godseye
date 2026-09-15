# GODSEYE v3.3.0 — Integration Delete Visibility Fix

Fixes the Integration Remove/Delete action not appearing for administrators after integration cards are dynamically rendered.

## Fix
- Centralized admin-only element visibility in `applyRoleVisibility()`.
- Re-applies role visibility immediately after the Integrations cards and analytics cards are rendered.
- Keeps Remove restricted to administrators.
- Preserves the v3.2 typed `REMOVE` confirmation and backend deletion/audit behavior.
