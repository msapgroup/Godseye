# GODSEYE 1.7.2 — Sidebar Router Runtime Fix

This release fixes the actual runtime cause of the dead sidebar. GODSEYE had two competing `showView` implementations. The later legacy assignment replaced the working router and called an undefined `originalShowView`, so every sidebar click failed at runtime even though JavaScript syntax checks passed.

## Fixes

- Removed the legacy `showView = function(...)` override completely.
- Kept one authoritative `showView(name, updateHash=true)` router.
- Kept delegated sidebar click handling and hash routing.
- Corrected the Devices view loader to use the current inventory renderer.
- Added regression tests that fail if `showView` is reassigned, duplicated, or references `originalShowView`.
- Added a real browser DOM interaction smoke test during release validation.
