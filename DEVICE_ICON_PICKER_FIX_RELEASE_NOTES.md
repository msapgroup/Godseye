# GODSEYE v2.7.0 — Device Icon Picker Fix

This release fixes the device icon selector so the full realistic icon library is immediately visible in the centered pop-up.

## Changes
- Adds an **All Icons** tab that opens by default.
- Shows the complete realistic icon library in the pop-up instead of only one category.
- Keeps Network Devices, Computers & Mobile, Security, Home & IoT, and Other category filters.
- Adds cache-busting to icon asset URLs so upgrades do not keep stale older icon artwork in the browser.
- Changes device icon asset responses to revalidate instead of caching for 24 hours.
- Adds image fallbacks so a missing icon never leaves a blank tile.
- Enlarges icon previews in the selector.
- Preserves the realistic Network Map from v2.6 and all prior device classification, naming, audit, sorting, and Pi-hole fixes.
