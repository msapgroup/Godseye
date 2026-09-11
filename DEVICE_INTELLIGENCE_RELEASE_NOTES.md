# GODSEYE v11 — Device Intelligence Block

This block connects device inventory, discovery evidence, history, diagnostics, and findings into a device-centric workflow.

## Added
- Device intelligence API and modal UI
- Device identity summary and risk score
- Discovery-source evidence display
- IP history display
- Recent event timeline
- Device-specific open findings
- Explainable recommendations
- One-click live diagnostics
- Administrator recheck action
- Scanner-to-intelligence correlation for ARP observations
- Manual-device source correlation
- Clickable Device Inventory rows/details

## Also fixed
- Corrected a JavaScript syntax error in the dashboard escape helper (`const esc=s=>...`) that could prevent dashboard button handlers from loading in a browser.

## Device APIs
- `GET /api/v1/devices/{id}`
- `GET /api/v1/devices/{id}/intelligence`
- `POST /api/v1/devices/{id}/diagnose`
- `POST /api/v1/devices/{id}/recheck`

The device intelligence is evidence-based. It reports what GODSEYE has actually observed and gives deterministic recommendations rather than inventing topology or device facts.
