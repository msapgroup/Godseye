# GODSEYE v4.0 — Dark Mode + Traffic Source Cards

Adds a persistent Light/Dark appearance toggle to the main GODSEYE dashboard and further refines Per-Device Traffic Collection.

## Dark mode
- Header Light/Dark toggle.
- Theme choice is stored in browser local storage.
- First visit follows the operating-system color preference.
- Dashboard, tables, forms, modals, integrations, monitoring, findings, reports, settings, and traffic collection receive dark-theme styling.
- Form controls expose the proper browser color scheme.
- Status/severity colors remain distinct.
- Login remains intentionally dark/high-contrast.

## Per-Device Traffic Collection
Each traffic source is now its own fully defined card:
- UniFi / Controller
- SNMP
- SPAN / Mirror
- Inline / Gateway

Every card shows its collection class, purpose, best-use case, setup requirement, and operational characteristic, with a stronger selected state and responsive layout.

## Accessibility
Representative dark-mode foreground/background pairs are regression-tested against WCAG contrast targets for normal and large text.
