# GODSEYE v4.27 clean rebuild

This branch is the clean v4.27 application rebuild line.

## Architecture boundary

- GODSEYE server/application is built and tested independently.
- Legacy embedded Windows Agent source, packages, and Windows Agent GitHub workflow are removed from this application tree.
- The future Windows Agent 2.3.0 is a separate standalone deliverable and must not be copied into the GODSEYE application repository as a release package.
- Server-side Remote Access protocol/API support remains part of GODSEYE.

## Validation target

The v4.27 application is not release-ready until its application tests pass and screenshot/Remote Access server behavior is validated against the intended protocol. Windows Agent readiness is tracked separately.
