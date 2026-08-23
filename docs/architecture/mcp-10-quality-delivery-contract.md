# MCP-10: Quality, Delivery, and Documentation Contract

**Status:** Accepted for MVP implementation
**Scope:** MCP-10.1 through MCP-10.5

## Required quality gates

| Gate | Command | Required result |
|---|---|---|
| .NET tests | `dotnet test McpSecurityScanner.slnx --configuration Release --no-restore` | All tests pass. |
| UI flow | `npm run test:ui` | All Node built-in UI-flow tests pass. |
| Coverage | `dotnet test … --collect:'XPlat Code Coverage' --results-directory TestResults` then `npm run check:coverage` | Total line coverage >= 75%. |
| Release build | `dotnet build McpSecurityScanner.slnx --configuration Release --no-restore` | Zero warnings and errors. |
| Container | `docker build --tag mcp-security-scanner:local .` then local run/health check | Root UI and invalid-URL safe response are reachable. |

The first measured coverage baseline is 78.23% total lines (1,977 covered of 2,527 valid). The gate is intentionally set to 75% for the MVP; raising it requires adding meaningful test coverage rather than weakening the scanner safety boundary.

## CI contract

`.github/workflows/ci.yml` runs on push, pull request, and manual dispatch with read-only repository permission. It restores .NET dependencies, runs coverage-collected .NET tests, enforces the coverage gate, runs native Node UI tests, performs a release build, and builds the Docker image. It does not deploy, scan external repositories, or use secrets.

## Container contract

The multi-stage Dockerfile builds only MSS source and publishes the ASP.NET API/UI. The runtime listens on port 8080 and uses the base image's non-root application user. It does not add a scanner mode that builds, starts, or otherwise executes an analyzed repository.
