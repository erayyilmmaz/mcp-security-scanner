# MSS-12: No-Execution CI Guard

## Objective

Keep the scanner's non-negotiable boundary continuously enforceable: MSS may read and parse bounded GitHub content, but it must never run analyzed repository code.

## Guard scope

`scripts/check-no-execution-boundary.mjs` recursively reads only MSS application source in `src/`, excluding generated `bin` and `obj` directories. It rejects these implementation primitives:

- .NET process-launch APIs (`System.Diagnostics.Process`, `Process.Start`, `ProcessStartInfo`)
- JavaScript process-launch APIs (`child_process`, `exec`, `execFile`, `spawn`, `fork`, `Deno.Command`, `Bun.spawn`)
- Git working-copy library usage (`LibGit2Sharp`)
- Explicit clone, checkout, package install/run, and MSS-external build/run command text

The script neither accepts a submitted repository URL nor accesses GitHub. It reads its own checked-out source and exits non-zero when it finds a prohibited primitive. `tests/guards/no-execution-boundary.test.mjs` proves that the current source passes and representative violations fail.

## Network contract

`GitHubRestApiClient.GitHubApiBaseAddress` owns the fixed `https://api.github.com/` base address. `CreateSecureMessageHandler()` creates an `HttpClientHandler` with `AllowAutoRedirect = false`; its unit test protects both facts. Repository input remains an identifier parsed into owner/repository components, never a fetch destination.

## CI and Docker boundary

CI runs the guard before dependency restore. The guard's scope is `src/`, so it intentionally does not reject the repository's own Docker build, local developer commands, test commands, or CI steps. Those commands package and validate MSS itself; none is derived from or applied to submitted repository content.

The guard is a focused regression tripwire, not a complete command-execution proof. Changes that introduce an indirect execution capability still require security review against the MCP-1 contract.
