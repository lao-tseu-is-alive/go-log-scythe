# AGENTS.md — Guidance for AI Coding Agents

This file provides project-specific context for AI coding assistants (Grok, Claude Code, Cursor, Aider, etc.) working on **go-log-scythe**.

## Project Overview

GoLogScythe is a high-performance Go daemon that monitors web server logs (Nginx/Apache), scores suspicious 4xx requests using weighted rules, and bans offending IPs using nftables sets.

Key characteristics:
- Zero external Go dependencies (only stdlib + internal packages).
- Strong emphasis on security (correct path handling for exec, no PATH lookup for nft/ufw).
- Real-time tailing + one-shot scan modes.
- Runtime reload via SIGHUP.
- Burst detection + weighted scoring + safety whitelisting.

Current version (see code): 0.5.0

## Core Architecture (post-0.5.0 refactor)

- `cmd/goLogScythe/` — **Thin** entrypoint only.
  - `main()` creates a `*monitor.Monitor` and wires signals.
  - A few compatibility shims + package globals still exist **only** to support the large existing integration test file.
- `internal/` — All real logic lives here (Go `internal/` rules apply).
  - See [internal/README.md](internal/README.md) for the detailed breakdown of each package.
  - `internal/monitor` is the central orchestrator.

**Rule of thumb**: If you're adding significant behavior, it probably belongs in one of the `internal/` packages, not directly in `cmd/`.

## Important Project Rules

### 🔒 Security (Critical)
- **NEVER** copy real credentials, tokens, passwords, or keys from `.env`, config files, or logs into source code, markdown, or test data.
- Always use placeholders like `<your_db_password>`, `notes-dev-token`, or `eyJhbGci...`.
- Prefer absolute paths + validation before any `exec` or file operations involving external tools (nft, ufw, etc.).
- The project has fixed multiple SonarQube issues around `go:S4036` (untrusted PATH) and path traversal.

### 🐹 Go Idioms & Style
- Follow strict Go idiomatic conventions.
- Use `internal/` packages for private modules.
- Prefer composition over large monolithic files.
- Keep cognitive complexity low on hot paths (`processLine` / `ProcessLine`).
- All new public API surfaces on packages (especially `monitor`) should be well documented.

### Documentation & Communication
- Code comments and commit messages: English (or French — be consistent within a file). English is the default.
- For any significant change (new feature, refactor, behavior change):
  - Update `CHANGELOG.md` (use Keep a Changelog format).
  - Update `README.md` when user-facing or architectural.
- Domain identifiers are usually English.

### DRY & Structure
- Do not duplicate logic. Extract shared behavior into the appropriate internal package.
- Before writing a new function, check if an equivalent already exists.
- `Monitor` (in `internal/monitor`) is the owner of runtime state. Avoid scattering globals.

### Testing
- Run `go test -race ./...` for anything touching shared state.
- Non-root environments: tests use a fake nft script. See `init()` in `goLogScythe_test.go` and `firewall.NftPath`.
- Pure unit tests belong with their package (`internal/*/…_test.go`).
- The large test file in `cmd/goLogScythe/` contains many integration-style tests that historically relied on package-level shims. When practical, prefer constructing a local `*monitor.Monitor` and calling its exported methods.
- Add test helpers on `Monitor` (e.g. `XXXForTest()`) when needed for the transition rather than exposing internal fields.

### Environment & Configuration
- All configuration goes through `internal/config`.
- New settings should have sensible defaults and be documented in README + example `deploy/config.env`.

## Common Tasks & Gotchas

- **Changing detection logic** → Usually `internal/parser` + `internal/scoring` + `internal/monitor`.
- **Changing ban / nftables behavior** → `internal/firewall` + `monitor.executeBan` path.
- **Adding SIGHUP or lifecycle behavior** → `internal/monitor`.
- **Touching the main function** → Keep it minimal. Move logic down.
- **Legacy shims** (`processLine`, global `banned`, `conf`, etc.) — they exist for test compatibility. Do not expand their use.
- When editing `internal/monitor/monitor.go`, make sure both the exported high-level methods (`TailLog`, `ProcessLine`, ...) **and** the internal pipeline stay consistent.

## Running & Building

```bash
# Build
go build -o goLogScythe ./cmd/goLogScythe/

# Test (always with race when possible)
go test -race ./...

# Run with preview + scan (very useful)
sudo PREVIEW_MODE=true SCAN_ALL_MODE=true ./goLogScythe
```

## Agent Workflow Recommendations

1. **Understand the boundary**: `cmd/` calls `monitor.New(...)` and then uses its exported methods. Most implementation changes should happen inside `internal/`.
2. Before editing, look at `internal/README.md` + the relevant package.
3. After structural changes, always verify:
   - `go build ./cmd/goLogScythe/...`
   - `go test -race ./cmd/goLogScythe ./internal/...`
   - Update CHANGELOG + README as needed.
4. When the user asks "did you leave this half-done?", check for:
   - Duplicate methods
   - Case mismatches on receiver methods (LoadRules vs loadRules)
   - Direct field access on `*monitor.Monitor` from outside the package
   - Tests still using unqualified `NewMonitor` or lowercase methods

## Related Files

- `.claude/CLAUDE.md` (if present in your environment) — may contain additional local rules.
- `internal/README.md` — package responsibilities.
- `README.md` and `CHANGELOG.md` — user-facing and historical truth.

---

**Goal**: Keep the codebase clean, secure, testable, and easy for both humans and agents to work on. When in doubt, make the Monitor and the internal packages clearer rather than adding more glue in `cmd/`.