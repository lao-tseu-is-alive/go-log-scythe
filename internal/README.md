# internal/ — Private Packages

This directory contains the **core implementation** of GoLogScythe. These packages are **internal** (Go's `internal/` mechanism prevents import from outside the module tree).

The design philosophy is:

- Keep `cmd/goLogScythe` as a **thin entrypoint**.
- Put all real logic, state, and algorithms in focused packages under `internal/`.
- Make the system easier to test, reason about, and evolve.

## Package Overview

| Package       | Responsibility                                                                 | Key Types / Functions                  |
|---------------|--------------------------------------------------------------------------------|----------------------------------------|
| `config`      | All environment variable handling, defaults, and typed getters.                | `Config`, `Load()`, `GetEnv*()`        |
| `parser`      | Log line parsing and IP normalization.                                         | `TryMatchWithPath()`, `NormalizeIP()`, `IsValidIP()` |
| `scoring`     | Loading `rules.conf` and calculating weighted threat scores.                   | `Load()`, `Calculate()`, `Rule`, `GetRules()` |
| `cache`       | Thread-safe LRU cache for tracking visitors (scores, paths seen, burst times). | `LRUCache`, `Visitor`                  |
| `firewall`    | Interactions with nftables (adding IPs to sets, parsing CIDR ranges).          | `AddIP()`, `LoadNftablesRanges()`, `IsCoveredByRange()` |
| `safety`      | Loading and populating the whitelist (SSH session IP + existing UFW rules).    | `Load()`, `Populate()`, `IsWhitelisted()` |
| `monitor`     | **The heart of the application.** Owns runtime state and orchestrates everything. | `Monitor`, `New()`, `ProcessLine()`, `TailLog()`, `ScanFullLog()`, `Janitor()`, `ReloadConfiguration()`, `LoadAndSyncBannedList()` |

## The Monitor Package

`internal/monitor` is special:

- It composes all the other packages.
- `Monitor` is the single source of truth for configuration, caches, banned/whitelist maps, nft ranges, and rules.
- The main detection logic (`ProcessLine`) lives here as a clean pipeline with small helper methods.
- It also implements the long-running behaviors: tailing logs, periodic cleanup, full scans, and SIGHUP reload.

## Usage from cmd/

The only code that should normally talk to these packages is:

- `cmd/goLogScythe/goLogScythe.go` (mainly just `monitor.New(config.Load())` + wiring signals and calling high-level methods).
- Tests (which are allowed to construct `monitor.Monitor` directly for unit-style testing).

During the transition some lightweight shims and package-level globals still exist in `cmd/` to keep the large integration test file working. New code should prefer creating a `*monitor.Monitor` and using its exported methods.

## Testing Notes

- Most packages have (or should have) their own `_test.go` files for pure unit tests.
- Integration-style tests that exercise the full pipeline often live in `cmd/goLogScythe/goLogScythe_test.go`.
- Non-root tests use a fake `nft` script (see `init()` in the test file and `firewall.NftPath`).
- Always run with `-race` when changing anything that touches shared state (`Monitor`, cache, etc.).

## Adding New Code

- New domain logic → usually a new small package or an extension of an existing one (`parser`, `scoring`, etc.).
- New orchestration behavior → almost always belongs in `monitor`.
- Avoid putting significant logic directly in `cmd/goLogScythe/`.

See also the root `AGENTS.md` for broader guidance when working with AI coding agents.