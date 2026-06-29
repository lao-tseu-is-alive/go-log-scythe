# Changelog

All notable changes to **GoLogScythe** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.2] - 2026-06-29

### Added
- **SIGHUP runtime reload** — The daemon now handles `syscall.SIGHUP` for zero-downtime configuration reload:
  - Reloads threat detection rules from `rules.conf` (path from `RULES_PATH`).
  - Reloads CIDR ranges from the nftables configuration file (path from `NFTABLES_CONF_PATH`) for pre-check skipping.
- New `reloadConfiguration()` function with safe atomic swap of configuration.
- `rulesMu` and `nftRangesMu` (`sync.RWMutex`) plus `getNftRanges()` helper for race-free concurrent access during reload.
- Signal handler updated to a loop that treats `SIGHUP` as reload (without cancelling the context or stopping `tailLog`).
- `loadRules()` now builds a fresh slice and swaps it under lock (prevents duplicate rules on reload and fixes latent append bug).
- `calculateScore()` now takes a quick snapshot of rules under read lock.
- `deploy/go-log-scythe.service` now includes `ExecReload=/bin/kill -s HUP $MAINPID`.

### Changed
- Startup nftables range loading uses a protected assignment.
- All hot-path reads of `rules` and `nftRanges` (in `processLine` and `filterBannableIPs`) now use safe snapshots.

### Fixed / Improved
- True "set and forget" operation: no more hourly `systemctl restart` via cron required to pick up new rules or CIDR ranges.
- Eliminates the repeated `⚠️  WARN: nft add element for X.X.X.X: exit status 1 (may already exist)` spam that happened on every restart inside `loadAndSyncBannedList`.
- Log file offset, LRU visitor cache (scores, paths, burst windows), and in-kernel + in-memory ban state are fully preserved across reloads with no perceptible interruption of monitoring.

---

## [0.4.1] - 2026-02-23

### Added
- **version flag** — `--version` flag to print version information and exit.

---

## [0.4.0] - 2026-02-20

### Added
- **Burst detection** — instant ban when an IP sends ≥ `BURST_LIMIT` (default: 5) 4xx requests within `BURST_WINDOW` (default: 3s). Catches aggressive scanners that spray many low-score paths (e.g., `eval-stdin.php` enumeration) faster than score-based detection alone.
- `BURST_LIMIT` environment variable (default: `5`) — max 4xx hits in burst window before instant ban. Set to `0` to disable burst detection.
- `BURST_WINDOW` environment variable (default: `3s`) — sliding window duration for burst counting.
- `TAIL_POLL_INTERVAL` environment variable (default: `100ms`) — configurable log file polling interval.
- `HitTimes` field on `Visitor` struct for sliding window timestamp tracking.
- **4 new tests** — `TestBurstDetection`, `TestBurstDetectionBelowLimit`, `TestBurstDetectionWindowExpiry`, `TestBurstDetectionDoesNotAffectWhitelisted`.

### Changed
- Log tail polling interval reduced from 500ms to 100ms (configurable) for 5× faster reaction to new log lines.
- `processLine()` now checks burst threshold before score threshold — burst bans fire earlier in the pipeline.

---

## [0.3.1] - 2026-02-16

### Added
- **Nftables CIDR range pre-check** — `loadNftablesRanges()` parses CIDR ranges from the nftables config file before syncing banned IPs to the kernel. IPs already covered by a broad subnet rule (e.g., `216.180.246.83` ∈ `216.180.246.0/24`) skip the `nft add element` command, avoiding redundant errors.
- **Warning for potential nftables service issues** — if a banned IP is covered by an existing nftables range, a ⚠️ warning is logged suggesting the nftables service may not be running (since traffic from that range should already be blocked).
- **`NFTABLES_CONF_PATH` environment variable** (default: `/etc/nftables.conf`) — configurable path to the nftables config file for CIDR range extraction.
- **`isIPCoveredByRanges()` helper** — returns the matching `*net.IPNet` for clean, informative warning messages.
- **6 new tests** — `TestLoadNftablesRanges`, `TestLoadNftablesRangesMultipleCIDRsPerLine`, `TestLoadNftablesRangesMissingFile`, `TestLoadNftablesRangesInvalidCIDR`, `TestIsIPCoveredByRanges`, `TestLoadAndSyncBannedListWithNftRanges`.

### Changed
- `loadAndSyncBannedList()` now accepts `[]*net.IPNet` parameter for range-aware syncing.
- CIDR regex uses `FindAllString` to capture multiple CIDRs per line (handles comma-separated nftables elements).
- Mask portion of CIDR regex limited to `/\d{1,2}` to reject nonsensical values like `/999`.

---

## [0.3.0] - 2026-02-16

### Added
- **Thread-safe LRU cache** — internal `sync.RWMutex` in `LRUCache` for correct concurrent access; the cache no longer relies on an external global lock.
- **IPv6 normalization** — new `normalizeIP()` function ensures equivalent IPv6 representations (e.g., `::1` and `0:0:0:0:0:0:0:1`) map to the same visitor/banned key.
- **Score clamping** — `maxScorePerHit` constant (20.0) prevents any single rule hit from exceeding a safe maximum, guarding against misconfigured `rules.conf`.
- **Pattern length validation** — `loadRules()` rejects regex patterns longer than 512 characters and warns when rule scores exceed the per-hit cap.
- **Preview mode cleanup** — the `banned` map is now cleared on startup when `PREVIEW_MODE=true`, so preview sessions always start with fresh threat tracking.
- **Configurable cache capacity** — new `CACHE_CAPACITY` environment variable (default: 10000) replaces the hardcoded limit.
- **8 new tests** covering concurrency (`TestLRUCacheConcurrency`, `TestProcessLineConcurrency`), IP normalization, score clamping, pattern length validation, and cache capacity.

### Changed
- Janitor goroutine no longer acquires the global mutex — it uses the cache's internal lock instead.
- Global `mu` mutex scope clarified: it now only protects the `banned` and `whitelist` maps.

### Fixed
- Potential race condition when janitor and `processLine` access the LRU cache concurrently (cache now self-synchronizes).
- IPv6 addresses in different textual forms could create duplicate visitor entries; now normalized on ingestion.
- Preview mode could accumulate stale banned IPs from a previous session's persisted file.

---

## [0.2.1] - 2026-01-20

### Added
- **Binary probe detection** — automatically detects and bans RDP, TLS, and SMB protocol probes sent to web ports (empty HTTP method → score 12.666).
- Tolerant regex using `(?s)` flag to handle binary garbage and newlines in malformed requests.
- `tryMatchWithPath()` function extracting IP, URL path, and status in a single pass.

### Changed
- Default log regex updated to a 3-group pattern (IP, path, status) supporting both normal and malformed requests.
- `processLine()` and `scanFullLog()` now use `tryMatchWithPath()` for unified parsing.

---

## [0.2.0] - 2026-01-19

### Added
- **Weighted scoring system** — configurable threat scores instead of simple request counting.
- **Externalized rules** — `rules.conf` file for defining URL pattern → score mappings.
- **Repeat penalty** — `REPEAT_PENALTY` (default 0.1) reduces score for repeated hits to the same path.
- **LRU eviction** — bounded visitor cache (`maxVisitors` = 10000) with LRU eviction policy.
- **Scan all mode** — `SCAN_ALL_MODE=true` reads the entire log file and reports findings.
- `RULES_PATH`, `BAN_THRESHOLD`, `REPEAT_PENALTY` environment variables.

### Changed
- Scoring model replaced simple hit counting with cumulative weighted scores.
- Default ban threshold changed from a count to a score-based threshold (10.0).

---

## [0.1.0] - 2026-01-16

### Added
- Initial release.
- Real-time log monitoring via `tailLog()` with truncation-based log rotation detection.
- IPv4 and IPv6 support with automatic `nftables` set selection (`parasites` / `parasites6`).
- Safety whitelisting of localhost, SSH session IP, UFW rules, and custom whitelist file.
- Persistence of banned IPs to file with kernel re-sync on startup.
- Preview mode (`PREVIEW_MODE=true`) for dry-run testing.
- Environment-driven configuration via `.env` file or system variables.
- Dual-regex fallback with `REGEX_OVERRIDE` for custom log formats.
- Comprehensive unit tests.
