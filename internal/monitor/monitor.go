package monitor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lao-tseu-is-alive/go-log-scythe/internal/cache"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/config"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/firewall"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/parser"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/safety"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/scoring"
)

// warnIpInExcludedRange is the message logged when we skip an IP because
// it is already covered by a broad nftables range.
var warnIpInExcludedRange = "⚠️  WARN: IP %s (score: %.1f) is already covered by nftables range %s — if traffic from this IP reached the server, verify that nftables service is running"

// ipStat holds an IP address and its cumulative threat score for scan results.
type ipStat struct {
	ip    string
	score float64
}

// scanStats holds aggregate statistics from scanning a log file.
type scanStats struct {
	totalLines int
	parsedOK   int
	total4xx   int
	ipScores   map[string]float64
}

// Monitor is the central orchestrator.
//
// It owns the runtime state and composes the focused internal packages.
type Monitor struct {
	conf  config.Config
	cache *cache.LRUCache

	banned    map[string]bool
	whitelist map[string]bool
	mu        sync.Mutex

	nftRanges []*net.IPNet

	rulesMu     sync.RWMutex
	nftRangesMu sync.RWMutex

	nftPath string
	ufwPath string

	reLog      *regexp.Regexp
	reOverride *regexp.Regexp

	rules []scoring.Rule

	nftDuplicateMessages []string
}

// New creates and initialises a Monitor from the given configuration.
func New(cfg config.Config) *Monitor {
	m := &Monitor{
		conf:                 cfg,
		banned:               make(map[string]bool),
		whitelist:            make(map[string]bool),
		nftRanges:            nil,
		rules:                nil,
		nftPath:              config.GetEnv("NFT_PATH", config.DefaultNftPath),
		ufwPath:              config.GetEnv("UFW_PATH", config.DefaultUfwPath),
		nftDuplicateMessages: []string{"File exists", "already exists"},
	}
	// Wire the resolved path to the firewall package so that AddIP uses the
	// same binary that was configured via NFT_PATH.
	firewall.NftPath = m.nftPath

	m.reLog = regexp.MustCompile(config.DefaultLogRegex)
	if cfg.RegexOverride != "" {
		re, err := regexp.Compile(cfg.RegexOverride)
		if err != nil {
			log.Fatalf("❌ FATAL: REGEX_OVERRIDE is invalid: %v", err)
		}
		m.reOverride = re
	}

	if cfg.RulesPath != "" {
		m.LoadRules(cfg.RulesPath)
	}

	cap := config.GetEnvInt("CACHE_CAPACITY", config.DefaultMaxVisitors)
	if cap <= 0 {
		cap = config.DefaultMaxVisitors
	}
	m.cache = cache.NewLRUCache(cap)

	safety.Load(cfg.WhitelistPath, m.ufwPath)
	safety.Populate(m.whitelist)

	return m
}

// LoadRules loads/reloads threat rules via the scoring package.
func (m *Monitor) LoadRules(path string) {
	scoring.Load(path)
	m.rulesMu.Lock()
	m.rules = scoring.GetRules()
	m.rulesMu.Unlock()
	log.Printf("📋 Loaded %d threat detection rules from %s", len(m.rules), path)
}

func (m *Monitor) loadRules(path string) {
	m.LoadRules(path)
}

// SetNftRanges replaces the current CIDR exclusion ranges.
func (m *Monitor) SetNftRanges(ranges []*net.IPNet) {
	m.nftRangesMu.Lock()
	m.nftRanges = ranges
	m.nftRangesMu.Unlock()
}

// GetNftRanges returns a copy of the current CIDR exclusion ranges.
func (m *Monitor) GetNftRanges() []*net.IPNet {
	m.nftRangesMu.RLock()
	defer m.nftRangesMu.RUnlock()
	dst := make([]*net.IPNet, len(m.nftRanges))
	copy(dst, m.nftRanges)
	return dst
}

// LoadNftablesRanges loads CIDR ranges from the given nftables.conf path.
// It delegates to the firewall package for the actual parsing.
func (m *Monitor) LoadNftablesRanges(path string) ([]*net.IPNet, error) {
	return firewall.LoadNftablesRanges(path)
}

// IsCoveredByRange reports whether ip falls inside one of the monitor's current ranges.
func (m *Monitor) IsCoveredByRange(ip net.IP) *net.IPNet {
	for _, r := range m.GetNftRanges() {
		if r.Contains(ip) {
			return r
		}
	}
	return nil
}

// isCoveredByRange is the lock-free (snapshot) version used internally when a caller already holds state.
func (m *Monitor) isCoveredByRange(ip net.IP) *net.IPNet {
	return m.IsCoveredByRange(ip)
}

// IsWhitelistedOrBanned reports (under lock) whether the IP should be ignored.
func (m *Monitor) IsWhitelistedOrBanned(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.whitelist[ip] || m.banned[ip]
}

// isWhitelistedOrBanned is a version safe to call while the caller already holds m.mu.
func (m *Monitor) isWhitelistedOrBanned(ip string) bool {
	return m.whitelist[ip] || m.banned[ip]
}

// ClearBannedForPreview empties the in-memory banned set (preview mode only).
func (m *Monitor) ClearBannedForPreview() {
	m.mu.Lock()
	m.banned = make(map[string]bool)
	m.mu.Unlock()
	log.Println("🧹 Preview mode: cleared banned map for clean tracking")
}

// Conf returns a copy of the current configuration.
func (m *Monitor) Conf() config.Config { return m.conf }

// ProcessLine is the main entry point for a single log line (real-time path).
func (m *Monitor) ProcessLine(line string) {
	if line == "" {
		return
	}

	ip, urlPath, status, ok := m.matchLogLine(line)
	if !ok {
		log.Printf("⚠️  WARN: Skipping unparseable line: %s", strings.TrimSpace(line))
		return
	}

	ip = parser.NormalizeIP(ip)

	if !strings.HasPrefix(status, "4") {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isWhitelistedOrBanned(ip) {
		return
	}

	if covered := m.isCoveredByRange(net.ParseIP(ip)); covered != nil {
		log.Printf(warnIpInExcludedRange, ip, 0.0, covered.String())
		return
	}

	score := m.calculateThreatScore(urlPath, ip, line)

	v := m.getOrCreateVisitor(ip)
	m.updateVisitor(v, urlPath, score)

	if m.shouldBanDueToBurst(v, ip) {
		return
	}

	m.cache.Put(ip, v)

	if v.Score >= m.conf.BanThreshold {
		m.executeBan(ip, v.Score)
		m.cache.Delete(ip)
	}
}

// LoadAndSyncBannedList loads previously banned IPs from disk and ensures they are present in nft sets.
func (m *Monitor) LoadAndSyncBannedList(nftRanges []*net.IPNet) {
	m.loadAndSyncBannedList(nftRanges)
}

// ScanFullLog runs a one-shot scan over an entire log file (used by --scan-all).
func (m *Monitor) ScanFullLog(path string) {
	m.scanFullLog(path)
}

// TailLog tails a log file forever (until ctx cancel) and feeds lines to ProcessLine.
func (m *Monitor) TailLog(ctx context.Context, path string) {
	m.tailLog(ctx, path)
}

// Janitor runs periodic cache cleanup until ctx is cancelled.
func (m *Monitor) Janitor(ctx context.Context) {
	m.janitor(ctx)
}

// ReloadConfiguration reloads rules + nftables CIDR ranges (SIGHUP path).
func (m *Monitor) ReloadConfiguration() {
	m.reloadConfiguration()
}

func (m *Monitor) matchLogLine(line string) (ip, urlPath, status string, ok bool) {
	// Try the override regex first; fall back to the default log regex on miss.
	// This restores the pre-refactor behaviour where REGEX_OVERRIDE was not exclusive.
	if m.reOverride != nil {
		ip, urlPath, status, ok = parser.TryMatchWithPath(m.reOverride, line)
		if ok && !parser.IsValidIP(ip) {
			log.Fatalf("❌ FATAL: REGEX_OVERRIDE extracted invalid IP: %s", ip)
		}
	}
	if !ok {
		ip, urlPath, status, ok = parser.TryMatchWithPath(m.reLog, line)
	}
	if !ok || !parser.IsValidIP(ip) {
		return "", "", "", false
	}
	return ip, urlPath, status, true
}

func (m *Monitor) calculateThreatScore(urlPath, ip, originalLine string) float64 {
	score := scoring.Calculate(urlPath)
	if score == config.VerySuspiciousBinProbesScore {
		log.Printf("⚠️ %s made a very suspicious (binary probe) request: %s",
			ip, strings.TrimSpace(originalLine))
	}
	return score
}

func (m *Monitor) getOrCreateVisitor(ip string) *cache.Visitor {
	v, exists := m.cache.Get(ip)
	if !exists {
		v = &cache.Visitor{
			IP:    ip,
			Paths: make(map[string]bool),
		}
	}
	return v
}

func (m *Monitor) updateVisitor(v *cache.Visitor, urlPath string, score float64) {
	if v.Paths[urlPath] {
		score *= m.conf.RepeatPenalty
	} else {
		v.Paths[urlPath] = true
	}
	v.Score += score
	now := time.Now()
	v.LastSeen = now

	if m.conf.BurstLimit > 0 && m.conf.BurstWindow > 0 {
		v.HitTimes = append(v.HitTimes, now)
		cutoff := now.Add(-m.conf.BurstWindow)
		trimIdx := 0
		for trimIdx < len(v.HitTimes) && v.HitTimes[trimIdx].Before(cutoff) {
			trimIdx++
		}
		if trimIdx > 0 {
			v.HitTimes = v.HitTimes[trimIdx:]
		}
	}
}

func (m *Monitor) shouldBanDueToBurst(v *cache.Visitor, ip string) bool {
	if len(v.HitTimes) < m.conf.BurstLimit {
		return false
	}
	log.Printf("⚡ BURST: %s sent %d 4xx requests in %v — triggering instant ban",
		ip, len(v.HitTimes), m.conf.BurstWindow)
	m.cache.Put(ip, v)
	m.executeBan(ip, v.Score)
	m.cache.Delete(ip)
	return true
}

func (m *Monitor) executeBan(ip string, score float64) {
	if m.conf.PreviewMode {
		log.Printf("👀 [PREVIEW] Would ban IP: %s (score: %.1f)", ip, score)
		m.banned[ip] = true
		return
	}

	parsed := net.ParseIP(ip)
	setName := m.conf.NftSetName
	if parsed != nil && parsed.To4() == nil {
		setName = m.conf.NftSetNameV6
	}

	ok, _, err := firewall.AddIP(ip, setName)
	if err != nil {
		log.Printf("❌ ERROR: Failed to ban %s: %v", ip, err)
		return
	}
	if !ok {
		return
	}

	m.banned[ip] = true
	if f, err := os.OpenFile(m.conf.BannedPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		defer f.Close()
		f.WriteString(ip + "\n")
	}
	log.Printf("🚫 BANNED: %s (set: %s)", ip, setName)
}

func (m *Monitor) addIPToNFTSet(ip, setName string) (ok, duplicate bool, err error) {
	return firewall.AddIP(ip, setName)
}

func (m *Monitor) loadAndSyncBannedList(nftRanges []*net.IPNet) {
	file, err := os.Open(m.conf.BannedPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Use the caller-supplied snapshot; fall back to the monitor's current ranges.
	// This fixes the bug where the parameter was silently ignored.
	ranges := nftRanges
	if ranges == nil {
		ranges = m.GetNftRanges()
	}

	s := bufio.NewScanner(file)
	for s.Scan() {
		ip := strings.TrimSpace(s.Text())
		if !parser.IsValidIP(ip) {
			continue
		}
		normalized := parser.NormalizeIP(ip)
		parsedIP := net.ParseIP(normalized)

		if covered := firewall.IsCoveredByRange(parsedIP, ranges); covered != nil {
			log.Printf(warnIpInExcludedRange, normalized, 0.0, covered.String())
			m.mu.Lock()
			m.banned[normalized] = true
			m.mu.Unlock()
			continue
		}

		// Mark as banned under lock, then sync to nft outside the lock so that
		// m.mu is not held during a potentially slow subprocess call.
		m.mu.Lock()
		alreadyBanned := m.banned[normalized]
		if !alreadyBanned {
			m.banned[normalized] = true
		}
		m.mu.Unlock()

		if !alreadyBanned && !m.conf.PreviewMode {
			m.syncIPToNftSet(normalized, parsedIP)
		}
	}
}

func (m *Monitor) syncIPToNftSet(normalized string, parsedIP net.IP) {
	setName := m.conf.NftSetName
	if parsedIP != nil && parsedIP.To4() == nil {
		setName = m.conf.NftSetNameV6
	}
	m.addIPToNFTSet(normalized, setName)
}

func (m *Monitor) janitor(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cache.CleanExpired(m.conf.Window)
		}
	}
}

func (m *Monitor) reloadConfiguration() {
	log.Println("📋 Reloading configuration via SIGHUP...")

	if m.conf.RulesPath != "" {
		m.LoadRules(m.conf.RulesPath)
	} else {
		m.rulesMu.Lock()
		m.rules = nil
		m.rulesMu.Unlock()
	}

	newRanges, err := m.LoadNftablesRanges(m.conf.NftablesConfPath)
	if err != nil {
		log.Printf("⚠️  WARN: Cannot reload nftables config '%s': %v", m.conf.NftablesConfPath, err)
	} else {
		m.SetNftRanges(newRanges)
		if len(newRanges) > 0 {
			log.Printf("📋 Reloaded %d CIDR ranges from %s", len(newRanges), m.conf.NftablesConfPath)
		}
	}
	log.Printf("📋 Configuration reloaded via SIGHUP (rules + CIDRs)")
}

func (m *Monitor) tailLog(ctx context.Context, path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ FATAL: Cannot open log: %v", err)
	}
	defer file.Close()

	offset, _ := file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	fmt.Printf("📖 Monitoring %s from offset %d...\n", path, offset)

	// partial holds bytes from an incomplete line returned by ReadString at EOF.
	// They are prepended to the next successful read so no log entry is lost.
	var partial string

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// Buffer any partial data; will be prepended once the rest arrives.
				if line != "" {
					partial += line
					offset += int64(len(line))
				}
				time.Sleep(m.conf.TailPollInterval)
				info, statErr := file.Stat()
				if statErr == nil && info.Size() < offset {
					fmt.Println("🔄 Log rotation detected. Resetting pointer.")
					file.Seek(0, io.SeekStart)
					offset = 0
					partial = ""
					reader.Reset(file)
				}
				continue
			}
			// Non-EOF error: log and keep the loop alive — transient errors (EINTR,
			// brief EIO) must not kill the monitoring goroutine permanently.
			log.Printf("⚠️  Read error: %v", err)
			continue
		}
		fullLine := partial + line
		partial = ""
		offset += int64(len(line))
		m.ProcessLine(strings.TrimSpace(fullLine))
	}
}

func (m *Monitor) scanFullLog(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ FATAL: Cannot open log: %v", err)
	}
	defer file.Close()

	fmt.Printf("📖 Scanning %s...\n", path)

	stats := m.scanLogScores(file)
	toBan := m.filterBannableIPs(stats.ipScores)
	m.printScanResults(stats, len(stats.ipScores), toBan)

	for _, stat := range toBan {
		if m.conf.PreviewMode {
			fmt.Printf("👀 [PREVIEW] Would ban: %s (score: %.1f)\n", stat.ip, stat.score)
		} else {
			// executeBan writes m.banned; acquire the lock as ProcessLine does.
			m.mu.Lock()
			m.executeBan(stat.ip, stat.score)
			m.mu.Unlock()
		}
	}
	if len(toBan) == 0 {
		fmt.Println("✅ No IPs exceed the ban threshold.")
	}
}

func (m *Monitor) scanLogScores(file *os.File) scanStats {
	stats := scanStats{ipScores: make(map[string]float64)}
	ipPaths := make(map[string]map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		stats.totalLines++

		ip, urlPath, status, ok := m.matchLogLine(line)
		if !ok {
			continue
		}
		ip = parser.NormalizeIP(ip)
		stats.parsedOK++

		if !strings.HasPrefix(status, "4") {
			continue
		}
		stats.total4xx++

		if ipPaths[ip] == nil {
			ipPaths[ip] = make(map[string]bool)
		}
		pathScore := scoring.Calculate(urlPath)
		if pathScore == config.VerySuspiciousBinProbesScore {
			log.Printf("⚠️ %s made a very suspicious ip request in log line: %s", ip, strings.TrimSpace(line))
		}
		if ipPaths[ip][urlPath] {
			pathScore *= m.conf.RepeatPenalty
		} else {
			ipPaths[ip][urlPath] = true
		}
		stats.ipScores[ip] += pathScore
	}
	return stats
}

func (m *Monitor) filterBannableIPs(ipScores map[string]float64) []ipStat {
	// Snapshot protected maps under lock to avoid a data race with concurrent
	// ProcessLine goroutines that write m.banned.
	m.mu.Lock()
	wl := make(map[string]bool, len(m.whitelist))
	maps.Copy(wl, m.whitelist)
	bn := make(map[string]bool, len(m.banned))
	maps.Copy(bn, m.banned)
	m.mu.Unlock()

	var toBan []ipStat
	for ip, score := range ipScores {
		if score < m.conf.BanThreshold {
			continue
		}
		if wl[ip] || bn[ip] {
			continue
		}
		if covered := m.isCoveredByRange(net.ParseIP(ip)); covered != nil {
			log.Printf(warnIpInExcludedRange, ip, score, covered.String())
			continue
		}
		toBan = append(toBan, ipStat{ip, score})
	}
	sort.Slice(toBan, func(i, j int) bool { return toBan[i].score > toBan[j].score })
	return toBan
}

func (m *Monitor) printScanResults(stats scanStats, uniqueIPs int, toBan []ipStat) {
	fmt.Println("📊 Scan Results:")
	fmt.Printf("   Total lines: %d\n", stats.totalLines)
	fmt.Printf("   Parsed OK: %d\n", stats.parsedOK)
	fmt.Printf("   4xx errors: %d\n", stats.total4xx)
	fmt.Printf("   Unique IPs with 4xx: %d\n", uniqueIPs)
	fmt.Printf("   IPs exceeding threshold (%.1f): %d\n", m.conf.BanThreshold, len(toBan))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// --- Test helpers (exported only for integration test compatibility during transition) ---

// SetConfForTest allows tests to mutate configuration on the monitor instance.
func (m *Monitor) SetConfForTest(c config.Config) { m.conf = c }

// ResetForTest clears mutable state (banned, whitelist, rules, ranges, cache).
func (m *Monitor) ResetForTest() {
	m.mu.Lock()
	m.banned = make(map[string]bool)
	m.whitelist = make(map[string]bool)
	m.mu.Unlock()

	m.rulesMu.Lock()
	m.rules = nil
	m.rulesMu.Unlock()

	m.nftRangesMu.Lock()
	m.nftRanges = nil
	m.nftRangesMu.Unlock()

	m.cache = cache.NewLRUCache(config.DefaultMaxVisitors)
}

// ClearBannedForTest only resets the banned map (used by load shim / tests to preserve other state).
func (m *Monitor) ClearBannedForTest() {
	m.mu.Lock()
	m.banned = make(map[string]bool)
	m.mu.Unlock()
}

// SyncBannedToGlobalForTest copies the internal banned set into the provided map (for legacy global checks in tests).
func (m *Monitor) SyncBannedToGlobalForTest(dst map[string]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.banned {
		dst[k] = v
	}
}

// SyncRulesToGlobalForTest copies current rules into dst (used by legacy reload shims).
func (m *Monitor) SyncRulesToGlobalForTest(dst *[]scoring.Rule) {
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	*dst = make([]scoring.Rule, len(m.rules))
	copy(*dst, m.rules)
}

// SyncNftRangesToGlobalForTest copies current nft ranges.
func (m *Monitor) SyncNftRangesToGlobalForTest(dst *[]*net.IPNet) {
	r := m.GetNftRanges()
	*dst = make([]*net.IPNet, len(r))
	copy(*dst, r)
}

// SetWhitelistForTest replaces the internal whitelist map (transition shim for legacy tests only).
func (m *Monitor) SetWhitelistForTest(w map[string]bool) {
	m.mu.Lock()
	if w == nil {
		m.whitelist = make(map[string]bool)
	} else {
		m.whitelist = w
	}
	m.mu.Unlock()
}

// CacheLenForTest exposes cache length for tests that previously reached .cache directly.
func (m *Monitor) CacheLenForTest() int {
	return m.cache.Len()
}

// CacheGetForTest exposes cache Get for tests.
func (m *Monitor) CacheGetForTest(ip string) (*cache.Visitor, bool) {
	return m.cache.Get(ip)
}

// SetBannedForTest adds an IP to the banned set (for tests that need precise banned state).
func (m *Monitor) SetBannedForTest(ip string) {
	m.mu.Lock()
	m.banned[ip] = true
	m.mu.Unlock()
}

// IsBannedForTest reports whether ip is in the banned set.
func (m *Monitor) IsBannedForTest(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.banned[ip]
}

// SetNftPathForTest overrides the nft binary path (for fake nft in tests).
func (m *Monitor) SetNftPathForTest(p string) {
	m.nftPath = p
	// Also update the firewall package var that AddIP actually reads.
	firewall.NftPath = p
}
