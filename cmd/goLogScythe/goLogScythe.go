/*
Package main implements a high-performance log monitor for 404 like http scans,
then it allows you to ban ip doing too much 404 using nftables.
It features environment-driven configuration, dual-regex fallback,
and a safety-first preview mode.
*/
package main

import (
	"bufio"
	"container/list"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// --- Default Constants ---
const (
	APP                          = "goLogScythe"
	AppSnake                     = "go-log-scythe"
	VERSION                      = "0.4.0"
	REPOSITORY                   = "https://github.com/lao-tseu-is-alive/go-log-scythe"
	defaultLogPath               = "/var/log/nginx/access.log"
	defaultWhitelistPath         = "./whitelist.txt"
	defaultBannedPath            = "banned_ips.txt"
	defaultRulesPath             = ""   // Empty means no rules file (backward compatible)
	defaultThreshold             = 10.0 // Score threshold for banning
	defaultRepeatPenalty         = 0.1  // 10% of full score for repeat path hits
	defaultWindow                = 15 * time.Minute
	defaultNftSet                = "parasites"
	defaultNftSetV6              = "parasites6"
	defaultNftConf               = "nftables.conf"
	defaultMaxVisitors           = 10000                  // Maximum visitors to track before eviction
	defaultBurstLimit            = 5                      // Max 4xx hits in burst window before instant ban
	defaultBurstWindow           = 3 * time.Second        // Sliding window for burst counting
	defaultTailPollInterval      = 100 * time.Millisecond // Poll interval for tail -f style monitoring
	VerySuspiciousBinProbesScore = 12.666
	maxScorePerHit               = 20.0 // Maximum score any single hit can contribute
	maxPatternLength             = 512  // Maximum regex pattern length in rules.conf
	// Combined Log Format Regex (works for both Nginx and Apache)
	// Uses (?s) to handle binary garbage/newlines in malformed requests
	// Matches: 1.2.3.4 - - [Date] \"METHOD /path HTTP/x.x\" 404 ...
	// OR malformed: 1.2.3.4 - - [Date] \"<binary garbage>\" 400 ...
	// Group 1: IP, Group 2: URL path (may be empty for malformed), Group 3: Status code
	// Two-stage: try to extract path, fallback to just IP/status for binary probes
	defaultLogRegex       = `(?s)^(\S+)\s+-\s+-\s+\[.*?\]\s+"(?:\S+\s+(\S*)\s+.*?|.*?)"\s+(\d{3})`
	warnIpInExcludedRange = "⚠️  WARN: IP %s (score: %.1f) is already covered by nftables range %s — if traffic from this IP reached the server, verify that nftables service is running"
	msgFuncNReturnedError = "%v returned error: %v"
)

var defaultNftablesConfPath = filepath.Join("/etc/", defaultNftConf)

// Rule represents a threat detection rule with a score and regex pattern
type Rule struct {
	Score   float64
	Pattern *regexp.Regexp
	Raw     string // Original pattern string for logging
}

type Config struct {
	LogPath          string
	WhitelistPath    string
	BannedPath       string
	RulesPath        string  // Path to rules.conf file
	NftablesConfPath string  // Path to nftables.conf for CIDR range checking
	BanThreshold     float64 // Score threshold for banning (default: 10.0)
	RepeatPenalty    float64 // Score multiplier for repeat path hits (default: 0.1)
	Window           time.Duration
	NftSetName       string
	NftSetNameV6     string
	RegexOverride    string
	BurstLimit       int           // Max 4xx hits in burst window before instant ban (default: 5)
	BurstWindow      time.Duration // Sliding window for burst counting (default: 3s)
	TailPollInterval time.Duration // Poll interval for tail -f style monitoring (default: 100ms)
	PreviewMode      bool
	ScanAllMode      bool
}

type Visitor struct {
	IP       string
	Score    float64         // Cumulative danger score
	Paths    map[string]bool // Track distinct paths for repeat penalty
	HitTimes []time.Time     // Sliding window of recent 4xx hit timestamps for burst detection
	LastSeen time.Time
}

// LRUCache is a thread-safe bounded cache with LRU eviction policy.
// It uses an internal RWMutex: reads (Get) use RLock, writes (Put/Delete/CleanExpired) use full Lock.
type LRUCache struct {
	mu       sync.RWMutex
	capacity int
	items    map[string]*list.Element
	order    *list.List // Front = most recently used
}

// NewLRUCache creates a new LRU cache with the given capacity
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		order:    list.New(),
	}
}

// Get retrieves a visitor from the cache and marks it as recently used.
// Note: MoveToFront is a write operation on the list, so we use a full Lock here.
func (c *LRUCache) Get(ip string) (*Visitor, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[ip]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(*Visitor), true
	}
	return nil, false
}

// Put adds or updates a visitor in the cache
func (c *LRUCache) Put(ip string, visitor *Visitor) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[ip]; ok {
		c.order.MoveToFront(elem)
		elem.Value = visitor
		return
	}

	// Evict oldest if at capacity
	if c.order.Len() >= c.capacity {
		c.evictOldest()
	}

	elem := c.order.PushFront(visitor)
	c.items[ip] = elem
}

// Delete removes a visitor from the cache
func (c *LRUCache) Delete(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[ip]; ok {
		c.order.Remove(elem)
		delete(c.items, ip)
	}
}

// evictOldest removes the least recently used item
func (c *LRUCache) evictOldest() {
	if elem := c.order.Back(); elem != nil {
		visitor := elem.Value.(*Visitor)
		c.order.Remove(elem)
		delete(c.items, visitor.IP)
	}
}

// Len returns the number of items in the cache
func (c *LRUCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.order.Len()
}

// CleanExpired removes entries older than the given window
func (c *LRUCache) CleanExpired(window time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	now := time.Now()

	// Iterate from back (oldest) to front
	for elem := c.order.Back(); elem != nil; {
		visitor := elem.Value.(*Visitor)
		prev := elem.Prev()
		if now.Sub(visitor.LastSeen) > window {
			c.order.Remove(elem)
			delete(c.items, visitor.IP)
			removed++
		}
		elem = prev
	}
	return removed
}

var (
	conf         Config
	visitorCache *LRUCache
	banned       = make(map[string]bool)
	whitelist    = make(map[string]bool)
	mu           sync.Mutex   // Protects banned and whitelist maps
	nftRanges    []*net.IPNet // Loaded nftables CIDR ranges for pre-check

	reLog      *regexp.Regexp
	reOverride *regexp.Regexp
	rules      []Rule // Loaded threat detection rules
)

func init() {
	// Initialize configuration from Environment Variables
	conf = Config{
		LogPath:          getEnv("LOG_PATH", defaultLogPath),
		WhitelistPath:    getEnv("WHITE_LIST_PATH", defaultWhitelistPath),
		BannedPath:       getEnv("BANNED_FILE_PATH", defaultBannedPath),
		RulesPath:        getEnv("RULES_PATH", defaultRulesPath),
		BanThreshold:     getEnvFloat("BAN_THRESHOLD", defaultThreshold),
		RepeatPenalty:    getEnvFloat("REPEAT_PENALTY", defaultRepeatPenalty),
		Window:           getEnvDuration("BAN_WINDOW", defaultWindow),
		NftSetName:       getEnv("NFT_SET_NAME", defaultNftSet),
		NftSetNameV6:     getEnv("NFT_SET_NAME_V6", defaultNftSetV6),
		NftablesConfPath: getEnv("NFTABLES_CONF_PATH", defaultNftablesConfPath),
		RegexOverride:    os.Getenv("REGEX_OVERRIDE"),
		BurstLimit:       getEnvInt("BURST_LIMIT", defaultBurstLimit),
		BurstWindow:      getEnvDuration("BURST_WINDOW", defaultBurstWindow),
		TailPollInterval: getEnvDuration("TAIL_POLL_INTERVAL", defaultTailPollInterval),
		PreviewMode:      getEnvBool("PREVIEW_MODE", false),
		ScanAllMode:      getEnvBool("SCAN_ALL_MODE", false),
	}

	// Pre-compile Regex
	reLog = regexp.MustCompile(defaultLogRegex)

	if conf.RegexOverride != "" {
		var err error
		reOverride, err = regexp.Compile(conf.RegexOverride)
		if err != nil {
			log.Fatalf("❌ FATAL: REGEX_OVERRIDE is invalid: %v", err)
		}
	}

	// Load threat detection rules if configured
	if conf.RulesPath != "" {
		loadRules(conf.RulesPath)
	}

	// Initialize LRU cache for visitor tracking (capacity configurable via env)
	cacheCapacity := getEnvInt("CACHE_CAPACITY", defaultMaxVisitors)
	if cacheCapacity <= 0 {
		cacheCapacity = defaultMaxVisitors
	}
	visitorCache = NewLRUCache(cacheCapacity)
}

// tailLog monitors the log file for new lines and processes them.
// Note on log rotation: This detects truncation-based rotation (copytruncate),
// which is the most common method for nginx/logrotate. Rename-style rotation
// (mv + create) is NOT detected and would require fsnotify (external dep).
func tailLog(ctx context.Context, path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ FATAL: Cannot open log: %v", err)
	}
	defer file.Close()

	// Start at the end of the file
	offset, _ := file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	fmt.Printf("📖 Monitoring %s from offset %d...\n", path, offset)

	for {
		// Check for shutdown
		select {
		case <-ctx.Done():
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// Wait for new data
				time.Sleep(conf.TailPollInterval)

				// Check for truncation (log rotation)
				stats, _ := file.Stat()
				if stats.Size() < offset {
					fmt.Println("🔄 Log rotation detected. Resetting pointer.")
					file.Seek(0, io.SeekStart)
					offset = 0
					reader.Reset(file)
				}
				continue
			}
			log.Printf("⚠️  Read error: %v", err)
			break
		}

		offset += int64(len(line))
		processLine(strings.TrimSpace(line))
	}
}

// matchLogLine tries override regex first, then the default log regex.
// Returns the parsed IP, URL path, status code, and whether matching succeeded.
func matchLogLine(line string) (ip, urlPath, status string, ok bool) {
	if reOverride != nil {
		ip, urlPath, status, ok = tryMatchWithPath(reOverride, line)
		if ok && !isValidIP(ip) {
			log.Fatalf("❌ FATAL: REGEX_OVERRIDE extracted invalid IP: %s", ip)
		}
	}
	if !ok {
		ip, urlPath, status, ok = tryMatchWithPath(reLog, line)
	}
	if !ok || !isValidIP(ip) {
		return "", "", "", false
	}
	return ip, urlPath, status, true
}

func processLine(line string) {
	if line == "" {
		return
	}

	ip, urlPath, status, ok := matchLogLine(line)
	if !ok {
		log.Printf("⚠️  WARN: Skipping unparseable line: %s", strings.TrimSpace(line))
		return
	}

	// Normalize IP to canonical form (handles IPv6 representation variants)
	ip = normalizeIP(ip)

	// Check for 4xx status codes
	if !strings.HasPrefix(status, "4") {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if whitelist[ip] || banned[ip] {
		return
	}

	// Skip IPs already covered by a broad nftables CIDR range
	parsedIP := net.ParseIP(ip)
	if matchingRange := isIPCoveredByRanges(parsedIP, nftRanges); matchingRange != nil {
		log.Printf(warnIpInExcludedRange, ip, 0.0, matchingRange.String())
		return
	}

	// Calculate score for this path (clamped to maxScorePerHit)
	pathScore := calculateScore(urlPath)
	if pathScore == VerySuspiciousBinProbesScore {
		log.Printf("⚠️ %s made a very suspicious ip request in log line: %s", ip, strings.TrimSpace(line))
	}

	// Use LRU cache for visitor tracking (auto-evicts oldest when full)
	// Cache has its own internal lock, but we already hold mu for banned/whitelist
	v, exists := visitorCache.Get(ip)
	if !exists {
		v = &Visitor{IP: ip, Paths: make(map[string]bool)}
	}

	// Apply repeat penalty if this path was already seen
	if v.Paths[urlPath] {
		pathScore *= conf.RepeatPenalty
	} else {
		v.Paths[urlPath] = true
	}

	v.Score += pathScore
	now := time.Now()
	v.LastSeen = now

	// Burst detection: track 4xx hit timestamps in a sliding window
	if conf.BurstLimit > 0 && conf.BurstWindow > 0 {
		v.HitTimes = append(v.HitTimes, now)
		// Trim hit times outside the burst window
		cutoff := now.Add(-conf.BurstWindow)
		trimIdx := 0
		for trimIdx < len(v.HitTimes) && v.HitTimes[trimIdx].Before(cutoff) {
			trimIdx++
		}
		if trimIdx > 0 {
			v.HitTimes = v.HitTimes[trimIdx:]
		}
		// Check burst threshold
		if len(v.HitTimes) >= conf.BurstLimit {
			log.Printf("⚡ BURST: %s sent %d 4xx requests in %v — triggering instant ban",
				ip, len(v.HitTimes), conf.BurstWindow)
			visitorCache.Put(ip, v)
			executeBan(ip, v.Score)
			visitorCache.Delete(ip)
			return
		}
	}

	visitorCache.Put(ip, v)

	if v.Score >= conf.BanThreshold {
		executeBan(ip, v.Score)
		visitorCache.Delete(ip)
	}
}

func executeBan(ip string, score float64) {
	if conf.PreviewMode {
		log.Printf("👀 [PREVIEW] Would ban IP: %s (score: %.1f)", ip, score)
		banned[ip] = true // Mark as banned in memory for this session
		return
	}

	// Determine if IPv4 or IPv6 (ip is already normalized by processLine/scanFullLog)
	parsedIP := net.ParseIP(ip)
	setName := conf.NftSetName
	if parsedIP != nil && parsedIP.To4() == nil {
		// IPv6 address
		setName = conf.NftSetNameV6
	}

	// 1. Kernel Action
	// Note: exec.Command does NOT use shell interpretation — each argument is passed
	// directly to the exec syscall. Combined with net.ParseIP validation upstream,
	// this is safe against command injection.
	cmd := exec.Command("nft", "add", "element", "inet", "filter", setName, "{", ip, "}")
	if err := cmd.Run(); err != nil {
		log.Printf("❌ ERROR: Failed to ban %s in nftables set %s: %v", ip, setName, err)
		return
	}

	// 2. Persistence Action
	banned[ip] = true
	f, err := os.OpenFile(conf.BannedPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		if _, err := f.WriteString(ip + "\n"); err != nil {
			log.Printf("⚠️  WARN: Failed to persist ban for %s: %v", ip, err)
		}
	}

	log.Printf("🚫 BANNED: %s (set: %s)", ip, setName)
}

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

// scanLogScores reads all lines from the file, parses them, and accumulates per-IP threat scores.
func scanLogScores(file *os.File) scanStats {
	stats := scanStats{ipScores: make(map[string]float64)}
	ipPaths := make(map[string]map[string]bool) // IP -> paths seen (for repeat penalty)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		stats.totalLines++

		ip, urlPath, status, ok := matchLogLine(line)
		if !ok {
			continue
		}

		ip = normalizeIP(ip)
		stats.parsedOK++

		if !strings.HasPrefix(status, "4") {
			continue
		}
		stats.total4xx++

		// Initialize path tracking for this IP
		if ipPaths[ip] == nil {
			ipPaths[ip] = make(map[string]bool)
		}

		// Calculate score with repeat penalty
		pathScore := calculateScore(urlPath)
		if pathScore == VerySuspiciousBinProbesScore {
			log.Printf("⚠️ %s made a very suspicious ip request in log line: %s", ip, strings.TrimSpace(line))
		}
		if ipPaths[ip][urlPath] {
			pathScore *= conf.RepeatPenalty
		} else {
			ipPaths[ip][urlPath] = true
		}

		stats.ipScores[ip] += pathScore
	}
	return stats
}

// filterBannableIPs returns IPs that exceed the ban threshold, excluding whitelisted,
// already-banned, and CIDR-covered IPs. Results are sorted by score descending.
func filterBannableIPs(ipScores map[string]float64) []ipStat {
	var toBan []ipStat
	for ip, score := range ipScores {
		if score < conf.BanThreshold {
			continue
		}
		if whitelist[ip] || banned[ip] {
			continue
		}
		if matchingRange := isIPCoveredByRanges(net.ParseIP(ip), nftRanges); matchingRange != nil {
			log.Printf(warnIpInExcludedRange,
				ip, score, matchingRange.String())
			continue
		}
		toBan = append(toBan, ipStat{ip, score})
	}
	sort.Slice(toBan, func(i, j int) bool {
		return toBan[i].score > toBan[j].score
	})
	return toBan
}

// printScanResults outputs scan statistics and the list of IPs to ban.
func printScanResults(stats scanStats, uniqueIPs int, toBan []ipStat) {
	fmt.Println("📊 Scan Results:")
	fmt.Printf("   Total lines: %d\n", stats.totalLines)
	fmt.Printf("   Parsed OK: %d\n", stats.parsedOK)
	fmt.Printf("   4xx errors: %d\n", stats.total4xx)
	fmt.Printf("   Unique IPs with 4xx: %d\n", uniqueIPs)
	fmt.Printf("   IPs exceeding threshold (%.1f): %d\n", conf.BanThreshold, len(toBan))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// scanFullLog reads the entire log file and processes all lines with weighted scoring
func scanFullLog(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ FATAL: Cannot open log: %v", err)
	}
	defer file.Close()

	fmt.Printf("📖 Scanning %s...\n", path)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	stats := scanLogScores(file)
	toBan := filterBannableIPs(stats.ipScores)
	printScanResults(stats, len(stats.ipScores), toBan)

	// Process IPs
	for _, stat := range toBan {
		if conf.PreviewMode {
			fmt.Printf("👀 [PREVIEW] Would ban: %s (score: %.1f)\n", stat.ip, stat.score)
		} else {
			executeBan(stat.ip, stat.score)
		}
	}

	if len(toBan) == 0 {
		fmt.Println("✅ No IPs exceed the ban threshold.")
	}
}

// --- Internal Utilities ---

func tryMatch(re *regexp.Regexp, line string) (string, string, bool) {
	m := re.FindStringSubmatch(line)
	if len(m) < 3 {
		return "", "", false
	}
	return m[1], m[2], true
}

// tryMatchWithPath extracts IP, URL path, and status from log line
// Returns: IP, urlPath, status, matched
func tryMatchWithPath(re *regexp.Regexp, line string) (string, string, string, bool) {
	m := re.FindStringSubmatch(line)
	if len(m) < 4 {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

func isValidIP(ipStr string) bool {
	return net.ParseIP(ipStr) != nil
}

// normalizeIP returns the canonical string representation of an IP address.
// This ensures IPv6 variants like "::1" and "0:0:0:0:0:0:0:1" produce the same key.
func normalizeIP(ipStr string) string {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return ipStr // Shouldn't happen after isValidIP check, but be safe
	}
	return parsed.String()
}

func loadSafetyWhitelist() {
	whitelist[normalizeIP("127.0.0.1")] = true
	whitelist[normalizeIP("::1")] = true

	// Import current SSH Session
	if ssh := os.Getenv("SSH_CONNECTION"); ssh != "" {
		fields := strings.Fields(ssh)
		if len(fields) > 0 && isValidIP(fields[0]) {
			normalized := normalizeIP(fields[0])
			log.Printf("🛡️  SAFETY: Whitelisting current SSH session IP: %s", normalized)
			whitelist[normalized] = true
		}
	}

	// Import from File
	file, err := os.Open(conf.WhitelistPath)
	if err == nil {
		defer file.Close()
		s := bufio.NewScanner(file)
		for s.Scan() {
			ip := strings.TrimSpace(s.Text())
			if isValidIP(ip) {
				whitelist[normalizeIP(ip)] = true
			}
		}
	}

	// Import from UFW status if available
	out, err := exec.Command("ufw", "status").Output()
	if err == nil {
		reIP := regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})`)
		for _, ip := range reIP.FindAllString(string(out), -1) {
			whitelist[normalizeIP(ip)] = true
		}
	}
}

// loadNftablesRanges extracts CIDR ranges (e.g., 192.168.1.0/24) from the nftables config file.
// These ranges are used to check whether an IP is already covered by a broad subnet rule
// before issuing individual nft add element commands.
func loadNftablesRanges(path string) ([]*net.IPNet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ranges []*net.IPNet
	// Regex to find CIDR patterns (e.g., 20.160.0.0/12, 192.168.1.0/24)
	// Mask limited to 1-2 digits to reject nonsensical values like /999
	reCIDR := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// FindAllString captures all CIDRs on a line (handles comma-separated elements)
		matches := reCIDR.FindAllString(line, -1)
		for _, match := range matches {
			_, network, err := net.ParseCIDR(match)
			if err == nil {
				ranges = append(ranges, network)
			}
		}
	}
	return ranges, scanner.Err()
}

// isIPCoveredByRanges checks if the given IP falls within any of the provided CIDR ranges.
// Returns the matching network if found, nil otherwise.
func isIPCoveredByRanges(ip net.IP, ranges []*net.IPNet) *net.IPNet {
	for _, r := range ranges {
		if r.Contains(ip) {
			return r
		}
	}
	return nil
}

// syncIPToNftSet adds an IP to the appropriate nftables set (IPv4 or IPv6).
func syncIPToNftSet(normalized string, parsedIP net.IP) {
	setName := conf.NftSetName
	if parsedIP != nil && parsedIP.To4() == nil {
		setName = conf.NftSetNameV6
	}
	cmd := exec.Command("nft", "add", "element", "inet", "filter", setName, "{", normalized, "}")
	if err := cmd.Run(); err != nil {
		// Note: nft returns error if IP already in set, which is fine
		log.Printf("⚠️  WARN: nft add element for %s: %v (may already exist)", normalized, err)
	}
}

func loadAndSyncBannedList(nftRanges []*net.IPNet) {
	file, err := os.Open(conf.BannedPath)
	if err != nil {
		return
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	for s.Scan() {
		ip := strings.TrimSpace(s.Text())
		if !isValidIP(ip) {
			continue
		}

		normalized := normalizeIP(ip)
		parsedIP := net.ParseIP(normalized)

		// Check if this IP is already covered by a broad CIDR range in nftables.conf
		if matchingRange := isIPCoveredByRanges(parsedIP, nftRanges); matchingRange != nil {
			// This is a warning: receiving traffic from a range that should already
			// be blocked suggests nftables may not be running or misconfigured.
			log.Printf(warnIpInExcludedRange, normalized, 0.0, matchingRange.String())
			// Still mark as banned in memory so tail/scan won't re-process it
			mu.Lock()
			banned[normalized] = true
			mu.Unlock()
			continue
		}

		mu.Lock()
		if !banned[normalized] {
			banned[normalized] = true
			syncIPToNftSet(normalized, parsedIP)
		}
		mu.Unlock()
	}
}

func janitor(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Cache has its own internal lock now, no need for global mu
			visitorCache.CleanExpired(conf.Window)
		}
	}
}

// --- Environment Variable Helpers ---

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		// Strip surrounding quotes if present (common in .env files)
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			return val[1 : len(val)-1]
		}
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	s := getEnv(key, "")
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	s := getEnv(key, "")
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	s := strings.ToLower(getEnv(key, ""))
	if s == "true" || s == "1" || s == "yes" {
		return true
	}
	if s == "false" || s == "0" || s == "no" {
		return false
	}
	return fallback
}

func getEnvFloat(key string, fallback float64) float64 {
	s := getEnv(key, "")
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return fallback
}

// loadRules parses the rules configuration file and populates the rules slice
func loadRules(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("⚠️  WARN: Cannot open rules file '%s': %v (using default scoring)", path, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	loadedCount := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse format: <score> <regex_pattern>
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			log.Printf("⚠️  WARN: Invalid rule format at line %d: %s", lineNum, line)
			continue
		}

		score, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		if err != nil {
			log.Printf("⚠️  WARN: Invalid score at line %d: %s", lineNum, parts[0])
			continue
		}

		pattern := strings.TrimSpace(parts[1])

		// Defense-in-depth: reject excessively long patterns
		if len(pattern) > maxPatternLength {
			log.Printf("⚠️  WARN: Rejecting rule at line %d: pattern too long (%d chars, max %d)", lineNum, len(pattern), maxPatternLength)
			continue
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Printf("⚠️  WARN: Invalid regex at line %d: %s (%v)", lineNum, pattern, err)
			continue
		}

		// Warn if score exceeds per-hit cap (it will be clamped at runtime)
		if score > maxScorePerHit {
			log.Printf("⚠️  WARN: Rule at line %d has score %.1f exceeding cap %.1f (will be clamped)", lineNum, score, maxScorePerHit)
		}

		rules = append(rules, Rule{Score: score, Pattern: re, Raw: pattern})
		loadedCount++
	}

	log.Printf("📋 Loaded %d threat detection rules from %s", loadedCount, path)
}

// calculateScore determines the score for a given URL path based on loaded rules.
// All scores are clamped to maxScorePerHit to prevent runaway banning from
// misconfigured rules.
func calculateScore(urlPath string) float64 {
	// Binary probes: empty path means malformed/garbage request (RDP, TLS, SMB probes)
	// These are extremely malicious - instant ban worthy
	if urlPath == "" {
		return VerySuspiciousBinProbesScore // Critical: binary protocol probe detected
	}

	for _, rule := range rules {
		if rule.Pattern.MatchString(urlPath) {
			// Clamp score to prevent single-hit instant bans from misconfigured rules
			if rule.Score > maxScorePerHit {
				return maxScorePerHit
			}
			return rule.Score
		}
	}
	// Default score for unmatched paths
	return 1.0
}

func main() {
	fmt.Printf("🚀 🛡️ Starting App:'%s', ver:%s, Repo: %s\n", APP, VERSION, REPOSITORY)

	if conf.PreviewMode {
		fmt.Println("🔍 PREVIEW MODE: No real bans will be issued.")
		// Clear any stale banned state so preview tracks threats fresh
		mu.Lock()
		banned = make(map[string]bool)
		mu.Unlock()
		log.Println("🧹 Preview mode: cleared banned map for clean tracking")
	}
	if conf.ScanAllMode {
		fmt.Println("📊 SCAN ALL MODE: Reading entire log file...")
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // ← Ensures cleanup when main() exits naturally.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("\n🛑 Received %v, shutting down gracefully...", sig)
		cancel()
	}()

	// 1. Safety Phase
	loadSafetyWhitelist()

	// 2. Load nftables CIDR ranges (always, even in preview — for informational warnings)
	var err error
	nftRanges, err = loadNftablesRanges(conf.NftablesConfPath)
	if err != nil {
		log.Printf("⚠️  WARN: Cannot read nftables config '%s': %v (skipping range check)", conf.NftablesConfPath, err)
	}
	if len(nftRanges) > 0 {
		log.Printf("📋 Loaded %d CIDR ranges from %s", len(nftRanges), conf.NftablesConfPath)
	}

	// 3. Sync Phase (Skip kernel sync if in preview)
	if !conf.PreviewMode {
		loadAndSyncBannedList(nftRanges)
	}

	// 3. Scan All Mode - process entire log file first
	if conf.ScanAllMode {
		scanFullLog(conf.LogPath)
		return // Exit after scan in this mode
	}

	// 4. Maintenance Phase (only for tail mode)
	go janitor(ctx)

	// 5. Execution Phase
	tailLog(ctx, conf.LogPath)

	log.Println("✅ LogScythe stopped.")
}
