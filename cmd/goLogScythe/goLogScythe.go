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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// --- Default Constants ---
const (
	APP                  = "goLogScythe"
	AppSnake             = "go-log-scythe"
	VERSION              = "0.1.0"
	REPOSITORY           = "https://github.com/lao-tseu-is-alive/go-log-scythe"
	defaultLogPath       = "/var/log/nginx/access.log"
	defaultWhitelistPath = "./whitelist.txt"
	defaultBannedPath    = "./banned_ips.txt"
	defaultThreshold     = 10
	defaultWindow        = 15 * time.Minute
	defaultNftSet        = "parasites"
	defaultNftSetV6      = "parasites6"
	maxVisitors          = 10000 // Maximum visitors to track before eviction

	// Combined Log Format Regex (works for both Nginx and Apache)
	// Matches: 1.2.3.4 - - [Date] "Request" 404 ...
	defaultLogRegex = `^(\S+)\s+-\s+-\s+\[.*?\]\s+".*?"\s+(\d{3})`
)

type Config struct {
	LogPath       string
	WhitelistPath string
	BannedPath    string
	Threshold     int
	Window        time.Duration
	NftSetName    string
	NftSetNameV6  string
	RegexOverride string
	PreviewMode   bool
	ScanAllMode   bool
}

type Visitor struct {
	IP       string
	Count    int
	LastSeen time.Time
}

// LRUCache is a bounded cache with LRU eviction policy
type LRUCache struct {
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

// Get retrieves a visitor from the cache and marks it as recently used
func (c *LRUCache) Get(ip string) (*Visitor, bool) {
	if elem, ok := c.items[ip]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(*Visitor), true
	}
	return nil, false
}

// Put adds or updates a visitor in the cache
func (c *LRUCache) Put(ip string, visitor *Visitor) {
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
	return c.order.Len()
}

// CleanExpired removes entries older than the given window
func (c *LRUCache) CleanExpired(window time.Duration) int {
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
	mu           sync.Mutex

	reLog      *regexp.Regexp
	reOverride *regexp.Regexp
)

func init() {
	// Initialize configuration from Environment Variables
	conf = Config{
		LogPath:       getEnv("LOG_PATH", defaultLogPath),
		WhitelistPath: getEnv("WHITE_LIST_PATH", defaultWhitelistPath),
		BannedPath:    getEnv("BANNED_FILE_PATH", defaultBannedPath),
		Threshold:     getEnvInt("BAN_THRESHOLD", defaultThreshold),
		Window:        getEnvDuration("BAN_WINDOW", defaultWindow),
		NftSetName:    getEnv("NFT_SET_NAME", defaultNftSet),
		NftSetNameV6:  getEnv("NFT_SET_NAME_V6", defaultNftSetV6),
		RegexOverride: os.Getenv("REGEX_OVERRIDE"),
		PreviewMode:   getEnvBool("PREVIEW_MODE", false),
		ScanAllMode:   getEnvBool("SCAN_ALL_MODE", false),
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

	// Initialize LRU cache for visitor tracking
	visitorCache = NewLRUCache(maxVisitors)
}

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
				time.Sleep(500 * time.Millisecond)

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

func processLine(line string) {
	if line == "" {
		return
	}

	var ip, status string
	var matched bool

	// 1. Try Override
	if reOverride != nil {
		ip, status, matched = tryMatch(reOverride, line)
		if matched && !isValidIP(ip) {
			log.Fatalf("❌ FATAL: REGEX_OVERRIDE extracted invalid IP: %s", ip)
		}
	}

	// 2. Try default log regex
	if !matched {
		ip, status, matched = tryMatch(reLog, line)
	}

	if !matched || !isValidIP(ip) {
		// Log a warning for data we can't parse, but keep the program running
		log.Printf("⚠️  WARN: Skipping unparseable line: %s", strings.TrimSpace(line))
		return
	}

	// Check for 4xx status codes
	if !strings.HasPrefix(status, "4") {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if whitelist[ip] || banned[ip] {
		return
	}

	// Use LRU cache for visitor tracking (auto-evicts oldest when full)
	v, exists := visitorCache.Get(ip)
	if !exists {
		v = &Visitor{IP: ip}
	}
	v.Count++
	v.LastSeen = time.Now()
	visitorCache.Put(ip, v)

	if v.Count >= conf.Threshold {
		executeBan(ip)
		visitorCache.Delete(ip)
	}
}

func executeBan(ip string) {
	if conf.PreviewMode {
		log.Printf("👀 [PREVIEW] Would ban IP: %s (%d hits)", ip, conf.Threshold)
		banned[ip] = true // Mark as banned in memory for this session
		return
	}

	// Determine if IPv4 or IPv6
	parsedIP := net.ParseIP(ip)
	setName := conf.NftSetName
	if parsedIP != nil && parsedIP.To4() == nil {
		// IPv6 address
		setName = conf.NftSetNameV6
	}

	// 1. Kernel Action
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

// scanFullLog reads the entire log file and processes all lines
func scanFullLog(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ FATAL: Cannot open log: %v", err)
	}
	defer file.Close()

	fmt.Printf("📖 Scanning %s...\n", path)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Statistics
	totalLines := 0
	parsedOK := 0
	total4xx := 0
	ipHits := make(map[string]int) // IP -> 4xx hit count

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		totalLines++

		if line == "" {
			continue
		}

		var ip, status string
		var matched bool

		// Try override regex first
		if reOverride != nil {
			ip, status, matched = tryMatch(reOverride, line)
		}

		// Try default log regex
		if !matched {
			ip, status, matched = tryMatch(reLog, line)
		}

		if !matched || !isValidIP(ip) {
			continue
		}

		parsedOK++

		// Count 4xx errors
		if strings.HasPrefix(status, "4") {
			total4xx++
			ipHits[ip]++
		}
	}

	// Collect IPs that exceed threshold
	type ipStat struct {
		ip   string
		hits int
	}
	var toBan []ipStat
	uniqueIPs := 0

	for ip, hits := range ipHits {
		uniqueIPs++
		if hits >= conf.Threshold {
			// Skip whitelisted IPs
			if whitelist[ip] {
				continue
			}
			// Skip already banned IPs
			if banned[ip] {
				continue
			}
			toBan = append(toBan, ipStat{ip, hits})
		}
	}

	// Sort by hits descending
	for i := 0; i < len(toBan)-1; i++ {
		for j := i + 1; j < len(toBan); j++ {
			if toBan[j].hits > toBan[i].hits {
				toBan[i], toBan[j] = toBan[j], toBan[i]
			}
		}
	}

	// Print results
	fmt.Println("📊 Scan Results:")
	fmt.Printf("   Total lines: %d\n", totalLines)
	fmt.Printf("   Parsed OK: %d\n", parsedOK)
	fmt.Printf("   4xx errors: %d\n", total4xx)
	fmt.Printf("   Unique IPs with 4xx: %d\n", uniqueIPs)
	fmt.Printf("   IPs exceeding threshold (%d): %d\n", conf.Threshold, len(toBan))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Process IPs
	for _, stat := range toBan {
		if conf.PreviewMode {
			fmt.Printf("👀 [PREVIEW] Would ban: %s (%d hits)\n", stat.ip, stat.hits)
		} else {
			executeBan(stat.ip)
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

func isValidIP(ipStr string) bool {
	return net.ParseIP(ipStr) != nil
}

func loadSafetyWhitelist() {
	whitelist["127.0.0.1"] = true
	whitelist["::1"] = true

	// Import current SSH Session
	if ssh := os.Getenv("SSH_CONNECTION"); ssh != "" {
		fields := strings.Fields(ssh)
		if len(fields) > 0 && isValidIP(fields[0]) {
			log.Printf("🛡️  SAFETY: Whitelisting current SSH session IP: %s", fields[0])
			whitelist[fields[0]] = true
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
				whitelist[ip] = true
			}
		}
	}

	// Import from UFW status if available
	out, err := exec.Command("ufw", "status").Output()
	if err == nil {
		reIP := regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})`)
		for _, ip := range reIP.FindAllString(string(out), -1) {
			whitelist[ip] = true
		}
	}
}

func loadAndSyncBannedList() {
	file, err := os.Open(conf.BannedPath)
	if err != nil {
		return
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	for s.Scan() {
		ip := strings.TrimSpace(s.Text())
		if isValidIP(ip) {
			mu.Lock()
			if !banned[ip] {
				banned[ip] = true
				setName := conf.NftSetName
				if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
					setName = conf.NftSetNameV6
				}
				cmd := exec.Command("nft", "add", "element", "inet", "filter", setName, "{", ip, "}")
				if err := cmd.Run(); err != nil {
					// Note: nft returns error if IP already in set, which is fine
					log.Printf("⚠️  WARN: nft add element for %s: %v (may already exist)", ip, err)
				}
			}
			mu.Unlock()
		}
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
			mu.Lock()
			visitorCache.CleanExpired(conf.Window)
			mu.Unlock()
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

func main() {
	fmt.Printf("🚀 🛡️ Starting App:'%s', ver:%s, BuildStamp: %s, Repo: %s\n", APP, VERSION, REPOSITORY)

	if conf.PreviewMode {
		fmt.Println("🔍 PREVIEW MODE: No real bans will be issued.")
	}
	if conf.ScanAllMode {
		fmt.Println("📊 SCAN ALL MODE: Reading entire log file...")
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("\n🛑 Received %v, shutting down gracefully...", sig)
		cancel()
	}()

	// 1. Safety Phase
	loadSafetyWhitelist()

	// 2. Sync Phase (Skip kernel sync if in preview)
	if !conf.PreviewMode {
		loadAndSyncBannedList()
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
