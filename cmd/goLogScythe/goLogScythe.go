/*
Package main implements a high-performance log monitor for 404 like http scans,
then it allows you to ban ip doing too much 404 using nftables.
It features environment-driven configuration, dual-regex fallback,
and a safety-first preview mode.
*/
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Default Constants ---
const (
	defaultLogPath       = "/var/log/nginx/access.log"
	defaultWhitelistPath = "./whitelist.txt"
	defaultBannedPath    = "./banned_ips.txt"
	defaultThreshold     = 10
	defaultWindow        = 15 * time.Minute
	defaultNftSet        = "parasites"

	// Standard Nginx/Apache Combined Log Format Regex
	// Matches: 1.2.3.4 - - [Date] "Request" 404 ...
	defaultNginxRegex = `^(\S+)\s+-\s+-\s+\[.*?\]\s+".*?"\s+(\d{3})`

	// Apache specific or custom gawk format fallback
	// Matches: 78.153.140.156 - - [15/Jan/2026:00:48:46 +0100] ...
	defaultApacheRegex = `^(\S+)\s+-\s+-\s+\[.*?\]\s+".*?"\s+(\d{3})`
)

type Config struct {
	LogPath       string
	WhitelistPath string
	BannedPath    string
	Threshold     int
	Window        time.Duration
	NftSetName    string
	RegexOverride string
	PreviewMode   bool
}

type Visitor struct {
	Count    int
	LastSeen time.Time
}

var (
	conf      Config
	visitors  = make(map[string]*Visitor)
	banned    = make(map[string]bool)
	whitelist = make(map[string]bool)
	mu        sync.Mutex

	reNginx    *regexp.Regexp
	reApache   *regexp.Regexp
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
		RegexOverride: os.Getenv("REGEX_OVERRIDE"),
		PreviewMode:   getEnvBool("PREVIEW_MODE", false),
	}

	// Pre-compile Regexes
	reNginx = regexp.MustCompile(defaultNginxRegex)
	reApache = regexp.MustCompile(defaultApacheRegex)

	if conf.RegexOverride != "" {
		var err error
		reOverride, err = regexp.Compile(conf.RegexOverride)
		if err != nil {
			log.Fatalf("❌ FATAL: REGEX_OVERRIDE is invalid: %v", err)
		}
	}
}

func main() {
	fmt.Println("🛡️  LogScythe: Starting Native Log Monitor")
	if conf.PreviewMode {
		fmt.Println("🔍 PREVIEW MODE: No real bans will be issued.")
	}

	// 1. Safety Phase
	loadSafetyWhitelist()

	// 2. Sync Phase (Skip kernel sync if in preview)
	if !conf.PreviewMode {
		loadAndSyncBannedList()
	}

	// 3. Maintenance Phase
	go janitor()

	// 4. Execution Phase
	tailLog(conf.LogPath)
}

func tailLog(path string) {
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

	// 2. Try Nginx then Apache
	if !matched {
		ip, status, matched = tryMatch(reNginx, line)
	}

	// Strategy C: Apache Fallback
	if !matched {
		ip, status, matched = tryMatch(reApache, line)
	}

	if !matched || !isValidIP(ip) {
		// Log a warning for data we can't parse, but keep the program running
		if line != "" {
			log.Printf("⚠️  WARN: Skipping unparseable line: %s", strings.TrimSpace(line))
		}
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

	v, exists := visitors[ip]
	if !exists {
		v = &Visitor{}
		visitors[ip] = v
	}
	v.Count++
	v.LastSeen = time.Now()

	if v.Count >= conf.Threshold {
		executeBan(ip)
		delete(visitors, ip)
	}
}

func executeBan(ip string) {
	if conf.PreviewMode {
		log.Printf("👀 [PREVIEW] Would ban IP: %s (%d hits)", ip, conf.Threshold)
		banned[ip] = true // Mark as banned in memory for this session
		return
	}

	// 1. Kernel Action
	cmd := exec.Command("nft", "add", "element", "inet", "filter", conf.NftSetName, "{", ip, "}")
	if err := cmd.Run(); err != nil {
		log.Printf("❌ ERROR: Failed to ban %s in nftables: %v", ip, err)
		return
	}

	// 2. Persistence Action
	banned[ip] = true
	f, err := os.OpenFile(conf.BannedPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(ip + "\n")
	}

	log.Printf("🚫 BANNED: %s", ip)
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
		ip := strings.Fields(ssh)[0]
		log.Printf("🛡️  SAFETY: Whitelisting current SSH session IP: %s", ip)
		whitelist[ip] = true
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
		if isValidIP(ip) && !banned[ip] {
			mu.Lock()
			banned[ip] = true
			exec.Command("nft", "add", "element", "inet", "filter", conf.NftSetName, "{", ip, "}").Run()
			mu.Unlock()
		}
	}
}

func janitor() {
	for {
		time.Sleep(2 * time.Minute)
		mu.Lock()
		for ip, v := range visitors {
			if time.Since(v.LastSeen) > conf.Window {
				delete(visitors, ip)
			}
		}
		mu.Unlock()
	}
}

// --- Environment Variable Helpers ---

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
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
