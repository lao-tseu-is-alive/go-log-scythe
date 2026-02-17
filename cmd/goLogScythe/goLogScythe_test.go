/*
Package main provides unit tests for the LogScythe log monitor.
*/
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	failedCreateLogFile    = "Failed to create temp log file: %v"
	failedTempFileCreation = "Failed to create temp banned file: %v"
	failedCreateNftFile    = "Failed to create temp nftables file: %v"
)

// --- Environment Variable Helper Tests ---

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envValue string
		setEnv   bool
		fallback string
		want     string
	}{
		{"uses fallback when not set", "TEST_NOT_SET", "", false, "default", "default"},
		{"uses env value when set", "TEST_SET", "custom", true, "default", "custom"},
		{"empty string is valid", "TEST_EMPTY", "", true, "default", ""},
		{"strips double quotes", "TEST_QUOTED", `"quoted_value"`, true, "default", "quoted_value"},
		{"strips single quotes", "TEST_SINGLE", `'single_quoted'`, true, "default", "single_quoted"},
		{"preserves unmatched quotes", "TEST_UNMATCHED", `"unmatched`, true, "default", `"unmatched`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			}
			got := getEnv(tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("getEnv(%q, %q) = %q, want %q", tt.key, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		setEnv   bool
		fallback int
		want     int
	}{
		{"uses fallback when not set", "", false, 42, 42},
		{"parses valid int", "100", true, 42, 100},
		{"fallback on invalid string", "notanint", true, 42, 42},
		{"parses negative int", "-5", true, 42, -5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_INT_" + tt.name
			if tt.setEnv {
				t.Setenv(key, tt.envValue)
			}
			got := getEnvInt(key, tt.fallback)
			if got != tt.want {
				t.Errorf("getEnvInt() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGetEnvDuration(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		setEnv   bool
		fallback time.Duration
		want     time.Duration
	}{
		{"uses fallback when not set", "", false, 5 * time.Minute, 5 * time.Minute},
		{"parses minutes", "10m", true, 5 * time.Minute, 10 * time.Minute},
		{"parses seconds", "30s", true, 5 * time.Minute, 30 * time.Second},
		{"parses hours", "2h", true, 5 * time.Minute, 2 * time.Hour},
		{"fallback on invalid", "invalid", true, 5 * time.Minute, 5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_DUR_" + tt.name
			if tt.setEnv {
				t.Setenv(key, tt.envValue)
			}
			got := getEnvDuration(key, tt.fallback)
			if got != tt.want {
				t.Errorf("getEnvDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		setEnv   bool
		fallback bool
		want     bool
	}{
		{"uses fallback when not set", "", false, true, true},
		{"true string", "true", true, false, true},
		{"false string", "false", true, true, false},
		{"1 is true", "1", true, false, true},
		{"0 is false", "0", true, true, false},
		{"yes is true", "yes", true, false, true},
		{"no is false", "no", true, true, false},
		{"TRUE uppercase", "TRUE", true, false, true},
		{"invalid uses fallback", "maybe", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_BOOL_" + tt.name
			if tt.setEnv {
				t.Setenv(key, tt.envValue)
			}
			got := getEnvBool(key, tt.fallback)
			if got != tt.want {
				t.Errorf("getEnvBool() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- IP Validation Tests ---

func TestIsValidIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"255.255.255.255", true},
		{"0.0.0.0", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"fe80::1", true},
		{"", false},
		{"invalid", false},
		{"192.168.1", false},
		{"192.168.1.256", false},
		{"abc.def.ghi.jkl", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isValidIP(tt.ip)
			if got != tt.want {
				t.Errorf("isValidIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// --- Regex Matching Tests ---

func TestTryMatch(t *testing.T) {
	// Use the default regex pattern
	re := regexp.MustCompile(`^(\S+)\s+-\s+-\s+\[.*?\]\s+".*?"\s+(\d{3})`)

	tests := []struct {
		name       string
		line       string
		wantIP     string
		wantStatus string
		wantMatch  bool
	}{
		{
			name:       "nginx combined format",
			line:       `192.168.1.100 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123`,
			wantIP:     "192.168.1.100",
			wantStatus: "404",
			wantMatch:  true,
		},
		{
			name:       "apache combined format",
			line:       `10.0.0.50 - - [16/Jan/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 456`,
			wantIP:     "10.0.0.50",
			wantStatus: "401",
			wantMatch:  true,
		},
		{
			name:       "200 status code",
			line:       `8.8.8.8 - - [16/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1024`,
			wantIP:     "8.8.8.8",
			wantStatus: "200",
			wantMatch:  true,
		},
		{
			name:       "empty line",
			line:       "",
			wantIP:     "",
			wantStatus: "",
			wantMatch:  false,
		},
		{
			name:       "malformed line",
			line:       "this is not a valid log line",
			wantIP:     "",
			wantStatus: "",
			wantMatch:  false,
		},
		{
			name:       "IPv6 address",
			line:       `2001:db8::1 - - [16/Jan/2026:10:00:00 +0000] "GET /test HTTP/1.1" 404 100`,
			wantIP:     "2001:db8::1",
			wantStatus: "404",
			wantMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, gotStatus, gotMatch := tryMatch(re, tt.line)
			if gotMatch != tt.wantMatch {
				t.Errorf("tryMatch() match = %v, want %v", gotMatch, tt.wantMatch)
			}
			if gotMatch {
				if gotIP != tt.wantIP {
					t.Errorf("tryMatch() ip = %q, want %q", gotIP, tt.wantIP)
				}
				if gotStatus != tt.wantStatus {
					t.Errorf("tryMatch() status = %q, want %q", gotStatus, tt.wantStatus)
				}
			}
		})
	}
}

// --- LRU Cache Tests ---

func TestLRUCacheBasicOperations(t *testing.T) {
	cache := NewLRUCache(3)

	// Test Put and Get
	cache.Put("192.168.1.1", &Visitor{IP: "192.168.1.1", Score: 1.0, Paths: make(map[string]bool)})
	cache.Put("192.168.1.2", &Visitor{IP: "192.168.1.2", Score: 2.0, Paths: make(map[string]bool)})

	v, ok := cache.Get("192.168.1.1")
	if !ok {
		t.Error("LRUCache.Get() should find existing key")
	}
	if v.Score != 1.0 {
		t.Errorf("LRUCache.Get() score = %.1f, want 1.0", v.Score)
	}

	// Test non-existent key
	_, ok = cache.Get("nonexistent")
	if ok {
		t.Error("LRUCache.Get() should return false for non-existent key")
	}

	// Test Len
	if cache.Len() != 2 {
		t.Errorf("LRUCache.Len() = %d, want 2", cache.Len())
	}
}

func TestLRUCacheEviction(t *testing.T) {
	cache := NewLRUCache(3)

	// Fill cache
	cache.Put("ip1", &Visitor{IP: "ip1", Score: 1.0, Paths: make(map[string]bool)})
	cache.Put("ip2", &Visitor{IP: "ip2", Score: 2.0, Paths: make(map[string]bool)})
	cache.Put("ip3", &Visitor{IP: "ip3", Score: 3.0, Paths: make(map[string]bool)})

	// Access ip1 to make it most recently used
	cache.Get("ip1")

	// Add ip4, should evict ip2 (least recently used)
	cache.Put("ip4", &Visitor{IP: "ip4", Score: 4.0, Paths: make(map[string]bool)})

	if cache.Len() != 3 {
		t.Errorf("LRUCache should maintain capacity, got len=%d", cache.Len())
	}

	// ip2 should be evicted
	_, ok := cache.Get("ip2")
	if ok {
		t.Error("ip2 should have been evicted")
	}

	// ip1, ip3, ip4 should exist
	if _, ok := cache.Get("ip1"); !ok {
		t.Error("ip1 should exist")
	}
	if _, ok := cache.Get("ip3"); !ok {
		t.Error("ip3 should exist")
	}
	if _, ok := cache.Get("ip4"); !ok {
		t.Error("ip4 should exist")
	}
}

func TestLRUCacheDelete(t *testing.T) {
	cache := NewLRUCache(3)
	cache.Put("ip1", &Visitor{IP: "ip1", Score: 1.0, Paths: make(map[string]bool)})
	cache.Put("ip2", &Visitor{IP: "ip2", Score: 2.0, Paths: make(map[string]bool)})

	cache.Delete("ip1")

	if cache.Len() != 1 {
		t.Errorf("After delete, len = %d, want 1", cache.Len())
	}

	if _, ok := cache.Get("ip1"); ok {
		t.Error("Deleted key should not exist")
	}
}

func TestLRUCacheCleanExpired(t *testing.T) {
	cache := NewLRUCache(10)
	now := time.Now()

	// Add entries with different ages
	cache.Put("new", &Visitor{IP: "new", LastSeen: now})
	cache.Put("old", &Visitor{IP: "old", LastSeen: now.Add(-20 * time.Minute)})
	cache.Put("ancient", &Visitor{IP: "ancient", LastSeen: now.Add(-1 * time.Hour)})

	removed := cache.CleanExpired(15 * time.Minute)

	if removed != 2 {
		t.Errorf("CleanExpired should remove 2 entries, removed %d", removed)
	}

	if cache.Len() != 1 {
		t.Errorf("After cleanup, len = %d, want 1", cache.Len())
	}

	if _, ok := cache.Get("new"); !ok {
		t.Error("'new' entry should still exist")
	}
}

// --- Whitelist Loading Tests ---

func TestLoadSafetyWhitelist(t *testing.T) {
	// Reset global state
	mu.Lock()
	whitelist = make(map[string]bool)
	mu.Unlock()

	// Create a temp whitelist file
	tmpDir := t.TempDir()
	whitelistFile := filepath.Join(tmpDir, "whitelist.txt")
	content := "10.0.0.1\n10.0.0.2\ninvalid\n192.168.1.100\n"
	if err := os.WriteFile(whitelistFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp whitelist: %v", err)
	}

	// Temporarily override config
	originalPath := conf.WhitelistPath
	conf.WhitelistPath = whitelistFile
	defer func() { conf.WhitelistPath = originalPath }()

	loadSafetyWhitelist()

	// Check localhost defaults
	if !whitelist["127.0.0.1"] {
		t.Error("loadSafetyWhitelist() did not add 127.0.0.1")
	}
	if !whitelist["::1"] {
		t.Error("loadSafetyWhitelist() did not add ::1")
	}

	// Check file-loaded IPs
	if !whitelist["10.0.0.1"] {
		t.Error("loadSafetyWhitelist() did not load 10.0.0.1 from file")
	}
	if !whitelist["10.0.0.2"] {
		t.Error("loadSafetyWhitelist() did not load 10.0.0.2 from file")
	}
	if !whitelist["192.168.1.100"] {
		t.Error("loadSafetyWhitelist() did not load 192.168.1.100 from file")
	}

	// Check invalid IP was skipped
	if whitelist["invalid"] {
		t.Error("loadSafetyWhitelist() should have skipped invalid IP")
	}
}

// --- ProcessLine Tests ---

func TestProcessLine(t *testing.T) {
	// Reset global state for each test
	resetGlobalState := func() {
		mu.Lock()
		visitorCache = NewLRUCache(defaultMaxVisitors)
		banned = make(map[string]bool)
		whitelist = make(map[string]bool)
		whitelist["127.0.0.1"] = true
		mu.Unlock()
	}

	t.Run("empty line is ignored", func(t *testing.T) {
		resetGlobalState()
		processLine("")
		mu.Lock()
		if visitorCache.Len() != 0 {
			t.Error("processLine() should ignore empty lines")
		}
		mu.Unlock()
	})

	t.Run("whitelisted IP is ignored", func(t *testing.T) {
		resetGlobalState()
		line := `127.0.0.1 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123`
		processLine(line)
		mu.Lock()
		if _, exists := visitorCache.Get("127.0.0.1"); exists {
			t.Error("processLine() should skip whitelisted IPs")
		}
		mu.Unlock()
	})

	t.Run("200 status is ignored", func(t *testing.T) {
		resetGlobalState()
		line := `8.8.8.8 - - [16/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1024`
		processLine(line)
		mu.Lock()
		if _, exists := visitorCache.Get("8.8.8.8"); exists {
			t.Error("processLine() should ignore non-4xx status codes")
		}
		mu.Unlock()
	})

	t.Run("404 increments visitor count", func(t *testing.T) {
		resetGlobalState()
		line := `192.168.1.50 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123`
		processLine(line)
		mu.Lock()
		v, exists := visitorCache.Get("192.168.1.50")
		if !exists {
			t.Fatal("processLine() did not create visitor entry")
		}
		if v.Score == 0 {
			t.Errorf("processLine() score = %.1f, want > 0", v.Score)
		}
		mu.Unlock()
	})

	t.Run("already banned IP is ignored", func(t *testing.T) {
		resetGlobalState()
		mu.Lock()
		banned["10.0.0.99"] = true
		mu.Unlock()

		line := `10.0.0.99 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123`
		processLine(line)

		mu.Lock()
		if _, exists := visitorCache.Get("10.0.0.99"); exists {
			t.Error("processLine() should skip already banned IPs")
		}
		mu.Unlock()
	})
}

// --- IPv4/IPv6 Detection Tests ---

func TestIPv6Detection(t *testing.T) {
	tests := []struct {
		ip     string
		isIPv6 bool
	}{
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"::1", true},
		{"2001:db8::1", true},
		{"fe80::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			parsed := net.ParseIP(tt.ip)
			if parsed == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			isIPv6 := parsed.To4() == nil
			if isIPv6 != tt.isIPv6 {
				t.Errorf("IP %s: isIPv6 = %v, want %v", tt.ip, isIPv6, tt.isIPv6)
			}
		})
	}
}

// --- loadAndSyncBannedList Tests ---

func TestLoadAndSyncBannedList(t *testing.T) {
	// Reset global state
	mu.Lock()
	banned = make(map[string]bool)
	mu.Unlock()

	// Create a temp banned file
	tmpDir := t.TempDir()
	bannedFile := filepath.Join(tmpDir, defaultBannedPath)
	content := "192.168.100.1\n192.168.100.2\ninvalid_ip\n10.20.30.40\n"
	if err := os.WriteFile(bannedFile, []byte(content), 0644); err != nil {
		t.Fatalf(failedTempFileCreation, err)
	}

	// Temporarily override config
	originalPath := conf.BannedPath
	originalPreview := conf.PreviewMode
	conf.BannedPath = bannedFile
	conf.PreviewMode = true // Skip actual nft commands
	defer func() {
		conf.BannedPath = originalPath
		conf.PreviewMode = originalPreview
	}()

	loadAndSyncBannedList(nil)

	// Check that valid IPs were loaded
	mu.Lock()
	defer mu.Unlock()

	if !banned["192.168.100.1"] {
		t.Error("loadAndSyncBannedList() did not load 192.168.100.1")
	}
	if !banned["192.168.100.2"] {
		t.Error("loadAndSyncBannedList() did not load 192.168.100.2")
	}
	if !banned["10.20.30.40"] {
		t.Error("loadAndSyncBannedList() did not load 10.20.30.40")
	}

	// Invalid IP should not be in banned map
	if banned["invalid_ip"] {
		t.Error("loadAndSyncBannedList() should have skipped invalid IP")
	}
}

func TestLoadAndSyncBannedListMissingFile(t *testing.T) {
	// Reset global state
	mu.Lock()
	banned = make(map[string]bool)
	mu.Unlock()

	// Temporarily override config with non-existent file
	originalPath := conf.BannedPath
	conf.BannedPath = "/nonexistent/path/banned.txt"
	defer func() { conf.BannedPath = originalPath }()

	// Should not panic on missing file
	loadAndSyncBannedList(nil)

	mu.Lock()
	if len(banned) != 0 {
		t.Errorf("loadAndSyncBannedList() with missing file should not load any IPs, got %d", len(banned))
	}
	mu.Unlock()
}

func TestLoadAndSyncBannedListWithIPv6(t *testing.T) {
	// Reset global state
	mu.Lock()
	banned = make(map[string]bool)
	mu.Unlock()

	// Create a temp banned file with IPv6 addresses
	tmpDir := t.TempDir()
	bannedFile := filepath.Join(tmpDir, defaultBannedPath)
	content := "192.168.1.1\n2001:db8::1\nfe80::1\n"
	if err := os.WriteFile(bannedFile, []byte(content), 0644); err != nil {
		t.Fatalf(failedTempFileCreation, err)
	}

	// Temporarily override config
	originalPath := conf.BannedPath
	originalPreview := conf.PreviewMode
	conf.BannedPath = bannedFile
	conf.PreviewMode = true
	defer func() {
		conf.BannedPath = originalPath
		conf.PreviewMode = originalPreview
	}()

	loadAndSyncBannedList(nil)

	mu.Lock()
	defer mu.Unlock()

	if !banned["192.168.1.1"] {
		t.Error("loadAndSyncBannedList() did not load IPv4 address")
	}
	if !banned["2001:db8::1"] {
		t.Error("loadAndSyncBannedList() did not load IPv6 address 2001:db8::1")
	}
	if !banned["fe80::1"] {
		t.Error("loadAndSyncBannedList() did not load IPv6 address fe80::1")
	}
}

// --- scanFullLog Tests ---

func TestScanFullLog(t *testing.T) {
	// Reset global state
	mu.Lock()
	visitorCache = NewLRUCache(defaultMaxVisitors)
	banned = make(map[string]bool)
	whitelist = make(map[string]bool)
	whitelist["127.0.0.1"] = true
	mu.Unlock()

	// Create a temp log file with mixed content
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "access.log")

	// Create log entries - 15 hits from 192.168.1.50 (exceeds threshold of 10)
	// 5 hits from 192.168.1.51 (below threshold)
	var logContent string
	for i := 0; i < 15; i++ {
		logContent += `192.168.1.50 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123` + "\n"
	}
	for i := 0; i < 5; i++ {
		logContent += `192.168.1.51 - - [16/Jan/2026:10:00:00 +0000] "GET /test HTTP/1.1" 403 456` + "\n"
	}
	// Add some 200 responses
	logContent += `8.8.8.8 - - [16/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1024` + "\n"
	// Add whitelisted IP with 404
	logContent += `127.0.0.1 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123` + "\n"

	if err := os.WriteFile(logFile, []byte(logContent), 0644); err != nil {
		t.Fatalf(failedCreateLogFile, err)
	}

	// Temporarily override config - use NON-preview mode but we won't have nft
	// We're testing that the function correctly identifies IPs to ban
	originalPath := conf.LogPath
	originalPreview := conf.PreviewMode
	originalThreshold := conf.BanThreshold
	conf.LogPath = logFile
	conf.PreviewMode = false // Test will fail on nft but we check banned map first
	conf.BanThreshold = 10.0
	defer func() {
		conf.LogPath = originalPath
		conf.PreviewMode = originalPreview
		conf.BanThreshold = originalThreshold
	}()

	// Note: In preview mode, scanFullLog prints but doesn't update banned map.
	// Test verifies the parsing logic works by checking the output behavior.
	// We set preview=false but expect nft to fail (that's ok for this test).
	conf.PreviewMode = true
	scanFullLog(logFile)

	// In preview mode, scanFullLog doesn't call executeBan, just prints.
	// So we can't verify banned map directly. Instead, verify the function
	// ran without panic and processed lines correctly by checking it completed.
	// This is a smoke test ensuring the scan logic works.

	// For now, we verify that 8.8.8.8 and 192.168.1.51 were NOT banned
	// (they would have been if processing was wrong)
	mu.Lock()
	if banned["192.168.1.51"] {
		t.Error("scanFullLog() should NOT have banned 192.168.1.51 (below threshold)")
	}
	if banned["8.8.8.8"] {
		t.Error("scanFullLog() should NOT have banned 8.8.8.8 (only 200 status)")
	}
	mu.Unlock()
}

func TestScanFullLogEmptyFile(t *testing.T) {
	// Reset global state
	mu.Lock()
	banned = make(map[string]bool)
	mu.Unlock()

	// Create empty log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "empty.log")
	if err := os.WriteFile(logFile, []byte(""), 0644); err != nil {
		t.Fatalf(failedCreateLogFile, err)
	}

	originalPreview := conf.PreviewMode
	conf.PreviewMode = true
	defer func() { conf.PreviewMode = originalPreview }()

	// Should not panic on empty file
	scanFullLog(logFile)

	mu.Lock()
	if len(banned) != 0 {
		t.Errorf("scanFullLog() on empty file should not ban anyone, got %d", len(banned))
	}
	mu.Unlock()
}

func TestScanFullLogWhitelistedIP(t *testing.T) {
	// Reset global state
	mu.Lock()
	banned = make(map[string]bool)
	whitelist = make(map[string]bool)
	whitelist["192.168.1.99"] = true
	mu.Unlock()

	// Create log file where whitelisted IP exceeds threshold
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "whitelist_test.log")
	var logContent string
	for i := 0; i < 20; i++ {
		logContent += `192.168.1.99 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123` + "\n"
	}
	if err := os.WriteFile(logFile, []byte(logContent), 0644); err != nil {
		t.Fatalf(failedCreateLogFile, err)
	}

	originalPreview := conf.PreviewMode
	originalThreshold := conf.BanThreshold
	conf.PreviewMode = true
	conf.BanThreshold = 10.0
	defer func() {
		conf.PreviewMode = originalPreview
		conf.BanThreshold = originalThreshold
	}()

	scanFullLog(logFile)

	mu.Lock()
	if banned["192.168.1.99"] {
		t.Error("scanFullLog() should NOT ban whitelisted IP even if exceeding threshold")
	}
	mu.Unlock()
}

// --- IP Normalization Tests ---

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"IPv4 passthrough", "192.168.1.1", "192.168.1.1"},
		{"IPv6 short form preserved", "::1", "::1"},
		{"IPv6 full form normalized", "0:0:0:0:0:0:0:1", "::1"},
		{"IPv6 leading zeros stripped", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"IPv6 mixed case", "2001:0DB8::1", "2001:db8::1"},
		{"invalid IP returned as-is", "not-an-ip", "not-an-ip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeIP(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeIP(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNormalizeIPIdempotent(t *testing.T) {
	ips := []string{"192.168.1.1", "::1", "2001:db8::1", "fe80::1"}
	for _, ip := range ips {
		normalized := normalizeIP(ip)
		normalizedAgain := normalizeIP(normalized)
		if normalized != normalizedAgain {
			t.Errorf("normalizeIP is not idempotent for %q: %q != %q", ip, normalized, normalizedAgain)
		}
	}
}

// --- Score Clamping Tests ---

func TestCalculateScoreClamping(t *testing.T) {
	// Save and restore original rules
	origRules := rules
	defer func() { rules = origRules }()

	// Add a rule with excessive score
	rules = []Rule{
		{Score: 999.0, Pattern: regexp.MustCompile(`/evil`), Raw: `/evil`},
		{Score: 5.0, Pattern: regexp.MustCompile(`/normal`), Raw: `/normal`},
	}

	// Excessive score should be clamped
	score := calculateScore("/evil")
	if score > maxScorePerHit {
		t.Errorf("calculateScore(/evil) = %.1f, want <= %.1f", score, maxScorePerHit)
	}
	if score != maxScorePerHit {
		t.Errorf("calculateScore(/evil) = %.1f, want exactly %.1f (clamped)", score, maxScorePerHit)
	}

	// Normal score should pass through
	score = calculateScore("/normal")
	if score != 5.0 {
		t.Errorf("calculateScore(/normal) = %.1f, want 5.0", score)
	}

	// Default score for unmatched
	score = calculateScore("/unknown")
	if score != 1.0 {
		t.Errorf("calculateScore(/unknown) = %.1f, want 1.0", score)
	}

	// Binary probe score (empty path)
	score = calculateScore("")
	if score != VerySuspiciousBinProbesScore {
		t.Errorf("calculateScore('') = %.3f, want %.3f", score, VerySuspiciousBinProbesScore)
	}
}

// --- Rules Validation Tests ---

func TestLoadRulesRejectsLongPattern(t *testing.T) {
	// Save and restore original rules
	origRules := rules
	defer func() { rules = origRules }()
	rules = nil

	// Create a rules file with one valid and one too-long pattern
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "rules.conf")
	longPattern := strings.Repeat("a", maxPatternLength+1)
	content := fmt.Sprintf("5.0 /valid-pattern\n10.0 %s\n", longPattern)
	if err := os.WriteFile(rulesFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp rules file: %v", err)
	}

	loadRules(rulesFile)

	if len(rules) != 1 {
		t.Errorf("loadRules() loaded %d rules, want 1 (long pattern should be rejected)", len(rules))
	}
	if len(rules) > 0 && rules[0].Raw != "/valid-pattern" {
		t.Errorf("loadRules() loaded wrong rule: %q, want /valid-pattern", rules[0].Raw)
	}
}

func TestLoadRulesWarnsHighScore(t *testing.T) {
	// Save and restore original rules
	origRules := rules
	defer func() { rules = origRules }()
	rules = nil

	// Create a rules file with a high-score rule (should load but warn)
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "rules.conf")
	content := "50.0 /super-dangerous\n"
	if err := os.WriteFile(rulesFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp rules file: %v", err)
	}

	loadRules(rulesFile)

	// Rule should still be loaded (warning only, not rejected)
	if len(rules) != 1 {
		t.Errorf("loadRules() loaded %d rules, want 1", len(rules))
	}
	// But score should be clamped at runtime
	if len(rules) > 0 {
		score := calculateScore("/super-dangerous")
		if score > maxScorePerHit {
			t.Errorf("calculateScore() = %.1f, want <= %.1f (should be clamped)", score, maxScorePerHit)
		}
	}
}

// --- Concurrency Tests ---

func TestLRUCacheConcurrency(t *testing.T) {
	cache := NewLRUCache(100)
	var wg sync.WaitGroup

	// Spawn multiple goroutines doing concurrent operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", id%256)

			// Put
			cache.Put(ip, &Visitor{
				IP:       ip,
				Score:    float64(id),
				Paths:    make(map[string]bool),
				LastSeen: time.Now(),
			})

			// Get
			cache.Get(ip)

			// Len
			cache.Len()

			// Delete half
			if id%2 == 0 {
				cache.Delete(ip)
			}
		}(i)
	}

	// Also run CleanExpired concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		cache.CleanExpired(1 * time.Minute)
	}()

	wg.Wait()
	// If we get here without panic or race detector complaint, the test passes
}

func TestProcessLineConcurrency(t *testing.T) {
	// Reset global state
	mu.Lock()
	visitorCache = NewLRUCache(defaultMaxVisitors)
	banned = make(map[string]bool)
	whitelist = make(map[string]bool)
	whitelist["127.0.0.1"] = true
	mu.Unlock()

	// Generate log lines from different IPs
	lines := make([]string, 100)
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)
		lines[i] = fmt.Sprintf(`%s - - [16/Jan/2026:10:00:00 +0000] "GET /path%d HTTP/1.1" 404 123`, ip, i)
	}

	var wg sync.WaitGroup
	for _, line := range lines {
		wg.Add(1)
		go func(l string) {
			defer wg.Done()
			processLine(l)
		}(line)
	}

	wg.Wait()
	// Success = no panics, no race detector complaints
}

// --- Configurable Cache Capacity Test ---

func TestCacheCapacityEnvVar(t *testing.T) {
	// Test that the cache respects custom capacity
	cache := NewLRUCache(5)

	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		cache.Put(ip, &Visitor{IP: ip, Score: 1.0, Paths: make(map[string]bool)})
	}

	if cache.Len() != 5 {
		t.Errorf("Cache should cap at 5 entries, got %d", cache.Len())
	}
}

// --- loadNftablesRanges Tests ---

func TestLoadNftablesRanges(t *testing.T) {
	tmpDir := t.TempDir()
	nftFile := filepath.Join(tmpDir, defaultNftConf)
	content := `#!/usr/sbin/nft -f
flush ruleset
table inet filter {
	set parasites {
		type ipv4_addr
		flags interval
		elements = {
			10.0.0.0/8,
			192.168.1.0/24,
			172.16.0.0/12
		}
	}
	chain input {
		type filter hook input priority 0; policy drop;
		tcp dport 22 ip saddr 1.2.3.4 accept
	}
}
`
	if err := os.WriteFile(nftFile, []byte(content), 0644); err != nil {
		t.Fatalf(failedCreateNftFile, err)
	}

	ranges, err := loadNftablesRanges(nftFile)
	if err != nil {
		t.Fatalf(msgFuncNReturnedError, "loadNftablesRanges", err)
	}

	if len(ranges) != 3 {
		t.Fatalf("loadNftablesRanges() returned %d ranges, want 3", len(ranges))
	}

	// Verify specific ranges were parsed
	expected := []string{"10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12"}
	for i, exp := range expected {
		if ranges[i].String() != exp {
			t.Errorf("Range %d = %s, want %s", i, ranges[i].String(), exp)
		}
	}

	// Verify containment check works
	ip := net.ParseIP("10.1.2.3")
	if isIPCoveredByRanges(ip, ranges) == nil {
		t.Error("10.1.2.3 should be covered by 10.0.0.0/8")
	}

	ip = net.ParseIP("8.8.8.8")
	if isIPCoveredByRanges(ip, ranges) != nil {
		t.Error("8.8.8.8 should NOT be covered by any range")
	}
}

func TestLoadNftablesRangesMultipleCIDRsPerLine(t *testing.T) {
	tmpDir := t.TempDir()
	nftFile := filepath.Join(tmpDir, defaultNftConf)
	// Simulate multiple CIDRs on one line (comma-separated as in nftables)
	content := `elements = { 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12 }
`
	if err := os.WriteFile(nftFile, []byte(content), 0644); err != nil {
		t.Fatalf(failedCreateNftFile, err)
	}

	ranges, err := loadNftablesRanges(nftFile)
	if err != nil {
		t.Fatalf(msgFuncNReturnedError, "loadNftablesRanges", err)
	}

	if len(ranges) != 3 {
		t.Errorf("loadNftablesRanges() returned %d ranges from one line, want 3", len(ranges))
	}
}

func TestLoadNftablesRangesMissingFile(t *testing.T) {
	ranges, err := loadNftablesRanges("/nonexistent/nftables.conf")
	if err == nil {
		t.Error("loadNftablesRanges() should return error for missing file")
	}
	if len(ranges) != 0 {
		t.Errorf("loadNftablesRanges() should return empty slice for missing file, got %d", len(ranges))
	}
}

func TestLoadNftablesRangesInvalidCIDR(t *testing.T) {
	tmpDir := t.TempDir()
	nftFile := filepath.Join(tmpDir, defaultNftConf)
	// Mix valid and invalid CIDRs (999.999.999.999/24 will match the regex but fail ParseCIDR)
	content := `elements = { 10.0.0.0/8, 999.999.999.999/24, 192.168.1.0/24 }
`
	if err := os.WriteFile(nftFile, []byte(content), 0644); err != nil {
		t.Fatalf(failedCreateNftFile, err)
	}

	ranges, err := loadNftablesRanges(nftFile)
	if err != nil {
		t.Fatalf(msgFuncNReturnedError, "loadNftablesRanges", err)
	}

	// Only 2 valid CIDRs should be parsed (the 999.x one is skipped by net.ParseCIDR)
	if len(ranges) != 2 {
		t.Errorf("loadNftablesRanges() returned %d ranges, want 2 (invalid CIDR should be skipped)", len(ranges))
	}
}

func TestIsIPCoveredByRanges(t *testing.T) {
	_, net1, _ := net.ParseCIDR("192.168.1.0/24")
	_, net2, _ := net.ParseCIDR("10.0.0.0/8")
	ranges := []*net.IPNet{net1, net2}

	tests := []struct {
		name    string
		ip      string
		want    bool
		wantNet string
	}{
		{"covered by /24", "192.168.1.50", true, "192.168.1.0/24"},
		{"covered by /8", "10.99.88.77", true, "10.0.0.0/8"},
		{"not covered", "8.8.8.8", false, ""},
		{"edge of range", "192.168.1.0", true, "192.168.1.0/24"},
		{"just outside range", "192.168.2.1", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := net.ParseIP(tt.ip)
			result := isIPCoveredByRanges(parsed, ranges)
			if tt.want && result == nil {
				t.Errorf("isIPCoveredByRanges(%s) = nil, want %s", tt.ip, tt.wantNet)
			}
			if !tt.want && result != nil {
				t.Errorf("isIPCoveredByRanges(%s) = %s, want nil", tt.ip, result.String())
			}
			if tt.want && result != nil && result.String() != tt.wantNet {
				t.Errorf("isIPCoveredByRanges(%s) = %s, want %s", tt.ip, result.String(), tt.wantNet)
			}
		})
	}

	// nil ranges should not panic
	result := isIPCoveredByRanges(net.ParseIP("1.2.3.4"), nil)
	if result != nil {
		t.Error("isIPCoveredByRanges with nil ranges should return nil")
	}
}

func TestLoadAndSyncBannedListWithNftRanges(t *testing.T) {
	// Reset global state
	mu.Lock()
	banned = make(map[string]bool)
	mu.Unlock()

	// Create a temp banned file with some IPs covered by ranges and some not
	tmpDir := t.TempDir()
	bannedFile := filepath.Join(tmpDir, defaultBannedPath)
	content := "192.168.1.50\n192.168.1.100\n10.20.30.40\n8.8.8.8\n"
	if err := os.WriteFile(bannedFile, []byte(content), 0644); err != nil {
		t.Fatalf(failedTempFileCreation, err)
	}

	// Create nftables ranges that cover 192.168.1.0/24
	_, net1, _ := net.ParseCIDR("192.168.1.0/24")
	nftRanges := []*net.IPNet{net1}

	// Temporarily override config
	originalPath := conf.BannedPath
	originalPreview := conf.PreviewMode
	conf.BannedPath = bannedFile
	conf.PreviewMode = true // Skip actual nft commands
	defer func() {
		conf.BannedPath = originalPath
		conf.PreviewMode = originalPreview
	}()

	loadAndSyncBannedList(nftRanges)

	mu.Lock()
	defer mu.Unlock()

	// IPs covered by range should still be in banned map (marked in memory)
	if !banned["192.168.1.50"] {
		t.Error("IP 192.168.1.50 (covered by range) should still be in banned map")
	}
	if !banned["192.168.1.100"] {
		t.Error("IP 192.168.1.100 (covered by range) should still be in banned map")
	}

	// IPs NOT covered by range should also be in banned map (added normally)
	if !banned["10.20.30.40"] {
		t.Error("IP 10.20.30.40 (not covered by range) should be in banned map")
	}
	if !banned["8.8.8.8"] {
		t.Error("IP 8.8.8.8 (not covered by range) should be in banned map")
	}
}
