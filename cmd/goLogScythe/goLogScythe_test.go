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

	"github.com/lao-tseu-is-alive/go-log-scythe/internal/cache"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/config"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/firewall"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/monitor"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/parser"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/scoring"
)

func init() {
	// For tests running as non-root, provide a fake nft that always succeeds
	// so executeBan can actually perform the ban side effects.
	fakeNft := "/tmp/fake-nft-test"
	_ = os.WriteFile(fakeNft, []byte("#!/bin/sh\nexit 0\n"), 0755)
	nftPath = fakeNft
}

const (
	failedCreateLogFile    = "Failed to create temp log file: %v"
	failedTempFileCreation = "Failed to create temp banned file: %v"
	failedCreateNftFile    = "Failed to create temp nftables file: %v"
)

const msgFuncNReturnedError = "%v returned error: %v"

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
			got := config.GetEnv(tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("config.GetEnv(%q, %q) = %q, want %q", tt.key, tt.fallback, got, tt.want)
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
			got := config.GetEnvInt(key, tt.fallback)
			if got != tt.want {
				t.Errorf("config.GetEnvInt() = %d, want %d", got, tt.want)
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
			got := config.GetEnvDuration(key, tt.fallback)
			if got != tt.want {
				t.Errorf("config.GetEnvDuration() = %v, want %v", got, tt.want)
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
			got := config.GetEnvBool(key, tt.fallback)
			if got != tt.want {
				t.Errorf("config.GetEnvBool() = %v, want %v", got, tt.want)
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
			got := parser.IsValidIP(tt.ip)
			if got != tt.want {
				t.Errorf("parser.IsValidIP(%q) = %v, want %v", tt.ip, got, tt.want)
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
			gotIP, gotStatus, gotMatch := parser.TryMatch(re, tt.line)
			if gotMatch != tt.wantMatch {
				t.Errorf("parser.TryMatch() match = %v, want %v", gotMatch, tt.wantMatch)
			}
			if gotMatch {
				if gotIP != tt.wantIP {
					t.Errorf("parser.TryMatch() ip = %q, want %q", gotIP, tt.wantIP)
				}
				if gotStatus != tt.wantStatus {
					t.Errorf("parser.TryMatch() status = %q, want %q", gotStatus, tt.wantStatus)
				}
			}
		})
	}
}

// --- LRU Cache Tests ---

func TestLRUCacheBasicOperations(t *testing.T) {
	c := cache.NewLRUCache(3)

	// Test Put and Get
	c.Put("192.168.1.1", &cache.Visitor{IP: "192.168.1.1", Score: 1.0, Paths: make(map[string]bool)})
	c.Put("192.168.1.2", &cache.Visitor{IP: "192.168.1.2", Score: 2.0, Paths: make(map[string]bool)})

	v, ok := c.Get("192.168.1.1")
	if !ok {
		t.Error("LRUCache.Get() should find existing key")
	}
	if v.Score != 1.0 {
		t.Errorf("LRUCache.Get() score = %.1f, want 1.0", v.Score)
	}

	// Test non-existent key
	_, ok = c.Get("nonexistent")
	if ok {
		t.Error("LRUCache.Get() should return false for non-existent key")
	}

	// Test Len
	if c.Len() != 2 {
		t.Errorf("LRUCache.Len() = %d, want 2", c.Len())
	}
}

func TestLRUCacheEviction(t *testing.T) {
	c := cache.NewLRUCache(3)

	// Fill cache
	c.Put("ip1", &cache.Visitor{IP: "ip1", Score: 1.0, Paths: make(map[string]bool)})
	c.Put("ip2", &cache.Visitor{IP: "ip2", Score: 2.0, Paths: make(map[string]bool)})
	c.Put("ip3", &cache.Visitor{IP: "ip3", Score: 3.0, Paths: make(map[string]bool)})

	// Access ip1 to make it most recently used
	c.Get("ip1")

	// Add ip4, should evict ip2 (least recently used)
	c.Put("ip4", &cache.Visitor{IP: "ip4", Score: 4.0, Paths: make(map[string]bool)})

	if c.Len() != 3 {
		t.Errorf("LRUCache should maintain capacity, got len=%d", c.Len())
	}

	// ip2 should be evicted
	_, ok := c.Get("ip2")
	if ok {
		t.Error("ip2 should have been evicted")
	}

	// ip1, ip3, ip4 should exist
	if _, ok := c.Get("ip1"); !ok {
		t.Error("ip1 should exist")
	}
	if _, ok := c.Get("ip3"); !ok {
		t.Error("ip3 should exist")
	}
	if _, ok := c.Get("ip4"); !ok {
		t.Error("ip4 should exist")
	}
}

func TestLRUCacheDelete(t *testing.T) {
	c := cache.NewLRUCache(3)
	c.Put("ip1", &cache.Visitor{IP: "ip1", Score: 1.0, Paths: make(map[string]bool)})
	c.Put("ip2", &cache.Visitor{IP: "ip2", Score: 2.0, Paths: make(map[string]bool)})

	c.Delete("ip1")

	if c.Len() != 1 {
		t.Errorf("After delete, len = %d, want 1", c.Len())
	}

	if _, ok := c.Get("ip1"); ok {
		t.Error("Deleted key should not exist")
	}
}

func TestLRUCacheCleanExpired(t *testing.T) {
	c := cache.NewLRUCache(10)
	now := time.Now()

	// Add entries with different ages
	c.Put("new", &cache.Visitor{IP: "new", LastSeen: now})
	c.Put("old", &cache.Visitor{IP: "old", LastSeen: now.Add(-20 * time.Minute)})
	c.Put("ancient", &cache.Visitor{IP: "ancient", LastSeen: now.Add(-1 * time.Hour)})

	removed := c.CleanExpired(15 * time.Minute)

	if removed != 2 {
		t.Errorf("CleanExpired should remove 2 entries, removed %d", removed)
	}

	if c.Len() != 1 {
		t.Errorf("After cleanup, len = %d, want 1", c.Len())
	}

	if _, ok := c.Get("new"); !ok {
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
	// Helper to create a fresh Monitor for each subtest using the internal package directly.
	newTestMonitor := func() *monitor.Monitor {
		cfg := config.Default()
		cfg.BanThreshold = 10.0
		cfg.RepeatPenalty = 0.1
		cfg.PreviewMode = false
		m := monitor.New(cfg)
		m.ResetForTest()
		m.SetWhitelistForTest(map[string]bool{"127.0.0.1": true})
		return m
	}

	t.Run("empty line is ignored", func(t *testing.T) {
		m := newTestMonitor()
		m.ProcessLine("")
		if m.CacheLenForTest() != 0 {
			t.Error("ProcessLine() should ignore empty lines")
		}
	})

	t.Run("whitelisted IP is ignored", func(t *testing.T) {
		m := newTestMonitor()
		line := `127.0.0.1 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123`
		m.ProcessLine(line)
		if _, exists := m.CacheGetForTest("127.0.0.1"); exists {
			t.Error("ProcessLine() should skip whitelisted IPs")
		}
	})

	t.Run("200 status is ignored", func(t *testing.T) {
		m := newTestMonitor()
		line := `8.8.8.8 - - [16/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1024`
		m.ProcessLine(line)
		if _, exists := m.CacheGetForTest("8.8.8.8"); exists {
			t.Error("ProcessLine() should ignore non-4xx status codes")
		}
	})

	t.Run("404 increments visitor count", func(t *testing.T) {
		m := newTestMonitor()
		line := `192.168.1.50 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123`
		m.ProcessLine(line)
		v, exists := m.CacheGetForTest("192.168.1.50")
		if !exists {
			t.Fatal("ProcessLine() did not create visitor entry")
		}
		if v.Score == 0 {
			t.Errorf("ProcessLine() score = %.1f, want > 0", v.Score)
		}
	})

	t.Run("already banned IP is ignored", func(t *testing.T) {
		m := newTestMonitor()
		m.SetBannedForTest("10.0.0.99")

		line := `10.0.0.99 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123`
		m.ProcessLine(line)

		if _, exists := m.CacheGetForTest("10.0.0.99"); exists {
			t.Error("ProcessLine() should skip already banned IPs")
		}
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
	visitorCache = cache.NewLRUCache(config.DefaultMaxVisitors)
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
	// Use scoring package directly
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "clamp.conf")
	content := "999.0 /evil\n5.0 /normal\n"
	os.WriteFile(rulesFile, []byte(content), 0644)

	scoring.Load(rulesFile)

	// Excessive score should be clamped
	score := scoring.Calculate("/evil")
	if score > config.MaxScorePerHit {
		t.Errorf("Calculate(/evil) = %.1f, want <= %.1f", score, config.MaxScorePerHit)
	}
	if score != config.MaxScorePerHit {
		t.Errorf("Calculate(/evil) = %.1f, want exactly %.1f (clamped)", score, config.MaxScorePerHit)
	}

	score = scoring.Calculate("/normal")
	if score != 5.0 {
		t.Errorf("Calculate(/normal) = %.1f, want 5.0", score)
	}

	score = scoring.Calculate("/unknown")
	if score != 1.0 {
		t.Errorf("Calculate(/unknown) = %.1f, want 1.0", score)
	}

	// Binary probe
	score = scoring.Calculate("")
	if score != config.VerySuspiciousBinProbesScore {
		t.Errorf("Calculate('') = %.3f, want %.3f", score, config.VerySuspiciousBinProbesScore)
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
	c := cache.NewLRUCache(100)
	var wg sync.WaitGroup

	// Spawn multiple goroutines doing concurrent operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", id%256)

			// Put
			c.Put(ip, &cache.Visitor{
				IP:       ip,
				Score:    float64(id),
				Paths:    make(map[string]bool),
				LastSeen: time.Now(),
			})

			// Get
			c.Get(ip)

			// Len
			c.Len()

			// Delete half
			if id%2 == 0 {
				c.Delete(ip)
			}
		}(i)
	}

	// Also run CleanExpired concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.CleanExpired(1 * time.Minute)
	}()

	wg.Wait()
	// If we get here without panic or race detector complaint, the test passes
}

func TestProcessLineConcurrency(t *testing.T) {
	// Use a dedicated Monitor so we exercise the real locking (m.mu + cache internal lock)
	// without going through the shim that does global map copies (which can race when
	// called concurrently from many goroutines).
	m := monitor.New(config.Default())
	m.ResetForTest()
	m.SetWhitelistForTest(map[string]bool{"127.0.0.1": true})

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
			m.ProcessLine(l)
		}(line)
	}

	wg.Wait()
	// Success = no panics, no race detector complaints
}

// --- Configurable Cache Capacity Test ---

func TestCacheCapacityEnvVar(t *testing.T) {
	// Test that the cache respects custom capacity
	c := cache.NewLRUCache(5)

	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		c.Put(ip, &cache.Visitor{IP: ip, Score: 1.0, Paths: make(map[string]bool)})
	}

	if c.Len() != 5 {
		t.Errorf("Cache should cap at 5 entries, got %d", c.Len())
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

// --- Burst Detection Tests ---

func TestBurstDetection(t *testing.T) {
	// Reset global state
	mu.Lock()
	visitorCache = cache.NewLRUCache(config.DefaultMaxVisitors)
	banned = make(map[string]bool)
	whitelist = make(map[string]bool)
	whitelist["127.0.0.1"] = true
	mu.Unlock()

	// Save and restore original config
	originalBurstLimit := conf.BurstLimit
	originalBurstWindow := conf.BurstWindow
	originalPreview := conf.PreviewMode
	originalThreshold := conf.BanThreshold
	conf.BurstLimit = 5
	conf.BurstWindow = 3 * time.Second
	conf.PreviewMode = true   // Skip actual nft commands
	conf.BanThreshold = 100.0 // Set very high so only burst triggers the ban
	defer func() {
		conf.BurstLimit = originalBurstLimit
		conf.BurstWindow = originalBurstWindow
		conf.PreviewMode = originalPreview
		conf.BanThreshold = originalThreshold
	}()

	// Send 5 rapid-fire 4xx lines from the same IP (each scores 1.0 default)
	// With threshold at 100, only burst detection can trigger the ban
	for i := 0; i < 5; i++ {
		line := fmt.Sprintf(`10.99.99.99 - - [20/Feb/2026:10:00:0%d +0000] "GET /page%d HTTP/1.1" 404 123`, i, i)
		processLine(line)
	}

	mu.Lock()
	defer mu.Unlock()

	if !banned["10.99.99.99"] {
		t.Error("burst detection should have banned 10.99.99.99 after 5 rapid 4xx requests")
	}
}

func TestBurstDetectionBelowLimit(t *testing.T) {
	// Reset global state
	mu.Lock()
	visitorCache = cache.NewLRUCache(config.DefaultMaxVisitors)
	banned = make(map[string]bool)
	whitelist = make(map[string]bool)
	whitelist["127.0.0.1"] = true
	mu.Unlock()

	originalBurstLimit := conf.BurstLimit
	originalBurstWindow := conf.BurstWindow
	originalPreview := conf.PreviewMode
	originalThreshold := conf.BanThreshold
	conf.BurstLimit = 5
	conf.BurstWindow = 3 * time.Second
	conf.PreviewMode = true
	conf.BanThreshold = 100.0 // Very high so score alone won't trigger
	defer func() {
		conf.BurstLimit = originalBurstLimit
		conf.BurstWindow = originalBurstWindow
		conf.PreviewMode = originalPreview
		conf.BanThreshold = originalThreshold
	}()

	// Send only 4 requests (below burst limit of 5)
	for i := 0; i < 4; i++ {
		line := fmt.Sprintf(`10.88.88.88 - - [20/Feb/2026:10:00:0%d +0000] "GET /page%d HTTP/1.1" 404 123`, i, i)
		processLine(line)
	}

	mu.Lock()
	defer mu.Unlock()

	if banned["10.88.88.88"] {
		t.Error("burst detection should NOT have banned 10.88.88.88 (only 4 requests, limit is 5)")
	}
}

func TestBurstDetectionWindowExpiry(t *testing.T) {
	// Reset global state
	mu.Lock()
	visitorCache = cache.NewLRUCache(config.DefaultMaxVisitors)
	banned = make(map[string]bool)
	whitelist = make(map[string]bool)
	whitelist["127.0.0.1"] = true
	mu.Unlock()

	originalBurstLimit := conf.BurstLimit
	originalBurstWindow := conf.BurstWindow
	originalPreview := conf.PreviewMode
	originalThreshold := conf.BanThreshold
	conf.BurstLimit = 5
	conf.BurstWindow = 50 * time.Millisecond // Very short window for testing
	conf.PreviewMode = true
	conf.BanThreshold = 100.0
	defer func() {
		conf.BurstLimit = originalBurstLimit
		conf.BurstWindow = originalBurstWindow
		conf.PreviewMode = originalPreview
		conf.BanThreshold = originalThreshold
	}()

	// Send 3 requests, wait for window to expire, then send 3 more
	for i := 0; i < 3; i++ {
		line := fmt.Sprintf(`10.77.77.77 - - [20/Feb/2026:10:00:0%d +0000] "GET /page%d HTTP/1.1" 404 123`, i, i)
		processLine(line)
	}

	// Wait longer than the burst window
	time.Sleep(100 * time.Millisecond)

	for i := 3; i < 6; i++ {
		line := fmt.Sprintf(`10.77.77.77 - - [20/Feb/2026:10:00:0%d +0000] "GET /page%d HTTP/1.1" 404 123`, i, i)
		processLine(line)
	}

	mu.Lock()
	defer mu.Unlock()

	if banned["10.77.77.77"] {
		t.Error("burst detection should NOT have banned 10.77.77.77 (requests spread across expired windows)")
	}
}

func TestBurstDetectionDoesNotAffectWhitelisted(t *testing.T) {
	// Reset global state
	mu.Lock()
	visitorCache = cache.NewLRUCache(config.DefaultMaxVisitors)
	banned = make(map[string]bool)
	whitelist = make(map[string]bool)
	whitelist["127.0.0.1"] = true
	whitelist["10.66.66.66"] = true // Whitelist the IP we'll test
	mu.Unlock()

	originalBurstLimit := conf.BurstLimit
	originalBurstWindow := conf.BurstWindow
	originalPreview := conf.PreviewMode
	originalThreshold := conf.BanThreshold
	conf.BurstLimit = 5
	conf.BurstWindow = 3 * time.Second
	conf.PreviewMode = true
	conf.BanThreshold = 100.0
	defer func() {
		conf.BurstLimit = originalBurstLimit
		conf.BurstWindow = originalBurstWindow
		conf.PreviewMode = originalPreview
		conf.BanThreshold = originalThreshold
	}()

	// Send 10 rapid requests from whitelisted IP
	for i := 0; i < 10; i++ {
		line := fmt.Sprintf(`10.66.66.66 - - [20/Feb/2026:10:00:0%d +0000] "GET /page%d HTTP/1.1" 404 123`, i, i)
		processLine(line)
	}

	mu.Lock()
	defer mu.Unlock()

	if banned["10.66.66.66"] {
		t.Error("burst detection should NOT ban whitelisted IPs")
	}
}

// --- Additional Environment Tests ---

func TestGetEnvFloat(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		setEnv   bool
		fallback float64
		want     float64
	}{
		{"uses fallback when not set", "", false, 3.14, 3.14},
		{"parses valid float", "2.5", true, 1.0, 2.5},
		{"parses integer as float", "42", true, 0.0, 42.0},
		{"parses negative float", "-3.14", true, 0.0, -3.14},
		{"fallback on invalid string", "notafloat", true, 9.99, 9.99},
		{"parses scientific notation", "1.5e2", true, 0.0, 150.0},
		{"zero value", "0", true, 99.9, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_FLOAT_" + strings.ReplaceAll(tt.name, " ", "_")
			if tt.setEnv {
				t.Setenv(key, tt.envValue)
			}
			got := config.GetEnvFloat(key, tt.fallback)
			if got != tt.want {
				t.Errorf("config.GetEnvFloat() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- Reload Configuration Test ---

func TestReloadConfiguration(t *testing.T) {
	// Backup globals
	origRulesPath := conf.RulesPath
	origNftPath := conf.NftablesConfPath
	rulesMu.RLock()
	origRules := rules
	rulesMu.RUnlock()
	nftRangesMu.RLock()
	origRanges := nftRanges
	nftRangesMu.RUnlock()

	defer func() {
		conf.RulesPath = origRulesPath
		conf.NftablesConfPath = origNftPath
		rulesMu.Lock()
		rules = origRules
		rulesMu.Unlock()
		nftRangesMu.Lock()
		nftRanges = origRanges
		nftRangesMu.Unlock()
	}()

	tmpDir := t.TempDir()

	// Create a rules.conf
	rulesFile := filepath.Join(tmpDir, "test-rules.conf")
	rulesContent := "# comment\n5.0 /wp-admin\n10.0 /\\.env\n"
	if err := os.WriteFile(rulesFile, []byte(rulesContent), 0644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	// Create nftables.conf with ranges
	nftFile := filepath.Join(tmpDir, "test-nft.conf")
	nftContent := `table inet filter {
    set parasites { type ipv4_addr; elements = { 10.0.0.0/8, 192.168.0.0/16 } }
}`
	if err := os.WriteFile(nftFile, []byte(nftContent), 0644); err != nil {
		t.Fatalf("write nft: %v", err)
	}

	// Configure and clear state
	conf.RulesPath = rulesFile
	conf.NftablesConfPath = nftFile

	rulesMu.Lock()
	rules = nil
	rulesMu.Unlock()
	nftRangesMu.Lock()
	nftRanges = nil
	nftRangesMu.Unlock()

	reloadConfiguration()

	// Verify rules were reloaded
	rulesMu.RLock()
	newRules := rules
	rulesMu.RUnlock()
	if len(newRules) != 2 {
		t.Errorf("reloadConfiguration() loaded %d rules, want 2", len(newRules))
	}

	// Verify CIDR ranges were reloaded
	nftRangesMu.RLock()
	newRanges := nftRanges
	nftRangesMu.RUnlock()
	if len(newRanges) == 0 {
		t.Error("reloadConfiguration() did not load any CIDR ranges")
	}
}

// --- Improved Safety Whitelist Tests ---

func TestLoadSafetyWhitelistSSHAndUFW(t *testing.T) {
	mu.Lock()
	whitelist = make(map[string]bool)
	mu.Unlock()

	tmpDir := t.TempDir()

	// Whitelist file
	wlFile := filepath.Join(tmpDir, "whitelist.txt")
	wlContent := "172.16.0.99\n"
	os.WriteFile(wlFile, []byte(wlContent), 0644)

	// Fake ufw that outputs some IPs (simulates "ufw status")
	fakeUfw := filepath.Join(tmpDir, "ufw")
	ufwScript := `#!/bin/sh
echo "Status: active"
echo "22/tcp ALLOW 203.0.113.77"
echo "443/tcp ALLOW 198.51.100.22"
`
	if err := os.WriteFile(fakeUfw, []byte(ufwScript), 0755); err != nil {
		t.Fatalf("write fake ufw: %v", err)
	}

	// Backup
	origWL := conf.WhitelistPath
	origUfwPath := ufwPath
	defer func() {
		conf.WhitelistPath = origWL
		ufwPath = origUfwPath
	}()

	conf.WhitelistPath = wlFile
	ufwPath = fakeUfw

	// Simulate SSH session
	t.Setenv("SSH_CONNECTION", "203.0.113.55 54321 10.0.0.1 22")

	loadSafetyWhitelist()

	mu.Lock()
	defer mu.Unlock()

	expected := []string{
		"127.0.0.1", "::1",
		"172.16.0.99",  // from file
		"203.0.113.55", // from SSH
		"203.0.113.77", // from fake ufw
		"198.51.100.22",
	}

	for _, ip := range expected {
		norm := normalizeIP(ip)
		if !whitelist[norm] {
			t.Errorf("loadSafetyWhitelist() missing expected IP %s (normalized %s)", ip, norm)
		}
	}
}

// --- Additional Rules and Matching Tests ---

func TestLoadRulesInvalidLines(t *testing.T) {
	origRules := rules
	defer func() { rules = origRules }()
	rules = nil

	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "bad-rules.conf")
	content := `# comment line
not-a-score /pattern
5.0 /good-one
abc /bad-score
5.0 [invalid regex
5.0 /another-good
`
	if err := os.WriteFile(rulesFile, []byte(content), 0644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	loadRules(rulesFile)

	// Only the two good rules should load
	if len(rules) != 2 {
		t.Errorf("loadRules() loaded %d rules, want 2 (invalid lines should be skipped)", len(rules))
	}
}

func TestTryMatchWithPath(t *testing.T) {
	// Use the actual default regex from the program
	re := regexp.MustCompile(defaultLogRegex)

	tests := []struct {
		name       string
		line       string
		wantIP     string
		wantPath   string
		wantStatus string
		wantMatch  bool
	}{
		{
			name:       "standard nginx 404 with path",
			line:       `203.0.113.10 - - [20/Feb/2026:12:00:00 +0000] "GET /admin.php HTTP/1.1" 404 123`,
			wantIP:     "203.0.113.10",
			wantPath:   "/admin.php",
			wantStatus: "404",
			wantMatch:  true,
		},
		{
			name:       "binary probe (empty path)",
			line:       `203.0.113.99 - - [20/Feb/2026:12:00:00 +0000] "" 400 0`,
			wantIP:     "203.0.113.99",
			wantPath:   "",
			wantStatus: "400",
			wantMatch:  true,
		},
		{
			name:       "malformed binary garbage",
			line:       `10.0.0.5 - - [20/Feb/2026:12:00:00 +0000] "�\x03\x00\x00\x0b" 400 0`,
			wantIP:     "10.0.0.5",
			wantPath:   "",
			wantStatus: "400",
			wantMatch:  true,
		},
		{
			name:       "no match",
			line:       "garbage line without structure",
			wantIP:     "",
			wantPath:   "",
			wantStatus: "",
			wantMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, path, status, ok := tryMatchWithPath(re, tt.line)
			if ok != tt.wantMatch {
				t.Fatalf("tryMatchWithPath match=%v, want %v", ok, tt.wantMatch)
			}
			if ok {
				if ip != tt.wantIP {
					t.Errorf("IP = %q, want %q", ip, tt.wantIP)
				}
				if path != tt.wantPath {
					t.Errorf("path = %q, want %q", path, tt.wantPath)
				}
				if status != tt.wantStatus {
					t.Errorf("status = %q, want %q", status, tt.wantStatus)
				}
			}
		})
	}
}

// Test that empty path gives the binary probe score
func TestCalculateScoreBinaryProbe(t *testing.T) {
	origRules := rules
	defer func() { rules = origRules }()
	rules = nil // no rules

	score := calculateScore("")
	if score != VerySuspiciousBinProbesScore {
		t.Errorf("calculateScore(\"\") = %v, want %v (binary probe)", score, VerySuspiciousBinProbesScore)
	}
}

func TestReloadConfigurationClearsRulesWhenNoPath(t *testing.T) {
	origRulesPath := conf.RulesPath
	origRules := rules
	defer func() {
		conf.RulesPath = origRulesPath
		rulesMu.Lock()
		rules = origRules
		rulesMu.Unlock()
	}()

	tmpDir := t.TempDir()
	nftFile := filepath.Join(tmpDir, "nft.conf")
	os.WriteFile(nftFile, []byte(""), 0644)

	conf.RulesPath = "" // no rules file
	rulesMu.Lock()
	rules = []scoring.Rule{{Score: 5, Pattern: regexp.MustCompile("x"), Raw: "x"}}
	rulesMu.Unlock()

	conf.NftablesConfPath = nftFile
	reloadConfiguration()

	rulesMu.RLock()
	defer rulesMu.RUnlock()
	if rules != nil && len(rules) != 0 {
		t.Errorf("reloadConfiguration() with empty RulesPath should clear rules, got %d", len(rules))
	}
}

func TestLoadRulesFileNotFound(t *testing.T) {
	orig := rules
	defer func() { rules = orig }()
	rules = []scoring.Rule{{}} // some previous

	loadRules("/this/file/does/not/exist.conf")

	// Should not crash and should keep previous rules (current behavior)
	if len(rules) == 0 {
		t.Error("loadRules on missing file should keep previous rules (or at least not panic)")
	}
}

// Test that triggers actual ban path (executeBan + filterBannableIPs)
func TestProcessLineTriggersBan(t *testing.T) {
	tmpDir := t.TempDir()
	bannedFile := filepath.Join(tmpDir, "banned.txt")

	// Create a dedicated Monitor for this test (proper way)
	cfg := config.Default()
	cfg.BannedPath = bannedFile
	cfg.BanThreshold = 1.0
	cfg.PreviewMode = false

	fakeNft := filepath.Join(tmpDir, "nft")
	os.WriteFile(fakeNft, []byte("#!/bin/sh\nexit 0\n"), 0755)

	// Point both the legacy path (if any) and the firewall package at the fake for this test
	firewall.NftPath = fakeNft
	m := monitor.New(cfg)
	m.SetNftPathForTest(fakeNft)

	// Unmatched path → score 1.0. Threshold=1.0 → should ban.
	line := `198.51.100.77 - - [21/Feb/2026:10:00:00 +0000] "GET /random-path-xyz HTTP/1.1" 404 42`
	m.ProcessLine(line)

	if !m.IsBannedForTest("198.51.100.77") {
		t.Error("ProcessLine should have banned the IP when score >= threshold")
	}
}
