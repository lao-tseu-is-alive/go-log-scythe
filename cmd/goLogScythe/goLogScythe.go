/*
Package main implements a high-performance log monitor for 404 like http scans,
then it allows you to ban ip doing too much 404 using nftables.
It features environment-driven configuration, dual-regex fallback,
and a safety-first preview mode.
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"

	"github.com/lao-tseu-is-alive/go-log-scythe/internal/cache"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/config"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/firewall"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/monitor"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/parser"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/safety"
	"github.com/lao-tseu-is-alive/go-log-scythe/internal/scoring"
)

const (
	APP        = "goLogScythe"
	VERSION    = "0.5.0"
	REPOSITORY = "https://github.com/lao-tseu-is-alive/go-log-scythe"
)

// warnIpInExcludedRange is the message logged when we skip an IP because
// it is already covered by a broad nftables range.
const warnIpInExcludedRange = "⚠️  WARN: IP %s (score: %.1f) is already covered by nftables range %s — if traffic from this IP reached the server, verify that nftables service is running"

// The heavy lifting now lives in internal/monitor.
// We keep minimal globals only for the (large) existing integration test file during transition.
var (
	conf         config.Config
	visitorCache *cache.LRUCache
	banned       = make(map[string]bool)
	whitelist    = make(map[string]bool)
	mu           sync.Mutex
	nftRanges    []*net.IPNet
	rulesMu      sync.RWMutex
	nftRangesMu  sync.RWMutex
	nftPath      string
	ufwPath      string
	reLog        *regexp.Regexp
	reOverride   *regexp.Regexp
	rules        []scoring.Rule
)

// theGlobalMonitor is used by compatibility shims for the integration test file.
// Clean code uses monitor.New(...) directly.
var theGlobalMonitor = monitor.New(config.Load())

//func NewLRUCache(cap int) *cache.LRUCache {return cache.NewLRUCache(cap)}

func calculateScore(p string) float64 {
	return scoring.Calculate(p)
}

var VerySuspiciousBinProbesScore = config.VerySuspiciousBinProbesScore

const (
	defaultBannedPath = config.DefaultBannedPath
	maxScorePerHit    = config.MaxScorePerHit
	maxPatternLength  = config.MaxPatternLength
	defaultLogRegex   = config.DefaultLogRegex
	defaultNftConf    = config.DefaultNftConf
)

func loadSafetyWhitelist() {
	safety.Load(conf.WhitelistPath, ufwPath)
	mu.Lock()
	whitelist = make(map[string]bool)
	safety.Populate(whitelist)
	mu.Unlock()
}

func normalizeIP(s string) string { return parser.NormalizeIP(s) }

func tryMatchWithPath(re *regexp.Regexp, line string) (string, string, string, bool) {
	return parser.TryMatchWithPath(re, line)
}

// The large Monitor implementation now lives in internal/monitor.
// The shims below exist only to keep the (large) existing integration test file working
// without a full rewrite in one step. New code and most unit tests should use monitor.New()
// and its exported methods directly.

func loadAndSyncBannedList(r []*net.IPNet) {
	theGlobalMonitor.SetConfForTest(conf)

	// Only clear banned (preserve whitelist/rules/ranges set up by other test setup).
	theGlobalMonitor.ClearBannedForTest()

	theGlobalMonitor.LoadAndSyncBannedList(r)

	mu.Lock()
	banned = make(map[string]bool)
	theGlobalMonitor.SyncBannedToGlobalForTest(banned)
	mu.Unlock()
}

func scanFullLog(p string) { theGlobalMonitor.ScanFullLog(p) }

func loadRules(p string) {
	theGlobalMonitor.LoadRules(p)
	// sync via scoring global (rules are owned by scoring pkg after Load) + monitor copy
	rulesMu.Lock()
	rules = scoring.GetRules()
	rulesMu.Unlock()
}

func processLine(line string) {
	theGlobalMonitor.SetConfForTest(conf)

	// For tests that mutate the legacy global whitelist directly
	theGlobalMonitor.SetWhitelistForTest(nil)
	wlCopy := make(map[string]bool)
	for k, v := range whitelist {
		wlCopy[k] = v
	}
	theGlobalMonitor.SetWhitelistForTest(wlCopy)

	theGlobalMonitor.ProcessLine(line)

	// Sync banned back for tests that inspect the package-level banned map.
	mu.Lock()
	theGlobalMonitor.SyncBannedToGlobalForTest(banned)
	mu.Unlock()
}

func reloadConfiguration() {
	theGlobalMonitor.SetConfForTest(conf)
	theGlobalMonitor.ReloadConfiguration()

	rulesMu.Lock()
	theGlobalMonitor.SyncRulesToGlobalForTest(&rules)
	rulesMu.Unlock()

	nftRangesMu.Lock()
	theGlobalMonitor.SyncNftRangesToGlobalForTest(&nftRanges)
	nftRangesMu.Unlock()
}

func isIPCoveredByRanges(ip net.IP, ranges []*net.IPNet) *net.IPNet {
	// Delegate to firewall (or could expose on Monitor). Use the passed-in ranges for legacy test compatibility.
	return firewall.IsCoveredByRange(ip, ranges)
}

func loadNftablesRanges(p string) ([]*net.IPNet, error) {
	return theGlobalMonitor.LoadNftablesRanges(p)
}

func main() {
	versionFlag := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("%s v%s\n", APP, VERSION)
		return
	}

	fmt.Printf("🚀 🛡️ Starting App:'%s', ver:%s, Repo: %s\n", APP, VERSION, REPOSITORY)

	m := monitor.New(config.Load())

	if m.Conf().PreviewMode {
		fmt.Println("🔍 PREVIEW MODE: No real bans will be issued.")
		m.ClearBannedForPreview()
	}
	if m.Conf().ScanAllMode {
		fmt.Println("📊 SCAN ALL MODE: Reading entire log file...")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for {
			sig := <-sigChan
			if sig == syscall.SIGHUP {
				m.ReloadConfiguration()
				continue
			}
			log.Printf("\n🛑 Received %v, shutting down gracefully...", sig)
			cancel()
			return
		}
	}()

	initialRanges, err := m.LoadNftablesRanges(m.Conf().NftablesConfPath)
	if err != nil {
		log.Printf("⚠️  WARN: Cannot read nftables config '%s': %v (skipping range check)", m.Conf().NftablesConfPath, err)
	} else {
		m.SetNftRanges(initialRanges)
		if len(initialRanges) > 0 {
			log.Printf("📋 Loaded %d CIDR ranges from %s", len(initialRanges), m.Conf().NftablesConfPath)
		}
	}

	if !m.Conf().PreviewMode {
		m.LoadAndSyncBannedList(initialRanges)
	}

	if m.Conf().ScanAllMode {
		m.ScanFullLog(m.Conf().LogPath)
		return
	}

	go m.Janitor(ctx)
	m.TailLog(ctx, m.Conf().LogPath)

	log.Println("✅ LogScythe stopped.")
}
