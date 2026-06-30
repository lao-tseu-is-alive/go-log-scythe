// Package safety is responsible for building the list of IPs that
// must never be banned (localhost, current SSH session, entries from
// whitelist file, and current UFW allow rules).
package safety

import (
	"bufio"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/lao-tseu-is-alive/go-log-scythe/internal/parser"
)

// Whitelist is the global set of protected IPs.
// It is intentionally a package-level map protected by a mutex
// because it is read from many hot paths.
var (
	whitelist   = make(map[string]bool)
	whitelistMu sync.RWMutex
)

// Load populates the (internal) whitelist.
func Load(whitelistPath, ufwBinary string) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	loadLocked(whitelistPath, ufwBinary)
}

// loadLocked does the work (assumes lock held).
func loadLocked(whitelistPath, ufwBinary string) {
	// Reset before repopulating so that stale entries from a previous Load call
	// (e.g. from a prior Monitor.New in tests) do not persist.
	for k := range whitelist {
		delete(whitelist, k)
	}
	whitelist["127.0.0.1"] = true
	whitelist["::1"] = true

	if ssh := os.Getenv("SSH_CONNECTION"); ssh != "" {
		if fields := strings.Fields(ssh); len(fields) > 0 && parser.IsValidIP(fields[0]) {
			norm := parser.NormalizeIP(fields[0])
			log.Printf("🛡️  SAFETY: Whitelisting current SSH session IP: %s", norm)
			whitelist[norm] = true
		}
	}

	if whitelistPath != "" {
		if f, err := os.Open(whitelistPath); err == nil {
			defer f.Close()
			s := bufio.NewScanner(f)
			for s.Scan() {
				ip := strings.TrimSpace(s.Text())
				if parser.IsValidIP(ip) {
					whitelist[parser.NormalizeIP(ip)] = true
				}
			}
		}
	}

	if ufwBinary != "" {
		if out, err := exec.Command(ufwBinary, "status").Output(); err == nil {
			re := regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})`)
			for _, ip := range re.FindAllString(string(out), -1) {
				whitelist[parser.NormalizeIP(ip)] = true
			}
		}
	}
}

// IsWhitelisted reports whether the given (normalized) IP must never be banned.
func IsWhitelisted(ip string) bool {
	whitelistMu.RLock()
	defer whitelistMu.RUnlock()
	return whitelist[ip]
}

// Populate populates the provided map with the current safety whitelist.
// Used during migration of the main package.
func Populate(dst map[string]bool) {
	whitelistMu.RLock()
	defer whitelistMu.RUnlock()
	for k, v := range whitelist {
		dst[k] = v
	}
}

// AddForTest is only for unit tests. Do not use in production code.
func AddForTest(ip string) {
	whitelistMu.Lock()
	whitelist[ip] = true
	whitelistMu.Unlock()
}
