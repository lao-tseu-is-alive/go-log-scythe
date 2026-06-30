// Package firewall handles all interactions with the system's firewall
// (nftables) and UFW for safety whitelisting.
//
// It provides idempotent operations and abstracts the external binaries.
package firewall

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/lao-tseu-is-alive/go-log-scythe/internal/config"
)

// Paths (can be overridden via env at startup via config)
var (
	NftPath = config.DefaultNftPath
	UfwPath = config.DefaultUfwPath
)

var (
	duplicateMessages = []string{"File exists", "already exists"}
	nftRanges         []*net.IPNet
	nftRangesMu       sync.RWMutex
)

// LoadNftablesRanges extracts CIDR ranges from the nftables config.
func LoadNftablesRanges(path string) ([]*net.IPNet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ranges []*net.IPNet
	reCIDR := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := reCIDR.FindAllString(line, -1)
		for _, match := range matches {
			_, ipNet, err := net.ParseCIDR(match)
			if err == nil {
				ranges = append(ranges, ipNet)
			}
		}
	}
	return ranges, scanner.Err()
}

// IsCoveredByRange checks if the IP is covered by any loaded range.
func IsCoveredByRange(ip net.IP, ranges []*net.IPNet) *net.IPNet {
	for _, r := range ranges {
		if r.Contains(ip) {
			return r
		}
	}
	return nil
}

// GetRanges returns a copy of current ranges.
func GetRanges() []*net.IPNet {
	nftRangesMu.RLock()
	defer nftRangesMu.RUnlock()
	dst := make([]*net.IPNet, len(nftRanges))
	copy(dst, nftRanges)
	return dst
}

// SetRanges updates the ranges (for reload).
func SetRanges(ranges []*net.IPNet) {
	nftRangesMu.Lock()
	nftRanges = ranges
	nftRangesMu.Unlock()
}

// AddIP adds the IP to the nft set idempotently.
func AddIP(ip, setName string) (ok, duplicate bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, NftPath, "add", "element", "inet", "filter", setName, "{", ip, "}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(output))
		for _, msg := range duplicateMessages {
			if strings.Contains(outStr, msg) {
				return true, true, nil
			}
		}
		return false, false, fmt.Errorf("nft add element %s to %s: %w: %s", ip, setName, err, outStr)
	}
	return true, false, nil
}

// ExecuteBan performs the ban action.
func ExecuteBan(ip string, score float64, preview bool, setName, bannedPath string) {
	if preview {
		log.Printf("👀 [PREVIEW] Would ban IP: %s (score: %.1f)", ip, score)
		return
	}

	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() == nil {
		setName = config.DefaultNftSetV6 // simplified
	}

	ok, _, err := AddIP(ip, setName)
	if err != nil {
		log.Printf("❌ ERROR: Failed to ban %s: %v", ip, err)
		return
	}
	if !ok {
		return
	}

	if f, err := os.OpenFile(bannedPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		defer f.Close()
		f.WriteString(ip + "\n")
	}

	log.Printf("🚫 BANNED: %s (set: %s)", ip, setName)
}
