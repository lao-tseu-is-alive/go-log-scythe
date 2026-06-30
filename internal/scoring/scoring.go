// Package scoring implements the threat scoring engine.
//
// It loads user-defined rules from a rules.conf file and computes
// a danger score for each requested URL path. High scores lead to
// automatic banning.
package scoring

import (
	"bufio"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Rule is a single threat detection rule loaded from rules.conf.
type Rule struct {
	Score   float64
	Pattern *regexp.Regexp
	Raw     string // Original pattern (for logging / debugging)
}

// MaxScorePerHit is the hard cap applied to any single rule.
// This prevents a single misconfigured rule from instantly banning everyone.
const MaxScorePerHit = 20.0

var (
	rules   []Rule
	rulesMu sync.RWMutex
)

// Load reads threat detection rules from the given path.
//
// The file format is:
//
//	<score> <regex>
//
// Lines starting with # are ignored. The function is safe to call
// multiple times (e.g. on SIGHUP reload).
func Load(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("⚠️  WARN: Cannot open rules file %q: %v (using default scoring)", path, err)
		return
	}
	defer file.Close()

	var loaded []Rule
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			log.Printf("⚠️  WARN: Invalid rule format at line %d: %s", lineNum, line)
			continue
		}

		score, err := parseScore(strings.TrimSpace(parts[0]))
		if err != nil {
			log.Printf("⚠️  WARN: Invalid score at line %d: %s", lineNum, parts[0])
			continue
		}

		pattern := strings.TrimSpace(parts[1])
		if len(pattern) > 512 {
			log.Printf("⚠️  WARN: Rejecting rule at line %d: pattern too long", lineNum)
			continue
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Printf("⚠️  WARN: Invalid regex at line %d: %s (%v)", lineNum, pattern, err)
			continue
		}

		if score > MaxScorePerHit {
			log.Printf("⚠️  WARN: Rule at line %d has score %.1f (will be clamped to %.1f)",
				lineNum, score, MaxScorePerHit)
		}

		loaded = append(loaded, Rule{
			Score:   score,
			Pattern: re,
			Raw:     pattern,
		})
	}

	rulesMu.Lock()
	rules = loaded
	rulesMu.Unlock()

	log.Printf("📋 Loaded %d threat detection rules from %s", len(loaded), path)
}

// Calculate returns the threat score for a given URL path.
//
// Special case: an empty path means the request did not look like HTTP
// at all (binary probe). These get a very high fixed score.
func Calculate(urlPath string) float64 {
	if urlPath == "" {
		return 12.666 // Binary protocol probe (RDP / TLS / SMB)
	}

	rulesMu.RLock()
	defer rulesMu.RUnlock()

	for _, r := range rules {
		if r.Pattern.MatchString(urlPath) {
			if r.Score > MaxScorePerHit {
				return MaxScorePerHit
			}
			return r.Score
		}
	}
	return 1.0 // default score for ordinary 404s
}

// GetRules returns a snapshot of the currently loaded rules.
func GetRules() []Rule {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	dst := make([]Rule, len(rules))
	copy(dst, rules)
	return dst
}

func parseScore(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

// Note: we will replace the parse helper properly when integrating.
