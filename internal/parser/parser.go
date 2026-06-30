// Package parser contains all logic related to parsing web server log lines.
//
// It understands both standard Combined Log Format and custom formats
// provided via REGEX_OVERRIDE. It is also tolerant to binary garbage
// that appears when attackers send non-HTTP protocols to web ports.
package parser

import (
	"net"
	"regexp"
)

// TryMatch attempts to extract the client IP and HTTP status code
// using the provided regular expression.
//
// It expects the regex to have at least two capturing groups:
// group 1 = IP, group 2 = status code.
//
// Returns the extracted values and a boolean indicating success.
func TryMatch(re *regexp.Regexp, line string) (ip, status string, ok bool) {
	m := re.FindStringSubmatch(line)
	if len(m) < 3 {
		return "", "", false
	}
	return m[1], m[2], true
}

// TryMatchWithPath is like TryMatch but also extracts the requested URL path.
//
// It expects three capturing groups: IP, path, status.
//
// This version is used by the default log regex so we can apply
// path-based threat scoring.
func TryMatchWithPath(re *regexp.Regexp, line string) (ip, urlPath, status string, ok bool) {
	m := re.FindStringSubmatch(line)
	if len(m) < 4 {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

// IsValidIP reports whether s is a valid IPv4 or IPv6 address.
func IsValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

// NormalizeIP returns the canonical string representation of an IP address.
//
// This is important for IPv6 because the same address can be written
// in many different ways (::1 vs 0:0:0:0:0:0:0:1).
func NormalizeIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}
