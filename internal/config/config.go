// Package config centralizes all configuration for goLogScythe.
//
// It is responsible for:
//   - Default values
//   - Loading values from environment variables
//   - Providing the global Config instance used by the application
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Default values. These are used when the corresponding environment
// variable is not set.
const (
	DefaultLogPath          = "/var/log/nginx/access.log"
	DefaultWhitelistPath    = "./whitelist.txt"
	DefaultBannedPath       = "banned_ips.txt"
	DefaultRulesPath        = ""
	DefaultThreshold        = 10.0
	DefaultRepeatPenalty    = 0.1
	DefaultWindow           = 15 * time.Minute
	DefaultNftSet           = "parasites"
	DefaultNftSetV6         = "parasites6"
	DefaultNftConf          = "nftables.conf"
	DefaultMaxVisitors      = 10000
	DefaultBurstLimit       = 5
	DefaultBurstWindow      = 3 * time.Second
	DefaultTailPollInterval = 100 * time.Millisecond

	// VerySuspiciousBinProbesScore is the score given to requests that do
	// not look like HTTP at all (binary protocol probes: RDP, TLS, SMB...).
	VerySuspiciousBinProbesScore = 12.666

	DefaultNftPath = "/usr/sbin/nft"
	DefaultUfwPath = "/usr/sbin/ufw"

	MaxScorePerHit   = 20.0
	MaxPatternLength = 512
)

// DefaultLogRegex is the regular expression used to parse standard
// Combined Log Format lines (Nginx / Apache).
// It is tolerant to binary garbage in the request line.
const DefaultLogRegex = `(?s)^(\S+)\s+-\s+-\s+\[.*?\]\s+"(?:\S+\s+(\S*)\s+.*?|.*?)"\s+(\d{3})`

// Config holds the runtime configuration of the application.
type Config struct {
	LogPath          string
	WhitelistPath    string
	BannedPath       string
	RulesPath        string // Path to rules.conf (empty = no weighted scoring)
	NftablesConfPath string // Path to nftables.conf used for broad range pre-checks
	BanThreshold     float64
	RepeatPenalty    float64
	Window           time.Duration
	NftSetName       string
	NftSetNameV6     string
	RegexOverride    string
	BurstLimit       int
	BurstWindow      time.Duration
	TailPollInterval time.Duration
	PreviewMode      bool
	ScanAllMode      bool
}

// Default returns a Config populated with all default values.
func Default() Config {
	return Config{
		LogPath:          DefaultLogPath,
		WhitelistPath:    DefaultWhitelistPath,
		BannedPath:       DefaultBannedPath,
		RulesPath:        DefaultRulesPath,
		BanThreshold:     DefaultThreshold,
		RepeatPenalty:    DefaultRepeatPenalty,
		Window:           DefaultWindow,
		NftSetName:       DefaultNftSet,
		NftSetNameV6:     DefaultNftSetV6,
		NftablesConfPath: "/etc/" + DefaultNftConf,
		BurstLimit:       DefaultBurstLimit,
		BurstWindow:      DefaultBurstWindow,
		TailPollInterval: DefaultTailPollInterval,
	}
}

// Load populates a Config from environment variables, falling back to defaults.
func Load() Config {
	c := Default()

	c.LogPath = getEnv("LOG_PATH", c.LogPath)
	c.WhitelistPath = getEnv("WHITE_LIST_PATH", c.WhitelistPath)
	c.BannedPath = getEnv("BANNED_FILE_PATH", c.BannedPath)
	c.RulesPath = getEnv("RULES_PATH", c.RulesPath)
	c.BanThreshold = getEnvFloat("BAN_THRESHOLD", c.BanThreshold)
	c.RepeatPenalty = getEnvFloat("REPEAT_PENALTY", c.RepeatPenalty)
	c.Window = getEnvDuration("BAN_WINDOW", c.Window)
	c.NftSetName = getEnv("NFT_SET_NAME", c.NftSetName)
	c.NftSetNameV6 = getEnv("NFT_SET_NAME_V6", c.NftSetNameV6)
	c.NftablesConfPath = getEnv("NFTABLES_CONF_PATH", c.NftablesConfPath)
	c.RegexOverride = os.Getenv("REGEX_OVERRIDE")
	c.BurstLimit = getEnvInt("BURST_LIMIT", c.BurstLimit)
	c.BurstWindow = getEnvDuration("BURST_WINDOW", c.BurstWindow)
	c.TailPollInterval = getEnvDuration("TAIL_POLL_INTERVAL", c.TailPollInterval)
	c.PreviewMode = getEnvBool("PREVIEW_MODE", c.PreviewMode)
	c.ScanAllMode = getEnvBool("SCAN_ALL_MODE", c.ScanAllMode)

	return c
}

// --- Environment variable helpers (with quote stripping) ---

// lowercase for internal use in this package
func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				return val[1 : len(val)-1]
			}
		}
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if s := getEnv(key, ""); s != "" {
		if i, err := strconv.Atoi(s); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if s := getEnv(key, ""); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	s := strings.ToLower(getEnv(key, ""))
	switch s {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return fallback
	}
}

func getEnvFloat(key string, fallback float64) float64 {
	if s := getEnv(key, ""); s != "" {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return fallback
}

// Exported versions for other packages in the module
func GetEnv(key, fallback string) string     { return getEnv(key, fallback) }
func GetEnvInt(key string, fallback int) int { return getEnvInt(key, fallback) }
func GetEnvDuration(key string, fallback time.Duration) time.Duration {
	return getEnvDuration(key, fallback)
}
func GetEnvBool(key string, fallback bool) bool { return getEnvBool(key, fallback) }
func GetEnvFloat(key string, fallback float64) float64 {
	return getEnvFloat(key, fallback)
}
