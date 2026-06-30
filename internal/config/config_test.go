package config

import (
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.LogPath != DefaultLogPath {
		t.Errorf("Default LogPath = %s, want %s", c.LogPath, DefaultLogPath)
	}
	if c.BanThreshold != DefaultThreshold {
		t.Errorf("Default BanThreshold = %f, want %f", c.BanThreshold, DefaultThreshold)
	}
	if c.Window != DefaultWindow {
		t.Errorf("Default Window = %v, want %v", c.Window, DefaultWindow)
	}
}

func TestLoad(t *testing.T) {
	// Set some envs
	t.Setenv("LOG_PATH", "/custom/log")
	t.Setenv("BAN_THRESHOLD", "5.5")
	t.Setenv("BAN_WINDOW", "30m")
	t.Setenv("PREVIEW_MODE", "true")
	t.Setenv("CACHE_CAPACITY", "5000")

	c := Load()

	if c.LogPath != "/custom/log" {
		t.Errorf("Load LogPath = %s, want /custom/log", c.LogPath)
	}
	if c.BanThreshold != 5.5 {
		t.Errorf("Load BanThreshold = %f, want 5.5", c.BanThreshold)
	}
	if c.Window != 30*time.Minute {
		t.Errorf("Load Window = %v, want 30m", c.Window)
	}
	if !c.PreviewMode {
		t.Error("Load PreviewMode should be true")
	}
}

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envVal   string
		fallback string
		want     string
	}{
		{"no env", "NO_SUCH", "", "def", "def"},
		{"with value", "HAS_VAL", "foo", "def", "foo"},
		{"strips double quotes", "QUOTED", `"bar"`, "def", "bar"},
		{"strips single quotes", "SQUOTED", `'baz'`, "def", "baz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				t.Setenv(tt.key, tt.envVal)
			}
			got := GetEnv(tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("GetEnv(%s) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	t.Setenv("INT_OK", "42")
	if got := GetEnvInt("INT_OK", 0); got != 42 {
		t.Errorf("got %d", got)
	}
	if got := GetEnvInt("INT_BAD", 99); got != 99 {
		t.Errorf("fallback failed: %d", got)
	}
}

func TestGetEnvDuration(t *testing.T) {
	t.Setenv("DUR_OK", "2h30m")
	if got := GetEnvDuration("DUR_OK", time.Minute); got != 2*time.Hour+30*time.Minute {
		t.Errorf("got %v", got)
	}
}

func TestGetEnvBool(t *testing.T) {
	cases := map[string]bool{
		"true":  true,
		"1":     true,
		"yes":   true,
		"false": false,
		"0":     false,
		"no":    false,
	}
	for val, want := range cases {
		t.Setenv("BOOL_TEST", val)
		if got := GetEnvBool("BOOL_TEST", !want); got != want {
			t.Errorf("GetEnvBool(%s) = %v", val, got)
		}
	}
}

func TestGetEnvFloat(t *testing.T) {
	t.Setenv("FLOAT_OK", "3.1415")
	if got := GetEnvFloat("FLOAT_OK", 0); got != 3.1415 {
		t.Errorf("got %f", got)
	}
}
