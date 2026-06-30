package parser

import "testing"

func TestIsValidIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"::1", true},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		if got := IsValidIP(tt.ip); got != tt.want {
			t.Errorf("IsValidIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	if got := NormalizeIP("2001:db8:0000:0000:0000:0000:0000:0001"); got != "2001:db8::1" {
		t.Errorf("NormalizeIP IPv6 = %s, want canonical", got)
	}
}
