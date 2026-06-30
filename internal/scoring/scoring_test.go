package scoring

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndCalculate(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "rules.conf")
	os.WriteFile(f, []byte("5.0 /admin\n10.0 /\\.env\n"), 0644)

	Load(f)

	if got := Calculate("/admin"); got != 5.0 {
		t.Errorf("got %f", got)
	}
	if got := Calculate("/.env"); got != 10.0 {
		t.Errorf("got %f", got)
	}
	if got := Calculate("/foo"); got != 1.0 {
		t.Errorf("default got %f", got)
	}
}

func TestBinaryProbe(t *testing.T) {
	// even without rules loaded
	if got := Calculate(""); got != 12.666 {
		t.Errorf("empty path got %f", got)
	}
}
