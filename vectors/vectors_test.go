package vectors

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMiaoVectors(t *testing.T) {
	path := filepath.Join("testdata", "s01-vector-set-v4.md")
	vs, err := LoadVectorSet(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(vs.WITs) != 3 {
		t.Fatalf("WITs: %d", len(vs.WITs))
	}
	if len(vs.Keys) != 5 {
		t.Fatalf("keys: %d", len(vs.Keys))
	}
	kr, err := LoadKeyring(vs)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}

	var failed int
	for i := range vs.Entries {
		e := &vs.Entries[i]
		results := VerifyEntry(vs, kr, e)
		for _, r := range results {
			switch {
			case r.Got == OutcomeSkip:
				t.Logf("SKIP %s — %s", r.ID, r.Detail)
			case r.OK():
				t.Logf("PASS %s (want %s)", r.ID, r.Want)
			default:
				failed++
				t.Errorf("FAIL %s: want %s got %s — %s", r.ID, r.Want, r.Got, r.Detail)
			}
		}
	}
	if failed > 0 {
		t.Fatalf("%d vector evaluation(s) failed", failed)
	}
}

func TestParseSmoke(t *testing.T) {
	vs, err := LoadVectorSet(filepath.Join("testdata", "s01-vector-set-v4.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"P-01", "P-02", "P-03", "P-04", "P-05", "P-06"} {
		e := vs.PositivesByID[id]
		if e == nil {
			t.Fatalf("missing %s", id)
		}
		if e.Message == "" {
			t.Fatalf("%s: empty message", id)
		}
		if strings.Contains(e.Message, "[WIT-") {
			t.Fatalf("%s: WIT placeholder not expanded", id)
		}
	}
	var nMsg, nSkip int
	for _, e := range vs.Entries {
		switch e.Kind {
		case "negative-message":
			nMsg++
		case "negative-behavior", "observation":
			nSkip++
		}
	}
	if nMsg < 15 {
		t.Fatalf("expected >=15 message negatives, got %d", nMsg)
	}
	if nSkip < 9 {
		t.Fatalf("expected >=9 skipped behavior/observation, got %d", nSkip)
	}
}
