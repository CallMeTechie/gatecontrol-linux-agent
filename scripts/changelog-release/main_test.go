package main

import (
	"strings"
	"testing"
)

func TestPreparePromotesUnreleased(t *testing.T) {
	in := "# Changelog\n\n## [Unreleased]\n\n* first state\n\n## [0.9.0] — 2026-01-01\n\n* old\n"
	got, promoted := prepare(in, "1.0.0", "2026-11-16", "feat: automatic releases")
	if !promoted {
		t.Fatal("hand-written block not promoted")
	}
	want := "# Changelog\n\n## [1.0.0] — 2026-11-16\n\n* first state\n\n## [0.9.0] — 2026-01-01\n\n* old\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestPrepareReplacesWholeUnreleasedHeading(t *testing.T) {
	in := "# Changelog\n\n## [Unreleased] · Unveröffentlicht\n\n* x\n"
	got, promoted := prepare(in, "1.0.0", "2026-11-16", "feat: y")
	if !promoted || !strings.Contains(got, "## [1.0.0] — 2026-11-16\n\n* x") || strings.Contains(got, "Unreleased") {
		t.Fatalf("got %q", got)
	}
}

func TestPrepareGeneratesBlock(t *testing.T) {
	for _, in := range []string{
		"# Changelog\n\n## [1.0.0] — 2026-11-16\n\n* x\n",
		"# Changelog\n\n## [Unreleased]\n\n---\n\n## [1.0.0] — 2026-11-16\n\n* x\n", // empty Unreleased block
	} {
		got, promoted := prepare(in, "1.0.1", "2026-11-17", "fix(enroll): clearer error (#3)")
		if promoted {
			t.Fatal("promoted an empty or missing Unreleased block")
		}
		block := "## [1.0.1] — 2026-11-17\n\n### Fixes\n- clearer error (#3)\n\n---\n\n## ["
		if !strings.HasPrefix(got, "# Changelog\n\n"+block) {
			t.Fatalf("got\n%s", got)
		}
	}
}

func TestSectionAndEntry(t *testing.T) {
	cases := []struct{ subject, section, entry string }{
		{"feat: a", "Features", "a"},
		{"fix(x)!: b", "Fixes", "b"},
		{"docs: c", "Dokumentation", "c"},
		{"chore(deps): bump d", "Änderungen", "bump d"},
		{"Merge something", "Änderungen", "Merge something"},
	}
	for _, c := range cases {
		if s := sectionFor(c.subject); s != c.section {
			t.Errorf("sectionFor(%q) = %q", c.subject, s)
		}
		if e := entryFor(c.subject); e != c.entry {
			t.Errorf("entryFor(%q) = %q", c.subject, e)
		}
	}
}
