// Command changelog-release prepares CHANGELOG.md for a release (called by the release workflow).
//
//	go run ./scripts/changelog-release <version> <date> <commit-subject> [file]
//
// Is there a hand-written "## [Unreleased]" block with content right below the header, its heading
// becomes the version ("## [1.0.0] — 2026-11-16"): whoever described the change wrote the better
// summary. Otherwise a block is generated from the first line of the merge commit (the PR title).
// Same rules as scripts/changelog-release.js in the gatecontrol repository.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

var (
	versionHeading    = regexp.MustCompile(`^## \[`)
	unreleasedHeading = regexp.MustCompile(`(?i)^## \[Unreleased\]`)
	conventional      = regexp.MustCompile(`^[a-z]+(\([^)]*\))?!?:\s*(.*)$`)
)

// sectionFor names the section of a generated block after the commit type.
func sectionFor(subject string) string {
	switch {
	case strings.HasPrefix(subject, "feat"):
		return "Features"
	case strings.HasPrefix(subject, "fix"):
		return "Fixes"
	case strings.HasPrefix(subject, "docs"):
		return "Dokumentation"
	}
	return "Änderungen"
}

// entryFor drops the conventional-commit prefix: "feat(x): text" → "text".
func entryFor(subject string) string {
	if m := conventional.FindStringSubmatch(subject); m != nil {
		return m[2]
	}
	return subject
}

// prepare returns the new changelog and whether a hand-written Unreleased block was promoted.
func prepare(content, version, date, subject string) (string, bool) {
	lines := strings.Split(content, "\n")
	at := -1
	for i, l := range lines {
		if versionHeading.MatchString(l) {
			at = i
			break
		}
	}
	heading := fmt.Sprintf("## [%s] — %s", version, date)
	if at != -1 && unreleasedHeading.MatchString(lines[at]) {
		end := len(lines)
		for i := at + 1; i < len(lines); i++ {
			if versionHeading.MatchString(lines[i]) {
				end = i
				break
			}
		}
		for _, l := range lines[at+1 : end] {
			if t := strings.TrimSpace(l); t != "" && t != "---" {
				out := append([]string(nil), lines...)
				out[at] = heading
				return strings.Join(out, "\n"), true
			}
		}
	}
	headerEnd := at
	if headerEnd == -1 {
		headerEnd = len(lines)
	}
	block := []string{heading, "", "### " + sectionFor(subject), "- " + entryFor(subject), "", "---", ""}
	out := append(append(append([]string(nil), lines[:headerEnd]...), block...), lines[headerEnd:]...)
	return strings.Join(out, "\n"), false
}

func main() {
	args := os.Args[1:]
	if len(args) < 3 || args[0] == "" || args[1] == "" {
		fmt.Fprintln(os.Stderr, "usage: changelog-release <version> <date> <commit-subject> [file]")
		os.Exit(2)
	}
	file := "CHANGELOG.md"
	if len(args) > 3 {
		file = args[3]
	}
	current, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "%s not found — nothing to do\n", file)
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	subject, _, _ := strings.Cut(args[2], "\n")
	text, promoted := prepare(string(current), args[0], args[1], subject)
	if err := os.WriteFile(file, []byte(text), 0o644); err != nil { //nolint:gosec // CHANGELOG.md is a public file
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if promoted {
		fmt.Printf("promoted the hand-written [Unreleased] block to [%s]\n", args[0])
	} else {
		fmt.Printf("inserted a generated block for [%s]\n", args[0])
	}
}
