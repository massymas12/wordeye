package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A genuine GIF whose LZW pixel data happens to contain the byte sequence
// 0x3C 0x3F 0x3D. On one field host this occurred in 102 of 15,274 real images
// — about 0.7%, exactly what a random three-byte sequence predicts — and every
// one was reported as a CONFIRMED CRITICAL polyglot web shell.
//
// The bytes after the tag were compressed pixel data: no statements, no calls,
// no closing tag. Three bytes of coincidence is not evidence, and a rule that
// says otherwise at top confidence teaches an analyst to ignore it.
func TestFieldFP_GifWithCoincidentalShortTag(t *testing.T) {
	gif := []byte("GIF89a")
	gif = append(gif, 0xD7, 0x00, 0x9E, 0x00, 0xF7, 0x00, 0x00)
	// LZW-ish noise containing the three-byte sequence, as observed.
	gif = append(gif, []byte("<?=")...)
	gif = append(gif, []byte("4EGeno")...)
	gif = append(gif, 0xF3, 0xF7, 0xF8, 0x01, 0x9C, 0xE2, 0x00, 0xB4, 0xFE, 0x8A)
	gif = append(gif, 0xC1, 0x33, 0x00, 0x2C, 0xFF, 0x11, 0x9A, 0x7D, 0x40, 0x0E)

	root := t.TempDir()
	scaffold(t, root)
	dir := filepath.Join(root, "wp-content", "uploads", "static_files")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "masthead.gif"), gif, 0o644); err != nil {
		t.Fatal(err)
	}

	a := fpAgent(t, root)
	a.scanFilesystem(context.Background())
	for _, f := range a.Report().Findings {
		if strings.HasPrefix(f.RuleID, "fs.polyglot") || strings.HasPrefix(f.RuleID, "fs.asset_contains") {
			t.Errorf("a genuine GIF was reported as %s (%s/%s)", f.RuleID, f.Severity, f.Confidence)
		}
	}
}

// The case the rule exists for: a real image with a real shell appended. This
// must still be caught, and caught hard.
func TestFieldTP_GifWithAppendedShell(t *testing.T) {
	gif := []byte("GIF89a")
	gif = append(gif, 0xD7, 0x00, 0x9E, 0x00, 0xF7, 0x00, 0x00, 0x2C, 0x00, 0x00)
	gif = append(gif, []byte("<?php "+"ev"+"al(base64_decode($_POST['x'])); ?>")...)

	root := t.TempDir()
	scaffold(t, root)
	dir := filepath.Join(root, "wp-content", "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "avatar.gif"), gif, 0o644); err != nil {
		t.Fatal(err)
	}

	a := fpAgent(t, root)
	a.scanFilesystem(context.Background())
	var hit bool
	for _, f := range a.Report().Findings {
		if f.RuleID == "fs.polyglot_file" {
			hit = true
			if f.Severity != "critical" {
				t.Errorf("an image with an appended eval shell is %s, want critical", f.Severity)
			}
		}
	}
	if !hit {
		t.Error("a real polyglot shell was not reported")
	}
}

// A short tag with genuine PHP behind it is still worth reporting — the fix is
// about requiring evidence, not about trusting the extension.
func TestFieldTP_ShortTagWithRealPayloadIsReported(t *testing.T) {
	gif := []byte("GIF89a")
	gif = append(gif, 0xD7, 0x00, 0x9E, 0x00, 0xF7, 0x00, 0x00, 0x2C, 0x00, 0x00)
	gif = append(gif, []byte("<?= $_GET['c'] ?>")...)

	root := t.TempDir()
	scaffold(t, root)
	dir := filepath.Join(root, "wp-content", "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spacer.gif"), gif, 0o644); err != nil {
		t.Fatal(err)
	}

	a := fpAgent(t, root)
	a.scanFilesystem(context.Background())
	var hit bool
	for _, f := range a.Report().Findings {
		if f.RuleID == "fs.polyglot_file" {
			hit = true
			if f.Confidence == "confirmed" {
				t.Error("a short-echo tag was reported at top confidence")
			}
		}
	}
	if !hit {
		t.Error("a short tag with a real payload was not reported at all")
	}
}

func TestPHPPayloadIsReal(t *testing.T) {
	// Binary noise: printable letters followed by high bytes, as LZW output is.
	noise := append([]byte("4EGeno"), 0xF3, 0xF7, 0xF8, 0x01, 0x9C, 0xE2, 0x00, 0xB4, 0xFE, 0x8A)

	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"binary noise", noise, false},
		{"real short echo", []byte(" $user->name ?>"), true},
		{"real statement", []byte(" system($_GET['c']); "), true},
		{"printable but not code", []byte(" the quick brown fox jumped over a log "), false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		if got := phpPayloadIsReal(c.in, 0); got != c.want {
			t.Errorf("%s: phpPayloadIsReal(%q) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

func TestFindPHPTagPrefersTheStrongerTag(t *testing.T) {
	if k, _ := findPHPTag([]byte("GIF89a<?= noise")); k != phpTagShort {
		t.Errorf("short tag not classified as short: %v", k)
	}
	if k, _ := findPHPTag([]byte("GIF89a<?php echo 1;")); k != phpTagFull {
		t.Errorf("full tag not classified as full: %v", k)
	}
	if k, _ := findPHPTag([]byte("GIF89a plain pixels")); k != phpTagNone {
		t.Errorf("no tag was classified as %v", k)
	}
}

// The polyglot path was unreachable on any real image.
//
// Binary-extension files were probed for only their first kilobyte, and a
// polyglot by construction keeps a valid media header and appends the shell
// after the pixel data. The rule could therefore never fire on a genuine
// image — and the existing tests passed only because their fixture GIFs were
// about fifty bytes, so the whole file fitted inside the probe window.
func TestPolyglotFoundInARealisticallySizedImage(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	dir := filepath.Join(root, "wp-content", "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// A 40KB GIF: header, then pixel data far larger than any head probe,
	// then the shell appended at the very end.
	gif := []byte("GIF89a")
	gif = append(gif, 0xD7, 0x00, 0x9E, 0x00, 0xF7, 0x00, 0x00, 0x2C, 0x00, 0x00)
	pixels := make([]byte, 40<<10)
	for i := range pixels {
		pixels[i] = byte(i % 251)
	}
	gif = append(gif, pixels...)
	gif = append(gif, []byte("<?php "+"ev"+"al(base64_decode($_POST['x'])); ?>")...)

	if err := os.WriteFile(filepath.Join(dir, "banner.gif"), gif, 0o644); err != nil {
		t.Fatal(err)
	}

	a := fpAgent(t, root)
	a.scanFilesystem(context.Background())

	var hit bool
	for _, f := range a.Report().Findings {
		if f.RuleID == "fs.polyglot_file" {
			hit = true
		}
	}
	if !hit {
		t.Error("a 40KB image with an appended shell was not detected; the polyglot path is unreachable")
	}
}

// An ordinary large image must still cost only the probe, not a full read.
func TestLargeCleanImageIsNotReported(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	dir := filepath.Join(root, "wp-content", "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gif := append([]byte("GIF89a"), make([]byte, 60<<10)...)
	if err := os.WriteFile(filepath.Join(dir, "clean.gif"), gif, 0o644); err != nil {
		t.Fatal(err)
	}

	a := fpAgent(t, root)
	a.scanFilesystem(context.Background())
	for _, f := range a.Report().Findings {
		if strings.HasPrefix(f.RuleID, "fs.polyglot") || strings.HasPrefix(f.RuleID, "fs.asset_contains") {
			t.Errorf("a clean image was reported as %s", f.RuleID)
		}
	}
}
