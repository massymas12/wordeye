package yara

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed rules/*.yar
var builtinFS embed.FS

// Embedded returns the compiled built-in ruleset.
func Embedded() (*Set, error) {
	var all []*Rule
	err := fs.WalkDir(builtinFS, "rules", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := builtinFS.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		rules, perr := Parse(string(b), filepath.Base(p))
		if perr != nil {
			return perr
		}
		all = append(all, rules...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return Compile(all)
}

// LoadPaths compiles the built-in ruleset together with any external .yar files
// or directories given.
//
// External rulesets are third-party content with their own licence terms; the
// agent loads them but never redistributes them, which is why none is vendored
// into this repository.
func LoadPaths(paths []string, includeBuiltin bool) (*Set, []string, error) {
	var all []*Rule
	var warnings []string

	if includeBuiltin {
		b, err := Embedded()
		if err != nil {
			return nil, nil, err
		}
		all = append(all, b.Rules...)
	}

	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, warnings, fmt.Errorf("yara: %w", err)
		}
		var files []string
		if fi.IsDir() {
			err = filepath.WalkDir(p, func(q string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if ext := strings.ToLower(filepath.Ext(q)); ext == ".yar" || ext == ".yara" {
					files = append(files, q)
				}
				return nil
			})
			if err != nil {
				return nil, warnings, err
			}
		} else {
			files = []string{p}
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v", f, err))
				continue
			}
			rules, err := Parse(string(b), filepath.Base(f))
			if err != nil {
				// A ruleset that uses unsupported features is reported and
				// skipped, never silently accepted — the operator needs to know
				// which rules are not protecting them.
				warnings = append(warnings, fmt.Sprintf("%s: %v", f, err))
				continue
			}
			all = append(all, rules...)
		}
	}

	set, err := Compile(all)
	if err != nil {
		return nil, warnings, err
	}
	return set, warnings, nil
}
