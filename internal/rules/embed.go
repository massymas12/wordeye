package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

// Packs ship inside the binary so the agent stays a single file to scp. An
// engagement can still override or extend them from disk with --pack.
//
//go:embed packs/*.yaml
var packsFS embed.FS

// Embedded returns a built-in pack by name, e.g. "core". Incident packs are
// supplied at runtime with --pack rather than embedded, so client-specific
// indicators never ship inside the binary.
func Embedded(name string) (*Pack, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".yaml")
	b, err := packsFS.ReadFile("packs/" + name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("no embedded pack %q", name)
	}
	return Parse(b, name)
}

// EmbeddedNames lists the built-in packs, for `--list-packs`.
func EmbeddedNames() []string {
	var out []string
	_ = fs.WalkDir(packsFS, "packs", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(p, "packs/"), ".yaml"))
		return nil
	})
	return out
}

// Load resolves a list of pack references. A reference is either the name of an
// embedded pack or a path to a YAML file on disk. Order matters: later packs
// override earlier rules with the same ID.
//
// extra is passed through to Compile for the heuristic engine's literals.
func Load(refs []string, extra []string) (*Set, error) {
	var packs []*Pack
	for _, ref := range refs {
		var (
			p   *Pack
			err error
		)
		if strings.ContainsAny(ref, "/\\") || strings.HasSuffix(ref, ".yaml") || strings.HasSuffix(ref, ".yml") {
			p, err = LoadFile(ref)
		} else {
			p, err = Embedded(ref)
		}
		if err != nil {
			return nil, err
		}
		packs = append(packs, p)
	}
	return Compile(extra, packs...)
}
