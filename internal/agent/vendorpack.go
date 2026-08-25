package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Vendor packs: authority for code that publishes no checksums.
//
// Provenance verifies WordPress core and anything on wordpress.org, which on a
// real site is most files but not the interesting remainder. Divi, Gravity
// Forms, ACF Pro, wp-smush-pro and a host's own mu-plugin publish no manifest,
// so they cannot be exonerated — and being unexonerated, they are precisely
// where the pattern engines keep firing on legitimate code. In one field run,
// after every other fix, EVERY surviving finding was premium or bespoke code.
//
// A managed estate already contains the missing authority. If a hundred and
// thirty sites run Divi and all carry byte-identical copies, the fleet is the
// reference: no attacker puts the same bytes at the same path on a hundred and
// thirty independent installations. internal/store/consensus.go computes that
// agreement; a vendor pack is how the answer travels.
//
// WHY A FILE RATHER THAN A QUERY
//
// The agent must run standalone. Most engagements start with one binary scp'd
// to one box, with no console, no enrollment and often no outbound access beyond
// wordpress.org. A pack is a single file that can be copied alongside the
// binary, so the estate's knowledge reaches hosts the console has never met.
//
// HONESTY
//
// A pack is WEAKER evidence than a publisher's checksum and is reported as
// such: separately counted, separately described, never merged into the
// "verified" total. A checksum says the publisher shipped these bytes. A pack
// says a number of machines agree, which is a statement about a fleet — and a
// fleet can be wrong together. The report always names which authority spoke.

// VendorEntry is one attested artefact.
type VendorEntry struct {
	SHA256 string `json:"sha256"`
	// Path is the webroot-relative location the digest was attested AT. A
	// digest is only honoured at its own path: vendor code does not move, and
	// binding the two means a pack cannot be used to bless a file that has been
	// relocated somewhere it has no business being.
	Path string `json:"path"`
	// Tree is the plugin/theme directory the entry belongs to.
	Tree string `json:"tree,omitempty"`
	// Sites is how many independent installations agreed.
	Sites int `json:"sites,omitempty"`
}

// VendorPack is a set of attestations plus provenance about the pack itself.
type VendorPack struct {
	Name        string        `json:"name"`
	GeneratedAt string        `json:"generated_at,omitempty"`
	Source      string        `json:"source,omitempty"`
	MinSites    int           `json:"min_sites,omitempty"`
	Entries     []VendorEntry `json:"entries"`

	// byKey indexes path+digest for lookup.
	byKey map[string]VendorEntry
	// sha is the digest of the pack file, recorded in the report so a finding
	// can always be traced to the exact attestation set that shaped it.
	sha string
}

// vendorMinSites is the floor a pack entry must have met. An entry claiming
// fewer independent sites than this is ignored even if present in the file,
// so a hand-edited pack cannot quietly lower the bar.
const vendorMinSites = 3

func vendorKey(path, sha string) string {
	return strings.ToLower(sha) + "\x00" + strings.TrimPrefix(path, "./")
}

// LoadVendorPacks reads and merges packs from disk. A malformed pack is an
// error rather than a warning: silently running with less authority than the
// operator believes they have is the failure mode this whole subsystem exists
// to avoid.
func LoadVendorPacks(paths []string) (*VendorPack, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	merged := &VendorPack{Name: "vendor", byKey: map[string]VendorEntry{}}
	var names []string
	h := sha256.New()

	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("vendor pack %s: %w", p, err)
		}
		h.Write(b)
		var vp VendorPack
		if err := json.Unmarshal(b, &vp); err != nil {
			return nil, fmt.Errorf("vendor pack %s: %w", p, err)
		}
		kept := 0
		for _, e := range vp.Entries {
			if e.SHA256 == "" || e.Path == "" {
				continue
			}
			// An entry that did not clear the agreement floor is not authority.
			if e.Sites != 0 && e.Sites < vendorMinSites {
				continue
			}
			merged.byKey[vendorKey(e.Path, e.SHA256)] = e
			kept++
		}
		if vp.Name != "" {
			names = append(names, fmt.Sprintf("%s (%d entries)", vp.Name, kept))
		} else {
			names = append(names, fmt.Sprintf("%s (%d entries)", p, kept))
		}
	}
	merged.Source = strings.Join(names, ", ")
	merged.sha = hex.EncodeToString(h.Sum(nil))
	return merged, nil
}

// Attests reports whether the pack vouches for this exact file at this exact
// path.
func (v *VendorPack) Attests(rel, sha string) (VendorEntry, bool) {
	if v == nil || len(v.byKey) == 0 || sha == "" {
		return VendorEntry{}, false
	}
	e, ok := v.byKey[vendorKey(rel, sha)]
	return e, ok
}

func (v *VendorPack) Len() int {
	if v == nil {
		return 0
	}
	return len(v.byKey)
}

func (v *VendorPack) SHA() string {
	if v == nil {
		return ""
	}
	return v.sha
}

// ---------------------------------------------------------------------------
// generating a pack
// ---------------------------------------------------------------------------

// VendorPackFrom builds a pack from attestations that have already been judged
// to represent vendor code. The caller supplies only entries whose verdict was
// "vendor"; this function does not decide, it serialises.
func VendorPackFrom(name, source string, at time.Time, entries []VendorEntry) *VendorPack {
	kept := make([]VendorEntry, 0, len(entries))
	for _, e := range entries {
		if e.SHA256 == "" || e.Path == "" || (e.Sites != 0 && e.Sites < vendorMinSites) {
			continue
		}
		kept = append(kept, e)
	}
	return &VendorPack{
		Name:        name,
		GeneratedAt: at.UTC().Format(time.RFC3339),
		Source:      source,
		MinSites:    vendorMinSites,
		Entries:     kept,
	}
}

// WriteTo serialises the pack as indented JSON.
func (v *VendorPack) WriteTo(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// agent-side accounting
// ---------------------------------------------------------------------------

// vendorAttested records paths a pack vouched for, so post-sweep passes can
// exonerate them exactly as they do manifest-verified files.
type vendorAttestations struct {
	sync.Map
}

func (v *vendorAttestations) note(rel string) { v.Store(rel, struct{}{}) }

func (v *vendorAttestations) has(rel string) bool {
	_, ok := v.Load(rel)
	return ok
}

// MergeVendorPack folds additional attestations into the agent's set.
//
// Locally configured packs take precedence. An operator who placed a pack on a
// host meant it, and the estate's opinion — which is corroboration, not a
// publisher's word — must not silently displace a deliberate local decision.
func (a *Agent) MergeVendorPack(extra *VendorPack) {
	if extra == nil || extra.Len() == 0 {
		return
	}
	if a.vendor == nil || a.vendor.Len() == 0 {
		a.vendor = extra
		return
	}
	for _, e := range extra.Entries {
		k := vendorKey(e.Path, e.SHA256)
		if _, exists := a.vendor.byKey[k]; exists {
			continue
		}
		a.vendor.byKey[k] = e
		a.vendor.Entries = append(a.vendor.Entries, e)
	}
}
