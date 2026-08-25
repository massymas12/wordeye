package rules

// Rule packs are DATA, not code. This is what makes WordEye estate-independent:
// the binary ships a generic core pack, and each engagement adds an incident
// pack carrying that campaign's IOCs. Nothing about a specific client, host, or
// incident is compiled into the agent.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule is one detection expressed declaratively.
//
// Evaluation order is deliberately cheapest-first:
//  1. extension / path / size filters (no file content touched)
//  2. Gate literals via the shared Aho-Corasick automaton (one pass, shared
//     across every rule in every pack)
//  3. All / Any regexes (only for rules whose gates all fired)
//  4. Not regexes (veto, e.g. to spare a known-good vendor file)
type Rule struct {
	ID          string `yaml:"id"`
	Class       string `yaml:"class"`
	Severity    string `yaml:"severity"`
	Confidence  string `yaml:"confidence"`
	Title       string `yaml:"title"`
	Detail      string `yaml:"detail"`
	Remediation string `yaml:"remediation"`

	// Actionable permits automated quarantine. Only honoured when Confidence
	// is "confirmed"; the report layer re-checks this invariant.
	Actionable bool `yaml:"actionable"`

	// Gate holds cheap lowercase literals. ALL must be present in the file
	// before any regex runs. A rule with no gates is evaluated on every
	// candidate file, so packs should always supply at least one.
	Gate []string `yaml:"gate"`

	Any []string `yaml:"any"` // at least one must match
	All []string `yaml:"all"` // every one must match
	Not []string `yaml:"not"` // any match vetoes the rule

	// AnyCode/AllCode are matched against the lexed code view even when the
	// rule's Scope is raw. This exists for rules that are genuinely mixed: the
	// canonical case is "php://input reaches an executor", where the path is
	// necessarily a string literal but the executor must be real code.
	AnyCode []string `yaml:"any_code"`
	AllCode []string `yaml:"all_code"`

	// Within bounds how far apart the All/AllCode matches may be, in bytes. A
	// rule that ANDs several patterns across a whole file is nearly worthless
	// on large files: a 500KB plugin contains almost any triple of tokens
	// somewhere. Proximity is what turns co-occurrence into evidence. Zero
	// means unbounded, which should be rare and deliberate.
	Within int `yaml:"within"`

	// Scope selects what the regexes are matched against.
	//
	//	""/"raw"  the file bytes as they are on disk (default)
	//	"code"    a lexed view in which comment bodies and string-literal
	//	          CONTENTS are blanked to spaces
	//
	// Use "code" for any rule that describes what the file DOES. A rule such as
	// "php://input reaches an executor" is a statement about code, and matching
	// it against raw bytes makes it fire on documentation, on translation
	// strings, and on security plugins that merely name the technique. Blanking
	// preserves offsets, so reported lines and evidence remain exact.
	Scope string `yaml:"scope"`

	Ext     []string `yaml:"ext"`      // restrict to these extensions (no dot)
	PathAny []string `yaml:"path_any"` // path must match one of these
	PathNot []string `yaml:"path_not"` // path must match none of these

	MinSize int64 `yaml:"min_size"`
	MaxSize int64 `yaml:"max_size"`

	// compiled forms
	anyRe, allRe, notRe  []*regexp.Regexp
	anyCodeRe, allCodeRe []*regexp.Regexp
	pathAnyRe, pathNotRe []*regexp.Regexp
	gateIDs              []int
	extSet               map[string]bool
	pack                 string
}

// IOCs are the incident-specific indicators. Separating these from Rule keeps
// per-engagement packs tiny and reviewable.
type IOCs struct {
	// Strings are matched against file content and reported as IOC hits.
	Strings []string `yaml:"strings"`
	// Filenames are exact basenames known to be attacker tooling.
	Filenames []string `yaml:"filenames"`
	// PathGlobs are filepath.Match patterns relative to the webroot.
	PathGlobs []string `yaml:"path_globs"`
	// IPs accepts bare addresses or CIDRs; matched against socket peers.
	IPs []string `yaml:"ips"`
	// Domains are matched in content, DB values and redirect targets.
	Domains []string `yaml:"domains"`
	// SpamKeywords drive the behavioural cloak probe and DB content checks.
	SpamKeywords []string `yaml:"spam_keywords"`
	// SuspectEmailDomains flag admin accounts registered on free/throwaway mail.
	SuspectEmailDomains []string `yaml:"suspect_email_domains"`
	// VendorDomains are former-supplier domains whose accounts should no longer
	// hold a role.
	VendorDomains []string `yaml:"vendor_domains"`
	// IncidentStart (YYYY-MM-DD) flags accounts created on or after this date.
	IncidentStart string `yaml:"incident_start"`
	// DBOptionPatterns are LIKE-style fragments searched in wp_options values.
	DBOptionPatterns []string `yaml:"db_option_patterns"`
}

type Meta struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
}

type Pack struct {
	Meta         Meta     `yaml:"meta"`
	ExcludePaths []string `yaml:"exclude_paths"`
	IOCs         IOCs     `yaml:"iocs"`
	Rules        []Rule   `yaml:"rules"`

	sha string
}

// Set is the compiled union of every loaded pack, plus the single automaton
// shared by all of their gate literals.
type Set struct {
	Packs   []Pack
	Rules   []*Rule
	IOCs    IOCs
	Exclude []*regexp.Regexp

	AC       *AC
	iocGate  []int // pattern ids for IOC strings, parallel to IOCs.Strings
	nPattern int
	index    map[string]int
}

// LiteralID resolves a literal registered at compile time to its automaton
// pattern id, or -1. The heuristic engine uses this to piggyback on the same
// single-pass scan the rule gates already pay for, rather than walking every
// file a second time.
func (s *Set) LiteralID(lit string) int {
	if id, ok := s.index[strings.ToLower(lit)]; ok {
		return id
	}
	return -1
}

// Parse reads one pack from YAML bytes.
func Parse(data []byte, origin string) (*Pack, error) {
	var p Pack
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", origin, err)
	}
	sum := sha256.Sum256(data)
	p.sha = hex.EncodeToString(sum[:])
	if p.Meta.Name == "" {
		p.Meta.Name = origin
	}
	for i := range p.Rules {
		p.Rules[i].pack = p.Meta.Name
	}
	return &p, nil
}

// LoadFile reads a pack from disk.
func LoadFile(path string) (*Pack, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, path)
}

// Compile merges packs into an evaluable Set, building the shared automaton.
// Later packs override earlier rules with the same ID, so an incident pack can
// tune or disable a core rule without editing the core.
//
// extra holds literals that are not rule gates but still need prefiltering —
// in practice the heuristic engine's sink and obfuscation vocabulary. Folding
// them into the same automaton keeps the scan to exactly one pass per file.
func Compile(extra []string, packs ...*Pack) (*Set, error) {
	s := &Set{}
	byID := map[string]*Rule{}
	var order []string

	for _, p := range packs {
		if p == nil {
			continue
		}
		s.Packs = append(s.Packs, *p)
		for _, ex := range p.ExcludePaths {
			re, err := regexp.Compile(ex)
			if err != nil {
				return nil, fmt.Errorf("pack %s: exclude_paths %q: %w", p.Meta.Name, ex, err)
			}
			s.Exclude = append(s.Exclude, re)
		}
		s.IOCs.merge(p.IOCs)
		for i := range p.Rules {
			r := p.Rules[i]
			if r.ID == "" {
				return nil, fmt.Errorf("pack %s: rule with empty id", p.Meta.Name)
			}
			if _, seen := byID[r.ID]; !seen {
				order = append(order, r.ID)
			}
			cp := r
			byID[r.ID] = &cp
		}
	}

	// Gather every literal that needs prefiltering: rule gates plus IOC strings.
	var literals []string
	seen := map[string]bool{}
	addLit := func(l string) {
		l = strings.ToLower(l)
		if l == "" || seen[l] {
			return
		}
		seen[l] = true
		literals = append(literals, l)
	}
	for _, id := range order {
		for _, g := range byID[id].Gate {
			addLit(g)
		}
	}
	for _, str := range s.IOCs.Strings {
		addLit(str)
	}
	for _, l := range extra {
		addLit(l)
	}

	ac, index := BuildAC(literals)
	s.AC = ac
	s.nPattern = ac.NumPatterns()
	s.index = index

	for _, id := range order {
		r := byID[id]
		if err := r.compile(index); err != nil {
			return nil, err
		}
		s.Rules = append(s.Rules, r)
	}
	for _, str := range s.IOCs.Strings {
		s.iocGate = append(s.iocGate, index[strings.ToLower(str)])
	}
	return s, nil
}

func (r *Rule) compile(index map[string]int) error {
	cc := func(list []string, what string) ([]*regexp.Regexp, error) {
		out := make([]*regexp.Regexp, 0, len(list))
		for _, p := range list {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %s %q: %w", r.ID, what, p, err)
			}
			out = append(out, re)
		}
		return out, nil
	}
	var err error
	if r.anyRe, err = cc(r.Any, "any"); err != nil {
		return err
	}
	if r.allRe, err = cc(r.All, "all"); err != nil {
		return err
	}
	if r.notRe, err = cc(r.Not, "not"); err != nil {
		return err
	}
	if r.anyCodeRe, err = cc(r.AnyCode, "any_code"); err != nil {
		return err
	}
	if r.allCodeRe, err = cc(r.AllCode, "all_code"); err != nil {
		return err
	}
	if r.pathAnyRe, err = cc(r.PathAny, "path_any"); err != nil {
		return err
	}
	if r.pathNotRe, err = cc(r.PathNot, "path_not"); err != nil {
		return err
	}
	for _, g := range r.Gate {
		if id, ok := index[strings.ToLower(g)]; ok {
			r.gateIDs = append(r.gateIDs, id)
		}
	}
	if len(r.Ext) > 0 {
		r.extSet = make(map[string]bool, len(r.Ext))
		for _, e := range r.Ext {
			r.extSet[strings.ToLower(strings.TrimPrefix(e, "."))] = true
		}
	}
	if r.Severity == "" {
		r.Severity = "medium"
	}
	if r.Confidence == "" {
		r.Confidence = "review"
	}
	if r.Class == "" {
		r.Class = "SHELL"
	}
	switch r.Scope {
	case "", "raw":
		r.Scope = "raw"
	case "code":
	default:
		return fmt.Errorf("rule %s: scope %q is not one of raw, code", r.ID, r.Scope)
	}
	return nil
}

// NeedsCode reports whether evaluating this rule requires the lexed code view.
// Callers use it to keep lexing lazy: most files never need it.
func (r *Rule) NeedsCode() bool {
	return r.Scope == "code" || len(r.allCodeRe) > 0 || len(r.anyCodeRe) > 0
}

// NumPatterns sizes the per-worker hit slice.
func (s *Set) NumPatterns() int { return s.nPattern }

// Excluded reports whether a path is globally excluded by any pack.
func (s *Set) Excluded(path string) bool {
	for _, re := range s.Exclude {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// PathEligible applies the content-free filters. Returning false here means the
// file is never read on this rule's behalf.
func (r *Rule) PathEligible(path, ext string, size int64) bool {
	if r.extSet != nil && !r.extSet[ext] {
		return false
	}
	if r.MinSize > 0 && size < r.MinSize {
		return false
	}
	if r.MaxSize > 0 && size > r.MaxSize {
		return false
	}
	for _, re := range r.pathNotRe {
		if re.MatchString(path) {
			return false
		}
	}
	if len(r.pathAnyRe) > 0 {
		ok := false
		for _, re := range r.pathAnyRe {
			if re.MatchString(path) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// GatesFired reports whether every gate literal for this rule occurs in the file.
func (r *Rule) GatesFired(hit []bool) bool {
	for _, id := range r.gateIDs {
		if id < 0 || id >= len(hit) || !hit[id] {
			return false
		}
	}
	return true
}

// MatchContent runs the regex stage. It returns the matched byte offset so the
// caller can render a line number and an evidence snippet.
// maxProxMatches bounds how many offsets are collected per pattern when a
// proximity window is in play. A pathological file can contain a token tens of
// thousands of times; the window search only needs a bounded sample to find a
// cluster, and the cap keeps this linear.
const maxProxMatches = 512

// MatchContent evaluates the rule.
//
// raw is the file as it is on disk. code is the lexed view with comment bodies
// and string-literal contents blanked to spaces; callers with no lexer (a
// non-PHP file) pass the same slice for both. Blanking preserves offsets, so
// offsets from either subject are directly comparable and index the real file.
//
// The returned offset is the earliest match, used for the evidence snippet.
func (r *Rule) MatchContent(raw, code []byte) (bool, int) {
	if code == nil {
		code = raw
	}
	// Whole-rule code scope: every pattern reads the lexed view.
	allSubj, anySubj, notSubj := raw, raw, raw
	if r.Scope == "code" {
		allSubj, anySubj, notSubj = code, code, code
	}

	for _, re := range r.notRe {
		if re.Match(notSubj) {
			return false, -1
		}
	}

	// Collect the AND-set. Both lists must be satisfied; they differ only in
	// which subject they read.
	nAll := len(r.allRe) + len(r.allCodeRe)
	off := -1
	var groups [][]int
	if r.Within > 0 && nAll > 1 {
		groups = make([][]int, 0, nAll)
	}
	collect := func(res []*regexp.Regexp, subj []byte) bool {
		for _, re := range res {
			if groups == nil {
				loc := re.FindIndex(subj)
				if loc == nil {
					return false
				}
				if off < 0 || loc[0] < off {
					off = loc[0]
				}
				continue
			}
			locs := re.FindAllIndex(subj, maxProxMatches)
			if len(locs) == 0 {
				return false
			}
			starts := make([]int, len(locs))
			for i, l := range locs {
				starts[i] = l[0]
			}
			groups = append(groups, starts)
		}
		return true
	}
	if !collect(r.allRe, allSubj) {
		return false, -1
	}
	if !collect(r.allCodeRe, code) {
		return false, -1
	}
	if groups != nil {
		start, ok := smallestWindow(groups, r.Within)
		if !ok {
			return false, -1
		}
		off = start
	}

	// The OR-set: one match from either list suffices.
	if n := len(r.anyRe) + len(r.anyCodeRe); n > 0 {
		found := false
		scan := func(res []*regexp.Regexp, subj []byte) {
			for _, re := range res {
				if loc := re.FindIndex(subj); loc != nil {
					found = true
					if off < 0 {
						off = loc[0]
					}
					return
				}
			}
		}
		scan(r.anyRe, anySubj)
		if !found {
			scan(r.anyCodeRe, code)
		}
		if !found {
			return false, -1
		}
	}

	// A rule with neither any nor all is purely gate+path driven; that is
	// legitimate (e.g. "any PHP file under uploads/"), so treat it as matched.
	if nAll == 0 && len(r.anyRe) == 0 && len(r.anyCodeRe) == 0 && off < 0 {
		off = 0
	}
	return off >= 0, off
}

// smallestWindow reports whether one offset can be chosen from every group such
// that all of them fall inside a window of `within` bytes, and returns where
// that window starts. Each group is the sorted match offsets of one pattern.
//
// This is the classic "smallest range covering one element from each list"
// sweep: advance the pointer of whichever group currently holds the minimum,
// tracking the best span seen.
func smallestWindow(groups [][]int, within int) (int, bool) {
	idx := make([]int, len(groups))
	bestLo, bestSpan := 0, -1
	for {
		lo, hi, loGroup := 1<<62, -1, -1
		for g, starts := range groups {
			if idx[g] >= len(starts) {
				// One list is exhausted, so no further window can cover it.
				return bestLo, bestSpan >= 0 && bestSpan <= within
			}
			v := starts[idx[g]]
			if v < lo {
				lo, loGroup = v, g
			}
			if v > hi {
				hi = v
			}
		}
		if span := hi - lo; bestSpan < 0 || span < bestSpan {
			bestLo, bestSpan = lo, span
			if span <= within {
				// Already inside the window; no need to keep searching.
				return bestLo, true
			}
		}
		idx[loGroup]++
	}
}

func (r *Rule) Pack() string { return r.pack }

// IOCHits returns the IOC strings present in a scanned file.
func (s *Set) IOCHits(hit []bool) []string {
	var out []string
	for i, id := range s.iocGate {
		if id >= 0 && id < len(hit) && hit[id] {
			out = append(out, s.IOCs.Strings[i])
		}
	}
	return out
}

func (i *IOCs) merge(o IOCs) {
	i.Strings = appendUnique(i.Strings, o.Strings)
	i.Filenames = appendUnique(i.Filenames, o.Filenames)
	i.PathGlobs = appendUnique(i.PathGlobs, o.PathGlobs)
	i.IPs = appendUnique(i.IPs, o.IPs)
	i.Domains = appendUnique(i.Domains, o.Domains)
	i.SpamKeywords = appendUnique(i.SpamKeywords, o.SpamKeywords)
	i.SuspectEmailDomains = appendUnique(i.SuspectEmailDomains, o.SuspectEmailDomains)
	i.VendorDomains = appendUnique(i.VendorDomains, o.VendorDomains)
	i.DBOptionPatterns = appendUnique(i.DBOptionPatterns, o.DBOptionPatterns)
	if o.IncidentStart != "" {
		i.IncidentStart = o.IncidentStart
	}
}

func appendUnique(dst, src []string) []string {
	seen := make(map[string]bool, len(dst))
	for _, d := range dst {
		seen[d] = true
	}
	for _, s := range src {
		if !seen[s] {
			seen[s] = true
			dst = append(dst, s)
		}
	}
	return dst
}

// Info summarises loaded packs for the report header, so every finding is
// traceable to the pack and version that produced it.
func (s *Set) Info() []PackInfo {
	out := make([]PackInfo, 0, len(s.Packs))
	for _, p := range s.Packs {
		n := 0
		for _, r := range s.Rules {
			if r.pack == p.Meta.Name {
				n++
			}
		}
		out = append(out, PackInfo{Name: p.Meta.Name, Version: p.Meta.Version, SHA256: p.sha, Rules: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type PackInfo struct {
	Name    string
	Version string
	SHA256  string
	Rules   int
}
