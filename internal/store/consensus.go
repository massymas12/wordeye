package store

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Cross-estate consensus: deciding whether an unverifiable file is vendor code.
//
// Provenance answers "is this file what its publisher shipped?" by comparing
// against wordpress.org manifests. Premium and bespoke code — Divi, ACF Pro,
// Gravity Forms, a host's own mu-plugin — publishes no manifest, so provenance
// has no authority to appeal to and every one of those files stays unverified.
// That is the last large source of unexplained findings.
//
// A managed estate supplies the missing authority. If twenty-three sites all
// run Divi and all carry a byte-identical Portability.php, that file is what
// Elegant Themes ships. No attacker gets the same bytes onto twenty-three
// independent sites at the same path by accident.
//
// THE DANGEROUS INVERSION
//
// The identical query answers the opposite question. A digest on many sites is
// ALSO the signature of a campaign — which is what DB.Correlate reports it as.
// Treating "seen widely" as "safe" would mean that an operator who compromised
// enough of the estate could exonerate their own shell, and the more successful
// they were, the more thoroughly it would be cleared. That failure mode is
// unacceptable, so consensus is deliberately narrow:
//
//   - LOCATION. Vendor code lives at a stable path inside the plugin or theme
//     that ships it. A digest appearing at differing paths, or anywhere outside
//     a vendor tree (uploads/, the webroot, wp-includes/), is never vendor code
//     however many sites carry it.
//   - AGREEMENT. Every sighting must be at the SAME relative path. Vendor files
//     do not move between installations; dropped files land wherever the
//     vulnerability allowed.
//   - TIME. Vendor code is installed once and sits there. A digest whose
//     sightings all appear inside a few days is a deployment event — which for
//     unexpected code is exactly what an intrusion looks like.
//
// And consensus NEVER dismisses. It annotates a finding with what the estate
// knows, and a human decides. Nothing here writes to a finding's state.
//
// The most useful verdict is the one that raises an alarm rather than lowering
// it: a file inside a premium plugin present on exactly ONE site of twenty-four
// running that plugin is far more interesting than one present on all of them.

// Consensus verdicts.
const (
	// ConsensusVendor: the same bytes at the same vendor path across enough
	// independent sites to be the publisher's own code.
	ConsensusVendor = "vendor"
	// ConsensusSingleton: a vendor tree carries a file no other site has. The
	// strongest signal this analysis produces.
	ConsensusSingleton = "singleton"
	// ConsensusCampaign: widespread, but not vendor-shaped — differing paths,
	// a non-vendor location, or a burst arrival.
	ConsensusCampaign = "campaign"
	// ConsensusInconclusive: not enough of the estate has reported.
	ConsensusInconclusive = "inconclusive"
)

const (
	// consensusMinSites is how many INDEPENDENT sites must agree before a
	// digest is called vendor code. Two sites can share an operator, a backup,
	// or a compromise; three is the smallest number that starts to mean
	// something. It is a floor, never a substitute for judgement.
	consensusMinSites = 3
	// consensusBurstWindow: sightings clustered more tightly than this look
	// like a deployment rather than an installed base.
	consensusBurstWindow = 7 * 24 * time.Hour
)

// Consensus is what the estate collectively knows about one digest.
type Consensus struct {
	SHA256 string `json:"sha256"`
	// Sites is the number of DISTINCT agents reporting this digest.
	Sites int `json:"sites"`
	// Paths are the distinct relative paths it was seen at. More than one means
	// the file moves, which vendor code does not do.
	Paths []string `json:"paths"`
	// VendorTree is the plugin/theme directory shared by every sighting, empty
	// if the sightings do not agree on one.
	VendorTree string    `json:"vendor_tree"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	// SitesRunningTree is how many agents have ANY finding inside the same
	// vendor tree. It is the denominator that makes a singleton meaningful:
	// 1-of-1 says nothing, 1-of-24 says a great deal.
	SitesRunningTree int    `json:"sites_running_tree"`
	Verdict          string `json:"verdict"`
	Rationale        string `json:"rationale"`
}

// Corroborates reports whether this consensus supports treating the file as
// benign. Callers must still refuse to act on it for confirmed or actionable
// findings — hard evidence outranks a popularity count.
func (c Consensus) Corroborates() bool { return c.Verdict == ConsensusVendor }

// vendorTreeOf returns the plugin or theme directory that owns a path, or "" if
// the path is not inside one. Only these trees can host vendor code; a digest
// found anywhere else is outside the scope of this analysis by construction.
func vendorTreeOf(rel string) string {
	rel = strings.TrimPrefix(strings.ReplaceAll(rel, "\\", "/"), "./")
	parts := strings.Split(rel, "/")
	// wp-content/{plugins,themes,mu-plugins}/<name>/...
	if len(parts) >= 4 && parts[0] == "wp-content" {
		switch parts[1] {
		case "plugins", "themes", "mu-plugins":
			return strings.Join(parts[:3], "/")
		}
	}
	return ""
}

// ConsensusFor computes consensus for a set of digests in one pass. Empty and
// duplicate digests are ignored.
//
// estateID scopes the evidence to one customer. This is not cosmetic: a quorum
// assembled from unrelated customers' machines is both weaker evidence (their
// software has no reason to agree) and a leak, since the verdict discloses how
// many OTHER clients run a given file. Pass 0 on a single-tenant console, or
// where no estates have been created, to consider every agent.
func (db *DB) ConsensusFor(estateID int64, shas []string) (map[string]Consensus, error) {
	uniq := make([]string, 0, len(shas))
	seen := map[string]bool{}
	for _, s := range shas {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		uniq = append(uniq, s)
	}
	if len(uniq) == 0 {
		return map[string]Consensus{}, nil
	}

	ph := strings.TrimSuffix(strings.Repeat("?,", len(uniq)), ",")
	args := make([]any, 0, len(uniq)+1)
	for _, s := range uniq {
		args = append(args, s)
	}
	estateFilter := ""
	if estateID != 0 {
		// The join already brings in agents, so filter on it directly.
		estateFilter = ` AND a.estate_id = ?`
		args = append(args, estateID)
	}

	// One row per (digest, path, HOST): the raw sightings.
	//
	// The unit of agreement is a HOST, not an agent row. Re-running an
	// installer enrolls a second agent for the same machine, and counting those
	// separately would let one box claim to be two independent witnesses. That
	// is not a cosmetic miscount: consensus EXONERATES, so an attacker with a
	// foothold could enroll repeatedly and manufacture the "many sites ship this
	// file, therefore it is vendor code" verdict for their own implant.
	//
	// hostname+webroot identifies a site installation. Where a host reported no
	// hostname we fall back to the agent id, which cannot over-count.
	//
	// Retired agents do not vote. A decommissioned host is not evidence about
	// what the estate currently runs, and leaving it in means stale enrollments
	// silently inflate every denominator.
	rows, err := db.sql.Query(`
		SELECT f.sha256, f.path,
		       COALESCE(NULLIF(a.hostname,'') || '|' || a.webroot, f.agent_id) AS host,
		       MIN(f.first_seen), MAX(f.last_seen)
		  FROM findings f
		  JOIN agents a ON a.id = f.agent_id AND a.retired = 0
		 WHERE f.sha256 IN (`+ph+`) AND f.state != 'dismissed'`+estateFilter+`
		 GROUP BY f.sha256, f.path, host`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type acc struct {
		agents map[string]bool
		paths  map[string]bool
		first  int64
		last   int64
	}
	byDigest := map[string]*acc{}
	for rows.Next() {
		var sha, p, agent string
		var first, last sql.NullInt64
		if err := rows.Scan(&sha, &p, &agent, &first, &last); err != nil {
			return nil, err
		}
		a := byDigest[sha]
		if a == nil {
			a = &acc{agents: map[string]bool{}, paths: map[string]bool{}}
			byDigest[sha] = a
		}
		a.agents[agent] = true // keyed by host identity, not agent id
		a.paths[p] = true
		if first.Valid && (a.first == 0 || first.Int64 < a.first) {
			a.first = first.Int64
		}
		if last.Valid && last.Int64 > a.last {
			a.last = last.Int64
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make(map[string]Consensus, len(byDigest))
	for sha, a := range byDigest {
		c := Consensus{
			SHA256:    sha,
			Sites:     len(a.agents),
			FirstSeen: unixOrZero(a.first),
			LastSeen:  unixOrZero(a.last),
		}
		for p := range a.paths {
			c.Paths = append(c.Paths, p)
		}
		sort.Strings(c.Paths)

		// The vendor tree is only meaningful if every sighting agrees on it.
		tree := ""
		agreed := true
		for _, p := range c.Paths {
			t := vendorTreeOf(p)
			if t == "" {
				agreed = false
				break
			}
			if tree == "" {
				tree = t
			} else if tree != t {
				agreed = false
				break
			}
		}
		if agreed {
			c.VendorTree = tree
		}
		if c.VendorTree != "" {
			n, err := db.sitesRunningTree(c.VendorTree, estateID)
			if err != nil {
				return nil, err
			}
			c.SitesRunningTree = n
		}
		c.Verdict, c.Rationale = classifyConsensus(c)
		out[sha] = c
	}

	// Digests nobody else has reported still deserve an answer.
	for _, s := range uniq {
		if _, ok := out[s]; !ok {
			out[s] = Consensus{SHA256: s, Verdict: ConsensusInconclusive,
				Rationale: "no sightings recorded for this digest"}
		}
	}
	return out, nil
}

// sitesRunningTree counts distinct agents with any finding inside a tree. It is
// the denominator for a singleton verdict.
//
// The tree is derived from a file path reported by an agent, so it is
// attacker-influenced. Parameter binding stops it being SQL, but LIKE has its
// own metacharacters: a plugin directory literally named "%" would otherwise
// match every path in the table and inflate the denominator, manufacturing a
// "1 of N sites" verdict. ESCAPE makes the pattern mean what it says.
func (db *DB) sitesRunningTree(tree string, estateID int64) (int, error) {
	// Distinct HOSTS, for the reason given on the sightings query above: this
	// is the denominator of a trust decision, and duplicate enrollments would
	// otherwise let a single machine vote more than once.
	q := `SELECT COUNT(DISTINCT COALESCE(NULLIF(a.hostname,'') || '|' || a.webroot, f.agent_id))
	        FROM findings f
	        JOIN agents a ON a.id = f.agent_id AND a.retired = 0
	       WHERE f.path LIKE ? ESCAPE '\' AND f.state != 'dismissed'`
	args := []any{likeEscape(tree) + `/%`}
	if estateID != 0 {
		q += ` AND a.estate_id = ?`
		args = append(args, estateID)
	}
	var n int
	if err := db.sql.QueryRow(q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// likeEscape neutralises LIKE wildcards in a literal value.
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// classifyConsensus applies the rules described at the top of this file.
func classifyConsensus(c Consensus) (string, string) {
	switch {
	case c.Sites == 0:
		return ConsensusInconclusive, "no sightings recorded for this digest"

	case c.VendorTree == "" && c.Sites >= 2:
		// Widespread but not vendor-shaped: either the path varies between
		// sites, or it is not in a plugin/theme tree at all. Identical bytes
		// appearing across sites OUTSIDE a vendor tree is the definition of a
		// campaign, and is the one case where a high count is alarming.
		return ConsensusCampaign, fmt.Sprintf(
			"identical bytes on %d sites but not at a consistent plugin/theme path (%s) — "+
				"vendor code does not move between installations",
			c.Sites, strings.Join(c.Paths, ", "))

	case c.VendorTree == "":
		return ConsensusInconclusive,
			"seen on one site and not inside a plugin or theme directory, so the estate has no opinion"

	case len(c.Paths) > 1:
		return ConsensusCampaign, fmt.Sprintf(
			"same digest at %d different paths across %d sites — a vendor ships a file to ONE location",
			len(c.Paths), c.Sites)

	case c.Sites == 1 && c.SitesRunningTree >= consensusMinSites:
		return ConsensusSingleton, fmt.Sprintf(
			"%d sites carry %s, but only this one has this file — it is not part of the released package",
			c.SitesRunningTree, c.VendorTree)

	case c.Sites == 1:
		return ConsensusInconclusive, fmt.Sprintf(
			"only %d site in the estate reports anything under %s, so there is nothing to compare against",
			c.SitesRunningTree, c.VendorTree)

	case c.Sites < consensusMinSites:
		return ConsensusInconclusive, fmt.Sprintf(
			"%d site(s) agree; %d are required before identical bytes are treated as vendor code",
			c.Sites, consensusMinSites)

	case !c.FirstSeen.IsZero() && !c.LastSeen.IsZero() &&
		c.LastSeen.Sub(c.FirstSeen) < consensusBurstWindow:
		// Arrived everywhere at once. An installed base accumulates; a
		// deployment lands. Refuse to corroborate until it has aged.
		return ConsensusCampaign, fmt.Sprintf(
			"appeared on %d sites within %s — an installed base accrues over time, "+
				"a simultaneous arrival is a deployment",
			c.Sites, c.LastSeen.Sub(c.FirstSeen).Round(time.Hour))

	default:
		return ConsensusVendor, fmt.Sprintf(
			"byte-identical at %s on %d independent sites — this is the published package",
			c.VendorTree, c.Sites)
	}
}

// Attestation is one file the estate corroborates as vendor code.
type Attestation struct {
	SHA256 string `json:"sha256"`
	Path   string `json:"path"`
	Tree   string `json:"tree,omitempty"`
	Sites  int    `json:"sites,omitempty"`
}

// VendorAttestations returns everything this estate can vouch for.
//
// This is the point of cross-site correlation, and until now it was computed
// and then thrown away. Premium and bespoke code publishes no checksum
// manifest, so provenance cannot speak for it and every dangerous-looking
// primitive inside Divi or Gravity Forms reaches the pattern engines with no
// authority to exonerate it. The estate itself is that authority: a file that
// is byte-identical at the same path across many independent installations is
// the publisher's code, because a targeted implant is not.
//
// The verdict logic is unchanged and its poisoning defences still apply — the
// path must agree across sites, digests appearing at several paths are read as
// a campaign rather than a vendor, and simultaneous first-sightings are
// rejected. Dismissed findings and retired agents do not vote.
//
// Only single-path digests are attested. A vendor ships a file to one location;
// anything else is not vendor-shaped and must not be exonerated.
func (db *DB) VendorAttestations(estateID int64) ([]Attestation, error) {
	cors, err := db.Correlate(2, estateID)
	if err != nil {
		return nil, err
	}
	if len(cors) == 0 {
		return nil, nil
	}
	shas := make([]string, 0, len(cors))
	for _, c := range cors {
		shas = append(shas, c.SHA256)
	}
	verdicts, err := db.ConsensusFor(estateID, shas)
	if err != nil {
		return nil, err
	}
	out := make([]Attestation, 0, len(verdicts))
	for sha, v := range verdicts {
		if v.Verdict != ConsensusVendor || len(v.Paths) != 1 {
			continue
		}
		out = append(out, Attestation{
			SHA256: sha, Path: v.Paths[0], Tree: v.VendorTree, Sites: v.Sites,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
