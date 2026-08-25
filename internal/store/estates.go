package store

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Estates: one customer's set of sites.
//
// A consultancy runs many clients through one console. Scoping matters for more
// than tidiness: a finding on one client's site must never appear as context for
// another, and cross-site consensus must not reach a quorum by borrowing
// unrelated customers' machines — that would both weaken the evidence and leak
// one client's estate shape into another's report.

type Estate struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Archived  bool      `json:"archived"`
	// Agents is the current member count, filled by ListEstates.
	Agents int `json:"agents"`
}

var slugStrip = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify makes a URL- and filename-safe identifier. It is used in the
// generated installer's filename, so it must never produce path separators or
// leading dots.
func Slugify(s string) string {
	out := slugStrip.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
	out = strings.Trim(out, "-")
	if len(out) > 48 {
		out = strings.Trim(out[:48], "-")
	}
	return out
}

func (db *DB) CreateEstate(name, notes, by string) (*Estate, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("estate name is required")
	}
	slug := Slugify(name)
	if slug == "" {
		return nil, fmt.Errorf("estate name must contain letters or digits")
	}
	ts := now()
	res, err := db.sql.Exec(
		`INSERT INTO estates (name, slug, notes, created_at, created_by) VALUES (?,?,?,?,?)`,
		name, slug, notes, ts, by)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, fmt.Errorf("an estate named %q already exists", name)
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Estate{ID: id, Name: name, Slug: slug, Notes: notes,
		CreatedAt: unixOrZero(ts), CreatedBy: by}, nil
}

func (db *DB) ListEstates(includeArchived bool) ([]Estate, error) {
	q := `SELECT e.id, e.name, e.slug, e.notes, e.created_at, e.created_by, e.archived,
	             (SELECT COUNT(*) FROM agents a WHERE a.estate_id = e.id AND a.retired = 0)
	        FROM estates e`
	if !includeArchived {
		q += ` WHERE e.archived = 0`
	}
	q += ` ORDER BY e.name`
	rows, err := db.sql.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Estate
	for rows.Next() {
		var e Estate
		var created int64
		var archived int
		if err := rows.Scan(&e.ID, &e.Name, &e.Slug, &e.Notes, &created,
			&e.CreatedBy, &archived, &e.Agents); err != nil {
			return nil, err
		}
		e.CreatedAt = unixOrZero(created)
		e.Archived = archived != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

func (db *DB) GetEstate(id int64) (*Estate, error) {
	var e Estate
	var created int64
	var archived int
	err := db.sql.QueryRow(
		`SELECT id, name, slug, notes, created_at, created_by, archived FROM estates WHERE id = ?`, id).
		Scan(&e.ID, &e.Name, &e.Slug, &e.Notes, &created, &e.CreatedBy, &archived)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no such estate")
	}
	if err != nil {
		return nil, err
	}
	e.CreatedAt = unixOrZero(created)
	e.Archived = archived != 0
	return &e, nil
}

// ArchiveEstate hides an estate without deleting it. Deleting would cascade
// away the agents and with them the findings, which is exactly the history an
// engagement needs to keep.
func (db *DB) ArchiveEstate(id int64, archived bool) error {
	_, err := db.sql.Exec(`UPDATE estates SET archived = ? WHERE id = ?`, boolInt(archived), id)
	return err
}

// SetAgentEstate moves an agent between customers, for hosts enrolled before
// their estate existed.
func (db *DB) SetAgentEstate(agentID string, estateID int64) error {
	var n int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM estates WHERE id = ?`, estateID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("no such estate")
	}
	_, err := db.sql.Exec(`UPDATE agents SET estate_id = ? WHERE id = ?`, estateID, agentID)
	return err
}

// SetTokenEstate scopes an enrollment token to a customer. Agents enrolled with
// it inherit the estate, which is what makes a generated installer land in the
// right place without the administrator running it having to know anything.
func (db *DB) SetTokenEstate(tokenID, estateID int64) error {
	_, err := db.sql.Exec(`UPDATE enroll_tokens SET estate_id = ? WHERE id = ?`, estateID, tokenID)
	return err
}

// EstateOfAgent returns the estate an agent belongs to, or 0.
func (db *DB) EstateOfAgent(agentID string) int64 {
	var id sql.NullInt64
	_ = db.sql.QueryRow(`SELECT estate_id FROM agents WHERE id = ?`, agentID).Scan(&id)
	if id.Valid {
		return id.Int64
	}
	return 0
}

// nullIfZero maps a zero id to SQL NULL, so an agent enrolled with an
// unscoped token has no estate rather than a dangling reference to id 0.
func nullIfZero(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}
