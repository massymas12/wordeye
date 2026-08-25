package console

import "wordeye/internal/store"

// Authorization, in one place.
//
// Today permission is a function of ROLE alone: an admin may do everything, an
// approver may change state, a viewer may only read. That is adequate for a
// single consultancy operating its own console, and it is what ships.
//
// It will not stay adequate. The obvious next requirement is per-customer
// access — an analyst who works Acme's incident should not browse Globex's
// findings — and that is a change of SHAPE, not of degree: the answer starts
// depending on which estate is being touched.
//
// So every decision goes through Permits, which already takes an estate even
// though it currently ignores it. Wiring real RBAC later means changing this
// one function and adding a grants table, rather than hunting scattered
// `user.CanAdmin()` calls through the handlers and hoping none were missed. A
// missed one is a silent authorization hole, which is precisely the bug class
// that a single chokepoint eliminates by construction.

// Action names the thing being attempted. Strings rather than an enum so that
// a grants table can store them directly.
type Action string

const (
	ActionViewFleet      Action = "fleet.view"
	ActionRetireAgent    Action = "fleet.retire"
	ActionViewFindings   Action = "findings.view"
	ActionChangeFinding  Action = "findings.state"
	ActionRunCommand     Action = "commands.create"
	ActionApproveCommand Action = "commands.approve"
	ActionViewEstates    Action = "estates.view"
	ActionManageEstates  Action = "estates.manage"
	ActionGenInstaller   Action = "installer.generate"
	ActionManageTokens   Action = "tokens.manage"
	ActionManageUsers    Action = "users.manage"
	ActionViewAudit      Action = "audit.view"
)

// Permits reports whether the signed-in user may perform action, optionally
// scoped to an estate.
//
// estateID is accepted and deliberately unused: it is the parameter that
// per-customer RBAC needs, and threading it through the call sites NOW means
// adding that feature later touches this file and nothing else. A signature
// change across every handler is exactly the kind of edit where one call site
// gets missed.
func Permits(u *store.User, action Action, estateID int64) bool {
	if u == nil {
		return false
	}
	_ = estateID // reserved for per-estate grants; see the note above.

	switch action {
	// Reading. Any authenticated operator; the console is useless otherwise.
	case ActionViewFleet, ActionViewFindings, ActionViewEstates, ActionViewAudit:
		return true

	// Changing incident state, or ordering work on a host.
	case ActionChangeFinding, ActionRunCommand, ActionApproveCommand, ActionRetireAgent:
		return u.CanApprove()

	// Administrative. Creating estates, minting tokens and generating
	// installers all hand out or widen access to the fleet, so they sit
	// together at the highest level.
	case ActionManageEstates, ActionGenInstaller, ActionManageTokens, ActionManageUsers:
		return u.CanAdmin()
	}
	// Unknown action: refuse. A typo in a new call site must fail closed rather
	// than silently permitting everyone.
	return false
}

// permittedActions is what the UI uses to decide which controls to render.
//
// Rendering is NOT the security boundary — every route re-checks server-side —
// but showing an operator buttons that will fail is a bad experience, and
// worse, it obscures what their role actually is.
func permittedActions(u *store.User) map[string]bool {
	all := []Action{
		ActionViewFleet, ActionViewFindings, ActionChangeFinding,
		ActionRunCommand, ActionApproveCommand, ActionRetireAgent, ActionViewEstates,
		ActionManageEstates, ActionGenInstaller, ActionManageTokens,
		ActionManageUsers, ActionViewAudit,
	}
	out := make(map[string]bool, len(all))
	for _, a := range all {
		out[string(a)] = Permits(u, a, 0)
	}
	return out
}
