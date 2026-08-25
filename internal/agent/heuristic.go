package agent

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"wordeye/internal/model"
	"wordeye/internal/rules"
)

// The generic web-shell detector.
//
// Signature matching only ever finds shells someone has already published. The
// families that get missed are the ones an operator repacked until a scanner
// stopped alerting: the bytes change, but the STRUCTURE cannot. A shell has to
// take attacker input, it has to reach an execution primitive, and if it wants
// to stay hidden it has to obfuscate the path between them.
//
// This engine scores that structure. Four things make it more than a keyword
// counter:
//
//   - It lexes PHP first, so a function named in a comment or a docblock is not
//     mistaken for a call, and a payload hidden in a string is found even when
//     the surrounding code is unremarkable.
//   - It reassembles concatenated literals, so `'ev'.'al'` is scored as `eval`.
//   - It follows assignments, so `$a = $_POST['x']; … eval($a);` is recognised
//     as input reaching a sink regardless of how far apart they sit.
//   - It DECODES packed payloads and scores what comes out, rather than judging
//     a file by its wrapper.
//
// Every literal below is registered into the shared Aho-Corasick automaton, so
// determining which appear costs nothing beyond the single pass the rule gates
// already perform. Only the handful that fired are then located precisely.

type sinkGroup struct {
	name    string
	weight  int
	cap     int
	members []string
}

var (
	execSinks = sinkGroup{"exec", 3, 9, []string{
		"eval(", "assert(", "shell_exec(", "passthru(", "proc_open(",
		"popen(", "pcntl_exec(", "system(", "create_function(", "expect_popen(",
	}}

	strongObf = sinkGroup{"obfuscation", 2, 8, []string{
		"base64_decode", "gzinflate", "gzuncompress", "gzdecode",
		"str_rot13", "convert_uudecode", "hex2bin", "zlib_decode",
	}}

	weakObf = sinkGroup{"encoding", 1, 4, []string{
		"strrev", "chr(", "pack(", "urldecode", "rawurldecode", "bin2hex", "substr(",
	}}

	inputSrc = sinkGroup{"input", 1, 4, []string{
		"$_get", "$_post", "$_request", "$_cookie", "$_files",
		"php://input", "getallheaders(", "http_user_agent", "$_server",
	}}

	evasion = sinkGroup{"evasion", 2, 6, []string{
		"error_reporting(0", "set_time_limit(0", "ignore_user_abort",
		"@eval", "@assert", "$globals[", "$$", "disable_functions",
	}}

	fileWrite = sinkGroup{"filewrite", 1, 3, []string{
		"file_put_contents", "move_uploaded_file", "fwrite(", "chmod(",
	}}

	phpMarkers = []string{"<?php", "<?="}

	// Markers of code written to be maintained rather than hidden. Used only to
	// discount weak, circumstantial scores — never to excuse hard evidence,
	// because a fake plugin header costs an attacker one line.
	benignMarkers = []string{
		"plugin name:", "theme name:", "namespace ", "declare(strict_types",
		"defined('abspath')", "defined( 'abspath'", "@package", "@since",
		"class ", "interface ", "public function", "private function",
		"add_action(", "add_filter(", "register_activation_hook",
	}

	allGroups = []*sinkGroup{&execSinks, &strongObf, &weakObf, &inputSrc, &evasion, &fileWrite}
)

// HeuristicLiterals is handed to rules.Compile so these share one automaton
// with the rule gates.
func HeuristicLiterals() []string {
	var out []string
	for _, g := range allGroups {
		out = append(out, g.members...)
	}
	out = append(out, phpMarkers...)
	return append(out, benignMarkers...)
}

type literalIDs struct {
	groups map[string][]int
	byID   map[int]string
	php    []int
	benign []int
}

func resolveLiterals(set *rules.Set) *literalIDs {
	l := &literalIDs{groups: map[string][]int{}, byID: map[int]string{}}
	for _, g := range allGroups {
		for _, m := range g.members {
			id := set.LiteralID(m)
			if id < 0 {
				continue
			}
			l.groups[g.name] = append(l.groups[g.name], id)
			l.byID[id] = m
		}
	}
	for _, m := range phpMarkers {
		if id := set.LiteralID(m); id >= 0 {
			l.php = append(l.php, id)
		}
	}
	for _, m := range benignMarkers {
		if id := set.LiteralID(m); id >= 0 {
			l.benign = append(l.benign, id)
		}
	}
	return l
}

func (l *literalIDs) anyHit(ids []int, hit []bool) bool {
	for _, id := range ids {
		if id < len(hit) && hit[id] {
			return true
		}
	}
	return false
}

func (l *literalIDs) countHits(ids []int, hit []bool) int {
	n := 0
	for _, id := range ids {
		if id < len(hit) && hit[id] {
			n++
		}
	}
	return n
}

func (l *literalIDs) present(group string, hit []bool) []string {
	var out []string
	for _, id := range l.groups[group] {
		if id < len(hit) && hit[id] {
			out = append(out, l.byID[id])
		}
	}
	return out
}

// heurScratch holds per-worker reusable buffers so the hot path stays
// allocation-light on a machine that is also serving a website.
type heurScratch struct {
	code  []byte
	lower []byte

	// lens carries the lexed view of the file currently being analysed, so that
	// the rule engine and the heuristic engine share one lex rather than
	// repeating it. Reset by beginFile at the top of every file.
	lens codeLens
}

// codeLens produces the lexed code view of a PHP file on demand, at most once
// per file. It is lazy because most files never need it: only a rule whose
// gates have already fired, or a heuristic that survived the cheap prefilter,
// ever asks.
type codeLens struct {
	src     []byte
	sc      *heurScratch
	isPHP   bool
	view    *phpView
	nocomm  []byte
	nocDone bool
}

// beginFile points the lens at a new file. Called once per file, before any
// engine runs.
func (sc *heurScratch) beginFile(src []byte, isPHP bool) {
	sc.lens = codeLens{src: src, sc: sc, isPHP: isPHP}
}

// lexed returns the lexed view, lexing on first use. Nil for non-PHP files.
func (c *codeLens) lexed() *phpView {
	if !c.isPHP {
		return nil
	}
	if c.view == nil {
		c.view = lexPHP(c.src, c.sc.code)
		c.sc.code = c.view.code
	}
	return c.view
}

// uncommented returns the file with comment bodies blanked but string literals
// intact — the view for engines that still need string contents as evidence.
func (c *codeLens) uncommented() []byte {
	if !c.isPHP {
		return c.src
	}
	if !c.nocDone {
		if v := c.lexed(); v != nil {
			c.nocomm = v.withoutComments(c.src, c.nocomm)
		} else {
			c.nocomm = c.src
		}
		c.nocDone = true
	}
	return c.nocomm
}

// subject returns the bytes a code-scoped rule should be matched against:
// the file with comment bodies and string-literal contents blanked to spaces.
// Offsets are preserved, so a match offset still indexes the original file.
// Non-PHP files have no lexer, so they fall back to raw bytes.
func (c *codeLens) subject() []byte {
	v := c.lexed()
	if v == nil {
		return c.src
	}
	return v.code
}

type heurResult struct {
	Score      int
	Reasons    []string
	Severity   model.Severity
	Entropy    float64
	B64Run     int
	Layers     []DecodedLayer
	Tainted    bool
	HardSignal bool
}

// ---------------------------------------------------------------------------
// taint and evasion patterns, compiled once
// ---------------------------------------------------------------------------

var (
	// $var = <expr up to ;>
	assignRe = regexp.MustCompile(`\$([A-Za-z_]\w*)\s*=\s*([^;]{0,400});`)
	// Superglobal or request-ish source appearing in an expression.
	inputExprRe = regexp.MustCompile(`\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|php://input|getallheaders\s*\(`)
	// A call to an execution primitive. preg_replace is excluded deliberately;
	// see isSinkName for why. include/require stay: they execute their
	// argument, so request input reaching one is LFI/RFI.
	sinkCallRe = regexp.MustCompile(`\b(eval|assert|system|shell_exec|passthru|proc_open|popen|pcntl_exec|create_function|include|include_once|require|require_once)\s*\(`)
	// Dispatch through a variable: $f(...) — the shape left behind when a
	// function name is assembled at runtime.
	varCallRe = regexp.MustCompile(`\$([A-Za-z_]\w*)\s*\(`)
	// Variable-variable and array-dispatch forms.
	indirectCallRe = regexp.MustCompile(`\$\$[A-Za-z_]\w*\s*\(|\$GLOBALS\s*\[[^\]]{1,40}\]\s*\(|\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]]{0,80}\]\s*\(`)
)

// analyzeHeuristic scores one file.
//
// rel is used only for location weighting: the same evidence means more under
// uploads/ than inside a vendored library.
func (a *Agent) analyzeHeuristic(src []byte, hit []bool, size int64, rel string, sc *heurScratch) *heurResult {
	l := a.lits

	// Only PHP-executable content is in scope. Deliberately independent of the
	// file's extension: a polyglot .jpg containing <?php is exactly what we want
	// scored.
	if !l.anyHit(l.php, hit) {
		return nil
	}

	execAny := l.anyHit(l.groups["exec"], hit)
	strongObfN := l.countHits(l.groups["obfuscation"], hit)

	// Cheap rejection before any lexing. Without an execution primitive, heavy
	// obfuscation, or an indirect-dispatch shape, there is no shell structure to
	// score. This rejects nearly every file in a WordPress install.
	// Dispatch shapes that contain NO sink name at all: $_GET['f'](...) and
	// $var(...). "](" and ")(" are rare enough in ordinary PHP to use as a cheap
	// pre-filter, and without this the early exit discarded a whole evasion
	// class before the lexer ever ran.
	dispatchShape := l.anyHit(l.groups["input"], hit) && bytes.Contains(src, []byte("]("))

	if !execAny && strongObfN < 2 && !dispatchShape &&
		!bytes.Contains(src, []byte("$$")) &&
		!bytes.Contains(src, []byte("$GLOBALS[")) {
		// Split-literal evasion removes the sink name entirely, so a file with
		// concatenated fragments still deserves a look.
		if !looksConcatHeavy(src) {
			return nil
		}
	}

	// --- Lex once; everything below reads the code view --------------------
	// Shared with the rule engine via the lens, so a file whose rule gates
	// already forced a lex is not lexed a second time here.
	view := sc.lens.lexed()
	if view == nil {
		view = lexPHP(src, sc.code)
		sc.code = view.code
	}
	code := view.code

	if cap(sc.lower) < len(code) {
		sc.lower = make([]byte, len(code))
	}
	lower := sc.lower[:len(code)]
	for i := 0; i < len(code); i++ {
		lower[i] = lowerASCII(code[i])
	}

	score := 0
	var reasons []string
	hard := false

	add := func(n int, format string, args ...any) {
		score += n
		reasons = append(reasons, fmt.Sprintf(format, args...))
	}

	// --- Group presence, measured in CODE only -----------------------------
	// This is the fix for the oldest false-positive class: a dangerous function
	// named in a comment or a docblock no longer counts as a call.
	countIn := func(g sinkGroup) []string {
		var found []string
		for _, m := range g.members {
			if bytes.Contains(lower, []byte(m)) {
				found = append(found, m)
			}
		}
		return found
	}
	execIn := countIn(execSinks)
	obfIn := countIn(strongObf)
	weakIn := countIn(weakObf)
	inputIn := countIn(inputSrc)
	evadeIn := countIn(evasion)
	writeIn := countIn(fileWrite)

	addGroup := func(g sinkGroup, found []string) {
		if len(found) == 0 {
			return
		}
		s := g.weight * len(found)
		if s > g.cap {
			s = g.cap
		}
		score += s
		reasons = append(reasons, fmt.Sprintf("%s: %s", g.name, strings.Join(found, " ")))
	}
	addGroup(execSinks, execIn)
	addGroup(strongObf, obfIn)
	addGroup(weakObf, weakIn)
	addGroup(inputSrc, inputIn)
	addGroup(evasion, evadeIn)
	addGroup(fileWrite, writeIn)

	// --- Taint: does request input actually reach an execution sink? -------
	// The strongest non-signature indicator there is, and unlike byte proximity
	// it does not care how far apart the two halves sit.
	tainted, taintWhy := taintReachesSink(code)
	if tainted {
		hard = true
		add(10, "taint: %s", taintWhy)
	} else if len(execIn) > 0 && len(inputIn) > 0 {
		// Both present but no traceable flow. Still worth something.
		if d, ok := nearestDistanceIn(lower, execIn, inputIn, 300); ok {
			add(5, "request input within %d bytes of an execution sink", d)
		} else {
			add(1, "execution sink and request input in the same file")
		}
	}

	// --- Indirect dispatch -------------------------------------------------
	if loc := indirectCallRe.FindIndex(code); loc != nil {
		// Weighted high on purpose. All three shapes this matches —
		// $_GET['f'](…), $GLOBALS['x'](…), $$var(…) — take the NAME of the
		// function to call from data. No maintainable code does that, and there
		// is no signature that can name a callee chosen at runtime.
		hard = true
		add(11, "call dispatched indirectly (variable-variable, $GLOBALS or superglobal)")
	}

	// Calling a variable as a function, with request input as its argument.
	// The function name is decided at runtime, so no signature can name it —
	// and legitimate code that does this with unsanitised input is vanishingly
	// rare. Catches both the assembled-name and variable-variable forms.
	if name, ok := varCallWithInput(code); ok {
		hard = true
		add(8, "$%s is called as a function with request input as its argument", name)
	}

	// --- Split-literal evasion ---------------------------------------------
	// Reassembling `'ev'.'al'` puts back the identifier the attacker removed.
	for _, chain := range view.concatChains(src, 64) {
		merged := strings.ToLower(strings.TrimSpace(string(chain.value)))
		if merged == "" {
			continue
		}
		if isSinkName(merged) {
			hard = true
			add(9, "function name assembled from %d concatenated literals: %q", chain.parts, merged)
			if len(inputIn) > 0 {
				// Assembling an execution primitive at runtime AND reading
				// request input is not something maintainable code does. There
				// is no benign reason to hide the name of a function you call.
				add(5, "assembled execution primitive in a file that reads request input")
			}
			break
		}
	}

	// --- Decoder chained into an executor ----------------------------------
	if len(execIn) > 0 && len(obfIn) > 0 {
		if d, ok := nearestDistanceIn(lower, execIn, obfIn, 60); ok {
			add(5, "decoder chained into an execution sink (%d bytes apart)", d)
		}
	}

	// --- Backtick shell-exec operator --------------------------------------
	// PHP's `cmd` operator executes a shell command and is invisible to any
	// scanner looking for function names.
	if view.hasBacktick {
		if len(inputIn) > 0 {
			hard = true
			add(8, "backtick shell-exec operator in a file that reads request input")
		} else {
			add(3, "backtick shell-exec operator present")
		}
	}

	// --- Packed payloads: decode and judge the CONTENTS --------------------
	tDec := time.Now()
	layers := deobfuscate(src, view)
	a.nsDecode.Add(int64(time.Since(tDec)))
	if len(layers) > 0 {
		hard = true
		deepest := layers[0]
		for _, x := range layers {
			if x.Depth > deepest.Depth {
				deepest = x
			}
		}
		add(8, "encoded payload unwrapped (%s)", summarizeLayers(layers))

		// Score the decoded payload the same way, and inherit its verdict. This
		// is the point of decoding: judge the code, not the packaging.
		for _, layer := range layers {
			if inner, why := payloadVerdict(layer.Data); inner > 0 {
				add(inner, "decoded payload at depth %d %s", layer.Depth, why)
				break
			}
		}
	}

	// --- Density -----------------------------------------------------------
	if size > 0 && size < 8192 && len(execIn) > 0 && len(inputIn) > 0 {
		add(4, "dense: exec+input in only %d bytes", size)
	}

	// --- High-entropy blob (independent of successful decoding) ------------
	runOff, runLen := longestEncodedRun(src)
	entropy := 0.0
	if runLen >= 128 {
		entropy = shannon(src[runOff : runOff+runLen])
	}
	switch {
	case runLen >= 2048 && entropy > 4.5:
		add(6, "%d-byte high-entropy encoded blob (H=%.2f)", runLen, entropy)
	case runLen >= 512 && entropy > 4.2:
		add(4, "%d-byte encoded blob (H=%.2f)", runLen, entropy)
	}

	// --- Obfuscator layout -------------------------------------------------
	if n := bytes.Count(src, []byte{'\n'}); len(src) > 4096 && n > 0 && len(src)/(n+1) > 2000 {
		add(3, "single-line source (%d bytes over %d lines)", len(src), n+1)
	} else if n == 0 && len(src) > 4096 {
		add(3, "no newlines in a large PHP file")
	}

	if score == 0 {
		return nil
	}

	// --- Location weighting ------------------------------------------------
	// Identical evidence is more damning in a directory that should never hold
	// executable PHP than in a vendored dependency.
	// Whether ANY authority could speak for this path. Without one, a core
	// directory tells us nothing about whether the file belongs there.
	provCovered := a.prov != nil && len(a.prov.expected) > 0
	if w, why := locationWeight(rel, provCovered); w != 1.0 {
		before := score
		score = int(float64(score) * w)
		if score != before {
			reasons = append(reasons, fmt.Sprintf("location: %s (x%.2f)", why, w))
		}
	}

	// --- Benign priors -----------------------------------------------------
	// Applied ONLY when there is no hard evidence. A plugin header is one line
	// for an attacker to add, so it must never be able to talk the engine out
	// of a traced taint path or a decoded payload.
	if !hard {
		if n := l.countHits(l.benign, hit); n >= 3 {
			discount := 3 + n/2
			if discount > 7 {
				discount = 7
			}
			score -= discount
			reasons = append(reasons, fmt.Sprintf(
				"discounted %d: %d markers of ordinary plugin code (namespace/hooks/docblocks)", discount, n))
		}
	}

	// --- Execution capability ----------------------------------------------
	// A web shell must be able to RUN something. Request input, encoding and
	// evasion markers describe how a payload would be delivered and hidden, but
	// with no reachable execution primitive the file cannot be a shell — it is
	// a plugin that reads a query string and base64-encodes an asset, which
	// describes a large share of the WordPress ecosystem.
	//
	// Without this gate a field scan called ACF Pro, Divi and Wordfence
	// critical web shells on exactly that basis: input + encoding + $GLOBALS[
	// and no sink anywhere in the file. Circumstantial indicators can still
	// raise a finding, but they can never carry a critical verdict on their own.
	canExecute := execAny || dispatchShape || tainted || hard
	if !canExecute {
		reasons = append(reasons,
			"no execution primitive present: scored on circumstantial indicators only")
	}

	var sev model.Severity
	switch {
	case score >= 16 && canExecute:
		sev = model.SevCritical
	case score >= 11 && canExecute:
		sev = model.SevHigh
	case score >= 7 && canExecute:
		sev = model.SevMedium
	case score >= 16:
		// Strong circumstantial shape but nothing to execute it. Worth an
		// analyst's eye; not worth waking anyone at 3am.
		sev = model.SevMedium
	default:
		return nil
	}

	sort.Strings(reasons)
	return &heurResult{
		Score: score, Reasons: reasons, Severity: sev,
		Entropy: entropy, B64Run: runLen, Layers: layers,
		Tainted: tainted, HardSignal: hard,
	}
}

// payloadVerdict scores a decoded payload, returning a bonus and a description.
func payloadVerdict(data []byte) (int, string) {
	lower := bytes.ToLower(data)
	if len(lower) > 256<<10 {
		lower = lower[:256<<10]
	}
	hasExec := false
	for _, m := range execSinks.members {
		if bytes.Contains(lower, []byte(m)) {
			hasExec = true
			break
		}
	}
	hasInput := false
	for _, m := range inputSrc.members {
		if bytes.Contains(lower, []byte(m)) {
			hasInput = true
			break
		}
	}
	switch {
	case hasExec && hasInput:
		return 12, "contains an execution sink reached from request input"
	case hasExec:
		return 7, "contains an execution primitive"
	case hasInput:
		return 4, "reads request input"
	case bytes.Contains(lower, []byte("<?php")):
		return 3, "is PHP source"
	}
	return 0, ""
}

// taintReachesSink performs a lightweight def-use analysis over the code view.
//
// Byte proximity was a poor stand-in for this: it missed the very common shape
// where input is captured at the top of a file and used far below. Following
// assignments catches that, and catches it regardless of intervening code.
func taintReachesSink(code []byte) (bool, string) {
	assigns := assignRe.FindAllSubmatchIndex(code, 400)
	if len(assigns) == 0 && !inputExprRe.Match(code) {
		return false, ""
	}

	tainted := map[string]bool{}
	// Seed: variables assigned directly from a request source.
	for _, m := range assigns {
		name := string(code[m[2]:m[3]])
		rhs := code[m[4]:m[5]]
		if inputExprRe.Match(rhs) {
			tainted[name] = true
		}
	}
	// Propagate through assignment chains. Three rounds covers the realistic
	// depth; shells are short.
	for round := 0; round < 3; round++ {
		changed := false
		for _, m := range assigns {
			name := string(code[m[2]:m[3]])
			if tainted[name] {
				continue
			}
			rhs := code[m[4]:m[5]]
			for t := range tainted {
				if containsVar(rhs, t) {
					tainted[name] = true
					changed = true
					break
				}
			}
		}
		if !changed {
			break
		}
	}
	if len(tainted) == 0 {
		return false, ""
	}

	// Does a tainted variable appear inside a sink's argument list?
	for _, loc := range sinkCallRe.FindAllSubmatchIndex(code, 200) {
		fn := string(code[loc[2]:loc[3]])
		args := argRegion(code, loc[1]-1)
		for t := range tainted {
			if containsVar(args, t) {
				return true, fmt.Sprintf("$%s carries request input into %s()", t, fn)
			}
		}
	}
	// Or is a tainted variable itself used as the function being called?
	for _, loc := range varCallRe.FindAllSubmatchIndex(code, 200) {
		name := string(code[loc[2]:loc[3]])
		if tainted[name] {
			return true, fmt.Sprintf("$%s holds request input and is called as a function", name)
		}
	}
	return false, ""
}

// argRegion returns the bytes between a call's parentheses, bounded.
func argRegion(code []byte, openParen int) []byte {
	if openParen < 0 || openParen >= len(code) || code[openParen] != '(' {
		return nil
	}
	depth := 0
	end := openParen
	limit := openParen + 600
	if limit > len(code) {
		limit = len(code)
	}
	for i := openParen; i < limit; i++ {
		switch code[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
				return code[openParen+1 : end]
			}
		}
	}
	return code[openParen+1 : limit]
}

// containsVar reports whether $name appears as a whole variable token.
func containsVar(hay []byte, name string) bool {
	needle := append([]byte{'$'}, name...)
	off := 0
	for {
		i := bytes.Index(hay[off:], needle)
		if i < 0 {
			return false
		}
		abs := off + i + len(needle)
		if abs >= len(hay) || !isIdentByte(hay[abs]) {
			return true
		}
		off = off + i + 1
	}
}

func isSinkName(s string) bool {
	s = strings.TrimSuffix(strings.TrimSpace(s), "(")
	for _, g := range []sinkGroup{execSinks, strongObf} {
		for _, m := range g.members {
			if strings.TrimSuffix(m, "(") == s {
				return true
			}
		}
	}
	switch s {
	case "eval", "assert", "system", "exec", "shell_exec", "passthru",
		"proc_open", "popen", "create_function", "call_user_func":
		return true
	}
	// preg_replace is NOT a sink. Its /e modifier — the only form that ever
	// executed anything — was removed in PHP 7. Passing request input to
	// preg_replace is how code SANITISES that input, so treating it as a sink
	// scored every well-behaved plugin as a shell: in one field run it produced
	// the taint reason behind every single heuristic false positive. The
	// surviving /e case is matched precisely by shell.preg_replace_e.
	return false
}

// looksConcatHeavy detects the shape of split-literal evasion: quoted fragments
// joined by the concatenation operator.
//
// This must tolerate whitespace. The first version matched only "'." and ".'",
// so `'ev' . 'al'` — written with the spaces any code formatter produces — slid
// straight past it, which defeated the entire split-literal defence.
//
// Counting concatenations alone is useless: joining strings is one of the most
// common things PHP does. The discriminator is FRAGMENT LENGTH. `'Hello ' .
// $name` is ordinary; `'ev' . 'al'` is someone hiding an identifier, because
// nobody splits a word into two-character pieces for readability. One short
// fragment is therefore enough to justify a closer look.
func looksConcatHeavy(src []byte) bool {
	for i := 0; i < len(src); i++ {
		q := src[i]
		if q != '\'' && q != '"' {
			continue
		}
		j := i + 1
		for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
			j++
		}
		if j >= len(src) || src[j] != '.' {
			continue
		}
		j++
		for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
			j++
		}
		if j >= len(src) || (src[j] != '\'' && src[j] != '"') {
			continue
		}
		// Measure the literal that follows the operator.
		open := src[j]
		k := j + 1
		for k < len(src) && src[k] != open && src[k] != '\n' {
			k++
		}
		if k-(j+1) <= 6 {
			return true
		}
	}
	return false
}

// locationWeight scales a score by where the file lives.
// locationWeight scores where a file sits.
//
// provenanceCovered says whether an authority could have vouched for this path.
// It matters enormously for core: "a shell hidden in wp-admin is more
// suspicious" is only true if we can distinguish a shell from wp-admin itself.
// When provenance is unavailable — no network, a fetch failure, --offline — we
// cannot, and applying the multiplier then AMPLIFIES ordinary core code into
// criticals. A field run did exactly that: provenance failed silently and five
// stock WordPress files were reported as web shells, the same false-positive
// class provenance was introduced to eliminate.
func locationWeight(rel string, provenanceCovered bool) (float64, string) {
	switch {
	case strings.Contains(rel, "wp-content/uploads/"):
		return 1.5, "inside the uploads tree, which should never hold executable PHP"
	case strings.Contains(rel, "wp-includes/"), strings.Contains(rel, "wp-admin/"):
		if !provenanceCovered {
			// Unverifiable core: treat it as ordinary rather than amplifying it.
			return 1.0, ""
		}
		return 1.4, "inside a WordPress core directory"
	case strings.Contains(rel, "mu-plugins/"):
		return 1.3, "a must-use plugin, auto-loaded on every request"
	case strings.Contains(rel, "/css/"), strings.Contains(rel, "/js/"),
		strings.Contains(rel, "/images/"), strings.Contains(rel, "/fonts/"),
		strings.Contains(rel, "/assets/"):
		return 1.3, "an asset directory"
	case strings.Contains(rel, "/vendor/"), strings.Contains(rel, "/node_modules/"):
		return 0.8, "a vendored dependency tree"
	}
	return 1.0, ""
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// nearestDistanceIn finds the smallest gap between any occurrence of a literal
// in a and any in b, operating on an already-lowercased buffer.
func nearestDistanceIn(lower []byte, aLits, bLits []string, max int) (int, bool) {
	aPos := occurrencesIn(lower, aLits, 64)
	bPos := occurrencesIn(lower, bLits, 64)
	if len(aPos) == 0 || len(bPos) == 0 {
		return 0, false
	}
	sort.Ints(aPos)
	sort.Ints(bPos)

	best := -1
	j := 0
	for _, p := range aPos {
		for j < len(bPos)-1 && bPos[j] < p {
			j++
		}
		for _, q := range []int{bPos[j], bPos[maxInt(0, j-1)]} {
			d := p - q
			if d < 0 {
				d = -d
			}
			if best < 0 || d < best {
				best = d
			}
		}
	}
	if best >= 0 && best <= max {
		return best, true
	}
	return best, false
}

// occurrencesIn avoids the repeated whole-file ToLower the previous version
// performed on every call — measurable on a memory-capped agent.
func occurrencesIn(lower []byte, lits []string, limit int) []int {
	var out []int
	for _, lit := range lits {
		off := 0
		for len(out) < limit {
			i := bytes.Index(lower[off:], []byte(lit))
			if i < 0 {
				break
			}
			out = append(out, off+i)
			off += i + len(lit)
		}
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// longestEncodedRun locates the longest run of base64/hex-ish characters. A
// packed payload shows up here as one very long run, which plain source never
// produces.
func longestEncodedRun(b []byte) (off, length int) {
	bestOff, bestLen := 0, 0
	curOff, curLen := 0, 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		enc := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
			c == '-' || c == '_'
		if enc {
			if curLen == 0 {
				curOff = i
			}
			curLen++
			continue
		}
		if curLen > bestLen {
			bestOff, bestLen = curOff, curLen
		}
		curLen = 0
	}
	if curLen > bestLen {
		bestOff, bestLen = curOff, curLen
	}
	return bestOff, bestLen
}

// shannon returns entropy in bits per byte. Base64 of compressed data lands
// around 5.5-6.0; prose and source code sit well below 4.5.
func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	h := 0.0
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// varCallWithInput finds `$f( ... $_POST ... )`: a call through a variable whose
// arguments carry request input. The callee is chosen at runtime, which is
// precisely what makes it invisible to name-based detection.
func varCallWithInput(code []byte) (string, bool) {
	for _, loc := range varCallRe.FindAllSubmatchIndex(code, 200) {
		name := string(code[loc[2]:loc[3]])
		args := argRegion(code, loc[1]-1)
		if inputExprRe.Match(args) {
			return name, true
		}
	}
	return "", false
}
